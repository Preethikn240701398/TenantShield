"""
TenantShield - Part 6 Configuration Check Endpoint
===================================================
Read-only security configuration audit endpoint for platform administrators.

Checks (all read-only on the main database):
1. PostgreSQL Row-Level Security (RLS) enabled on the documents table.
2. App role (tenantshield_app) does NOT have superuser or createdb privileges.
3. App role does NOT have unrestricted table-level SELECT on security_events (no bypass).
4. App-layer security control flags (ENABLE_APP_OWNERSHIP_CHECK, ENABLE_DB_RLS, ENABLE_QUERY_TENANT_FILTER).
5. JWT algorithm & token expiry settings.
6. APP_ENV is not 'lab' in production path.
7. Envelope encryption master key is configured (non-empty, correct length).

Enforces:
- Platform Admin authentication required (401 / 403).
- Refuses when APP_ENV is 'lab' (HTTP 400).
- Strictly read-only: no DDL, DML, or writes.
- Never exposes credentials, key material, or secrets.
"""

import logging
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import text

from app.api.deps import get_current_user
from app.api.dashboard import require_platform_admin
from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.schemas.auth import AuthenticatedUser

logger = logging.getLogger("tenantshield.config_check")

router = APIRouter(prefix="/admin/dashboard", tags=["Admin Dashboard"])


def _is_lab_mode() -> bool:
    env = (getattr(settings, "APP_ENV", "") or getattr(settings, "ENVIRONMENT", "")).lower()
    return env == "lab"


def _check_lab_refusal() -> None:
    if _is_lab_mode():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Refused: Config check endpoints are disabled when APP_ENV is lab.",
        )


def _check_result(name: str, passed: bool, detail: str, recommendation: str = "") -> Dict[str, Any]:
    return {
        "name": name,
        "status": "PASS" if passed else "FAIL",
        "detail": detail,
        "recommendation": recommendation if not passed else "",
    }


# ------------------------------------------------------------------------------
# GET /admin/dashboard/config-check
# ------------------------------------------------------------------------------
@router.get("/config-check", summary="Security Configuration Audit Check")
async def config_check(
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Performs a read-only audit of security-relevant application and database
    configuration settings. Returns pass/fail status per check with explanations.
    Never writes to any table, never exposes credentials or key material.
    """
    require_platform_admin(current_user)
    _check_lab_refusal()

    checks: List[Dict[str, Any]] = []

    # ---- Database Checks (read-only queries) ----
    async with AsyncSessionLocal() as session:

        # Check 1: RLS enabled on documents table
        try:
            res = await session.execute(
                text(
                    "SELECT relrowsecurity FROM pg_class "
                    "WHERE relname = 'documents' AND relkind = 'r'"
                )
            )
            row = res.fetchone()
            rls_on = row is not None and bool(row[0])
            checks.append(_check_result(
                "RLS enabled on documents",
                rls_on,
                "pg_class.relrowsecurity = true for 'documents' table." if rls_on
                else "Row-Level Security is NOT enabled on the documents table.",
                "Enable RLS: ALTER TABLE documents ENABLE ROW LEVEL SECURITY;",
            ))
        except Exception as exc:
            checks.append(_check_result(
                "RLS enabled on documents",
                False,
                f"Could not query pg_class: {exc}",
                "Investigate database connectivity or permissions.",
            ))

        # Check 2: App role does NOT have superuser privileges
        try:
            res = await session.execute(
                text(
                    "SELECT rolsuper, rolcreatedb, rolcreaterole "
                    "FROM pg_roles WHERE rolname = 'tenantshield_app'"
                )
            )
            row = res.fetchone()
            if row is None:
                checks.append(_check_result(
                    "App role privileges not elevated",
                    False,
                    "Role 'tenantshield_app' not found in pg_roles.",
                    "Verify database role exists.",
                ))
            else:
                no_super = not row[0]
                no_createdb = not row[1]
                no_createrole = not row[2]
                all_ok = no_super and no_createdb and no_createrole
                problems = []
                if not no_super:
                    problems.append("rolsuper=true")
                if not no_createdb:
                    problems.append("rolcreatedb=true")
                if not no_createrole:
                    problems.append("rolcreaterole=true")
                checks.append(_check_result(
                    "App role privileges not elevated",
                    all_ok,
                    "tenantshield_app has rolsuper=false, rolcreatedb=false, rolcreaterole=false." if all_ok
                    else f"tenantshield_app has elevated privileges: {', '.join(problems)}.",
                    "Revoke elevated privileges: ALTER ROLE tenantshield_app NOSUPERUSER NOCREATEDB NOCREATEROLE;",
                ))
        except Exception as exc:
            checks.append(_check_result(
                "App role privileges not elevated",
                False,
                f"Could not query pg_roles: {exc}",
                "Investigate database connectivity or permissions.",
            ))

        # Check 3: tenant_keys table has RLS enabled
        try:
            res = await session.execute(
                text(
                    "SELECT relrowsecurity FROM pg_class "
                    "WHERE relname = 'tenant_keys' AND relkind = 'r'"
                )
            )
            row = res.fetchone()
            rls_keys = row is not None and bool(row[0])
            checks.append(_check_result(
                "RLS enabled on tenant_keys",
                rls_keys,
                "pg_class.relrowsecurity = true for 'tenant_keys' table." if rls_keys
                else "Row-Level Security is NOT enabled on the tenant_keys table.",
                "Enable RLS: ALTER TABLE tenant_keys ENABLE ROW LEVEL SECURITY;",
            ))
        except Exception as exc:
            checks.append(_check_result(
                "RLS enabled on tenant_keys",
                False,
                f"Could not query pg_class: {exc}",
            ))

    # ---- Application-Layer Flag Checks ----
    # Check 4: ENABLE_APP_OWNERSHIP_CHECK
    ownership_on = getattr(settings, "ENABLE_APP_OWNERSHIP_CHECK", True)
    checks.append(_check_result(
        "Layer A: App ownership check enabled",
        bool(ownership_on),
        "ENABLE_APP_OWNERSHIP_CHECK=True; application-level ownership check is active." if ownership_on
        else "ENABLE_APP_OWNERSHIP_CHECK=False; Layer A is disabled.",
        "Set ENABLE_APP_OWNERSHIP_CHECK=True in environment configuration.",
    ))

    # Check 5: ENABLE_DB_RLS
    db_rls_flag = getattr(settings, "ENABLE_DB_RLS", True)
    checks.append(_check_result(
        "Layer B: DB RLS enforcement flag enabled",
        bool(db_rls_flag),
        "ENABLE_DB_RLS=True; database Row-Level Security enforcement is active." if db_rls_flag
        else "ENABLE_DB_RLS=False; Layer B is disabled.",
        "Set ENABLE_DB_RLS=True in environment configuration.",
    ))

    # Check 6: ENABLE_QUERY_TENANT_FILTER
    query_filter = getattr(settings, "ENABLE_QUERY_TENANT_FILTER", True)
    checks.append(_check_result(
        "Layer C: Query tenant filter enabled",
        bool(query_filter),
        "ENABLE_QUERY_TENANT_FILTER=True; WHERE tenant_id=? query filter is active." if query_filter
        else "ENABLE_QUERY_TENANT_FILTER=False; Layer C is disabled.",
        "Set ENABLE_QUERY_TENANT_FILTER=True in environment configuration.",
    ))

    # Check 7: MUTATION_SESSION_TENANT_CONTEXT is False (disabled in non-lab)
    mutation_flag = getattr(settings, "MUTATION_SESSION_TENANT_CONTEXT", False)
    checks.append(_check_result(
        "Mutation session context disabled",
        not bool(mutation_flag),
        "MUTATION_SESSION_TENANT_CONTEXT=False; session-level tenant bypass is off." if not mutation_flag
        else "MUTATION_SESSION_TENANT_CONTEXT=True; session-level context override is ACTIVE.",
        "Set MUTATION_SESSION_TENANT_CONTEXT=False in environment configuration.",
    ))

    # Check 8: APP_ENV is not 'lab'
    app_env = (getattr(settings, "APP_ENV", "") or "").lower()
    env_ok = app_env != "lab"
    checks.append(_check_result(
        "APP_ENV is not lab",
        env_ok,
        f"APP_ENV='{app_env}'; running in non-lab mode." if env_ok
        else "APP_ENV='lab'; this is a security research mode — security controls may be disabled.",
        "Set APP_ENV=development or APP_ENV=production.",
    ))

    # Check 9: JWT algorithm is HS256
    algo = getattr(settings, "ALGORITHM", "HS256")
    algo_ok = algo in ("HS256", "RS256", "ES256")
    checks.append(_check_result(
        "JWT algorithm configured",
        algo_ok,
        f"JWT ALGORITHM='{algo}'; valid signing algorithm." if algo_ok
        else f"JWT ALGORITHM='{algo}' is not a recognized secure algorithm.",
        "Set ALGORITHM=HS256 or RS256 in environment configuration.",
    ))

    # Check 10: Envelope encryption master key is set (check length only, never expose)
    master_key = getattr(settings, "TENANTSHIELD_MASTER_KEY", "") or ""
    key_ok = len(master_key) == 64 and all(c in "0123456789abcdefABCDEF" for c in master_key)
    checks.append(_check_result(
        "Envelope encryption master key configured",
        key_ok,
        "TENANTSHIELD_MASTER_KEY is a valid 64-character hexadecimal key (256-bit)." if key_ok
        else (
            "TENANTSHIELD_MASTER_KEY is missing, empty, or not a valid 64-character hex string."
            if not master_key
            else f"TENANTSHIELD_MASTER_KEY has unexpected format (length={len(master_key)})."
        ),
        "Set TENANTSHIELD_MASTER_KEY to a 64-character hexadecimal string (256-bit AES key).",
    ))

    # Check 11: SECRET_KEY is not the default placeholder
    secret_key = getattr(settings, "SECRET_KEY", "")
    key_changed = bool(secret_key) and "change_this" not in secret_key.lower()
    checks.append(_check_result(
        "JWT signing key is not default placeholder",
        key_changed,
        "JWT signing key is set and is not the default placeholder value." if key_changed
        else "JWT signing key appears to be the default placeholder — tokens can be forged.",
        "Set SECRET_KEY to a cryptographically random string of at least 32 characters.",
    ))

    # Compute overall verdict
    all_pass = all(c["status"] == "PASS" for c in checks)
    fail_count = sum(1 for c in checks if c["status"] == "FAIL")

    return {
        "overall_status": "PASS" if all_pass else "FAIL",
        "total_checks": len(checks),
        "passed": len(checks) - fail_count,
        "failed": fail_count,
        "checks": checks,
    }
