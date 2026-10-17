"""
TenantShield - Isolation Mutation Testing Framework
===================================================
Executes realistic isolation mutation experiments to evaluate the detection
capabilities of the dynamic verification suite.

Definitions:
- A mutation is a deliberately injected realistic mistake.
- ISOLATED run: the mutation is applied and every other isolation protection
  that could hide it is switched off (Layer A app check, Layer B RLS, Layer C query filter),
  so only the mutated layer stands between tenants.
- A mutation is CAUGHT if the attack suite reports a leak in its ISOLATED run.
  It is MISSED if the suite reports no leak in its ISOLATED run.
- MASKED run: the same mutation with all other protections ON. Reports whether
  a leak appeared; if none, the other layers masked the mistake (informational, not scored).

Safety Rules:
- Mutations run only when APP_ENV=lab AND the database name is tenantshield_lab.
- Every mutation is applied inside try/finally and always reverted.
- Clean baseline verification required before the first mutation.
- Baseline state re-checked and recorded after each revert.
- Mutation switches default to OFF and cannot be enabled outside lab mode.
- High rate limit configured during mutation runs to avoid false 429s.
"""

import asyncio
from contextlib import asynccontextmanager, contextmanager
import csv
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse

from dotenv import load_dotenv

# Ensure project root in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

load_dotenv()

from sqlalchemy import create_engine, text as stext

from app.core.config import settings
from app.core.database import reconfigure_engine
from scripts.setup_lab_db import (
    get_lab_url_from_admin,
    mask_url_secrets,
    setup_or_reset_lab_database,
)
from verifier.runner import VerificationRunner

logger = logging.getLogger("tenantshield.mutation")


class MutationSafetyError(RuntimeError):
    """Raised when mutation safety constraints are violated."""
    pass


DEFINITIONS = {
    "mutation": "A deliberately injected realistic mistake.",
    "isolated_run": (
        "The mutation is applied and every other isolation protection that could "
        "hide it is switched off (using lab switches), so only the mutated layer stands between tenants."
    ),
    "caught": (
        "A mutation is CAUGHT if the attack suite reports a leak in its ISOLATED run."
    ),
    "missed": (
        "A mutation is MISSED if the suite reports no leak in its ISOLATED run, "
        "meaning the attack suite cannot see that mistake."
    ),
    "masked_run": (
        "The same mutation with all other protections ON. Evaluates whether defense-in-depth "
        "layers masked the mistake. Informational and not part of the score."
    ),
}


def verify_mutation_safety() -> None:
    """
    Guarantees mutations execute ONLY when APP_ENV='lab' and the active database
    is explicitly 'tenantshield_lab'. Refuses execution immediately otherwise.
    """
    env = (getattr(settings, "APP_ENV", "") or getattr(settings, "ENVIRONMENT", "")).lower()
    if env != "lab":
        raise MutationSafetyError(
            f"Safety Refusal: Isolation mutation testing can only run when APP_ENV='lab' (currently '{env}'). "
            f"Execution refused."
        )

    # Check active lab database connection string
    target_url = getattr(settings, "LAB_DATABASE_URL", "")
    parsed = urlparse(target_url)
    db_name = parsed.path.lstrip("/")
    if db_name != "tenantshield_lab":
        raise MutationSafetyError(
            f"Safety Refusal: Isolation mutation testing can only execute against database 'tenantshield_lab' "
            f"(currently '{db_name}'). Execution refused."
        )


def query_db_evidence(admin_url: str) -> Dict[str, Any]:
    """
    Directly queries PostgreSQL system catalogs on tenantshield_lab at run time.
    Does not rely on log lines or assumptions.
    """
    lab_admin_url = get_lab_url_from_admin(admin_url)
    engine = create_engine(lab_admin_url)
    try:
        with engine.connect() as conn:
            # 1. RLS flags on documents table
            row = conn.execute(
                stext("SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = 'documents'")
            ).fetchone()
            relrowsecurity = bool(row.relrowsecurity) if row else None
            relforcerowsecurity = bool(row.relforcerowsecurity) if row else None

            # 2. Current role connected
            user_row = conn.execute(stext("SELECT current_user")).fetchone()
            current_role = user_row.current_user if user_row else None

            # 3. Active policies on documents table
            pol_rows = conn.execute(
                stext(
                    "SELECT policyname, cmd, roles::text, qual, with_check "
                    "FROM pg_policies WHERE tablename = 'documents'"
                )
            ).fetchall()
            policies = [
                {
                    "policyname": p.policyname,
                    "cmd": p.cmd,
                    "roles": p.roles,
                    "qual": p.qual,
                    "with_check": p.with_check,
                }
                for p in pol_rows
            ]

            # 4. Role attributes for tenantshield_app and current_role
            role_attr_rows = conn.execute(
                stext(
                    "SELECT rolname, rolsuper, rolbypassrls, rolinherit "
                    "FROM pg_roles WHERE rolname IN ('tenantshield_app', 'tenantshield_lab_bypass', :c_role)"
                ),
                {"c_role": current_role or ""},
            ).fetchall()
            role_attributes = {
                r.rolname: {
                    "rolsuper": bool(r.rolsuper),
                    "rolbypassrls": bool(r.rolbypassrls),
                    "rolinherit": bool(r.rolinherit),
                }
                for r in role_attr_rows
            }

            # 5. Document counts per tenant
            doc_counts = conn.execute(
                stext("SELECT tenant_id::text, count(*) as count FROM documents GROUP BY tenant_id")
            ).fetchall()
            documents_per_tenant = {d.tenant_id: d.count for d in doc_counts}
            total_documents = sum(documents_per_tenant.values())

        return {
            "current_user": current_role,
            "relrowsecurity": relrowsecurity,
            "relforcerowsecurity": relforcerowsecurity,
            "policies": policies,
            "role_attributes": role_attributes,
            "total_documents": total_documents,
            "documents_per_tenant": documents_per_tenant,
        }
    finally:
        engine.dispose()


def check_baseline_state(admin_url: str) -> Dict[str, Any]:
    """
    Verifies that the database and application controls match the expected clean baseline state:
    - relrowsecurity = True
    - relforcerowsecurity = True
    - policy exists with normal '=' condition
    - tenantshield_app has rolbypassrls = False
    """
    evidence = query_db_evidence(admin_url)
    rls_ok = evidence.get("relrowsecurity") is True and evidence.get("relforcerowsecurity") is True

    # Check policy condition
    policies = evidence.get("policies", [])
    doc_policy = next((p for p in policies if p["policyname"] == "tenant_isolation_policy"), None)
    policy_condition_ok = False
    if doc_policy:
        qual = doc_policy.get("qual") or ""
        policy_condition_ok = "!=" not in qual and "=" in qual

    # Check role bypassrls
    roles = evidence.get("role_attributes", {})
    app_role_ok = True
    if "tenantshield_app" in roles:
        app_role_ok = not roles["tenantshield_app"].get("rolbypassrls", False)

    is_baseline = rls_ok and policy_condition_ok and app_role_ok
    return {
        "is_baseline": is_baseline,
        "rls_ok": rls_ok,
        "policy_condition_ok": policy_condition_ok,
        "app_role_ok": app_role_ok,
        "evidence": evidence,
    }


def derive_attack_reason_code(
    attack: Dict[str, Any],
    layer_a: bool,
    layer_b: bool,
    layer_c: bool,
    mutation_id: Optional[str] = None,
) -> str:
    """
    Derives observed reason code from factual test results and layer states.
    """
    outcome = attack.get("outcome", "")
    status = attack.get("status_code", 0)
    category = attack.get("category", "")
    blocking = attack.get("blocking_control", "unknown")

    if outcome == "LEAKED":
        return "NONE"
    if outcome == "INCONCLUSIVE":
        return "RATE_LIMITED_429"

    if blocking == "ROLE_CHECK" or status == 403:
        return "ROLE_CHECK"
    if blocking == "TOKEN_TENANT_CONTEXT" or status == 401:
        return "TOKEN_TENANT_CONTEXT"

    if category in ("read", "update", "delete"):
        if status == 404:
            if layer_a and not layer_b:
                return "OWNERSHIP_CHECK"
            elif layer_b and not layer_a:
                return "RLS_FILTERED"
            elif layer_c and not layer_a and not layer_b:
                return "QUERY_TENANT_FILTER"
            elif layer_a and layer_b:
                return "OWNERSHIP_CHECK"
            else:
                return "DECRYPT_FAILED"

    if category == "create_injection":
        proof = attack.get("create_injection_proof")
        if proof and proof.get("new_doc_owned_by_attacker"):
            return "TOKEN_TENANT_CONTEXT"

    return "unknown"


class IsolationMutationRunner:
    """
    Orchestrates isolation mutation testing against tenantshield_lab.
    """

    def __init__(self, admin_url: Optional[str] = None):
        self.admin_url = admin_url or os.getenv("POSTGRES_ADMIN_URL")
        if not self.admin_url:
            raise ValueError("POSTGRES_ADMIN_URL environment variable is required.")
        self.results: List[Dict[str, Any]] = []

    def _reset_lab(self) -> None:
        """Resets tenantshield_lab to clean baseline schema and data."""
        setup_or_reset_lab_database(self.admin_url, reset=True)
        reconfigure_engine(settings.LAB_DATABASE_URL)

    async def run_clean_baseline(self) -> Dict[str, Any]:
        """
        Executes clean baseline check: all controls ON, no mutation.
        Requires NO_LEAK_DETECTED and correct RLS flags; aborts otherwise.
        """
        verify_mutation_safety()
        print("\n[*] Initializing Clean Baseline Verification...")
        self._reset_lab()

        # Ensure all baseline switches are ON
        settings.APP_ENV = "lab"
        settings.ENVIRONMENT = "lab"
        settings.ENABLE_APP_OWNERSHIP_CHECK = True
        settings.ENABLE_DB_RLS = True
        settings.ENABLE_QUERY_TENANT_FILTER = True
        settings.MUTATION_SESSION_TENANT_CONTEXT = False
        reconfigure_engine(settings.LAB_DATABASE_URL)

        baseline_state = check_baseline_state(self.admin_url)
        if not baseline_state["is_baseline"]:
            raise RuntimeError(
                f"Clean baseline state check failed: rls_ok={baseline_state['rls_ok']}, "
                f"policy_condition_ok={baseline_state['policy_condition_ok']}, "
                f"app_role_ok={baseline_state['app_role_ok']}"
            )

        runner = VerificationRunner()
        report = await runner.run_verification()

        verdict = report["summary"]["overall_verdict"]
        control_passed = report["summary"]["control_verification"] == "PASSED"
        leaks = report["summary"]["leaked_attacks"]

        if verdict != "NO_LEAK_DETECTED" or not control_passed or leaks > 0:
            raise RuntimeError(
                f"Clean baseline run failed security requirement: verdict={verdict}, "
                f"control_passed={control_passed}, leaks={leaks}. Aborting mutation run."
            )

        print("[+] Clean baseline verified: NO_LEAK_DETECTED, control PASSED, 0 leaks.")
        return {
            "verdict": verdict,
            "control_passed": control_passed,
            "leaks": leaks,
            "evidence": baseline_state["evidence"],
        }

    # =========================================================================
    # Mutation 1: Query missing its tenant filter in the application layer
    # =========================================================================
    @contextmanager
    def _mutate_1_missing_query_tenant_filter(self):
        orig_val = settings.ENABLE_QUERY_TENANT_FILTER
        try:
            settings.ENABLE_QUERY_TENANT_FILTER = False
            yield
        finally:
            settings.ENABLE_QUERY_TENANT_FILTER = orig_val

    # =========================================================================
    # Mutation 2: RLS policy with the condition flipped
    # =========================================================================
    @contextmanager
    def _mutate_2_flipped_rls_policy(self):
        lab_admin_url = get_lab_url_from_admin(self.admin_url)
        engine = create_engine(lab_admin_url, isolation_level="AUTOCOMMIT")
        try:
            with engine.connect() as conn:
                conn.execute(stext("DROP POLICY IF EXISTS tenant_isolation_policy ON documents;"))
                conn.execute(
                    stext(
                        "CREATE POLICY tenant_isolation_policy ON documents "
                        "FOR ALL "
                        "USING (tenant_id != NULLIF(current_setting('app.current_tenant_id', true), '')::uuid) "
                        "WITH CHECK (tenant_id != NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);"
                    )
                )
            yield
        finally:
            with engine.connect() as conn:
                conn.execute(stext("DROP POLICY IF EXISTS tenant_isolation_policy ON documents;"))
                conn.execute(
                    stext(
                        "CREATE POLICY tenant_isolation_policy ON documents "
                        "FOR ALL "
                        "USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid) "
                        "WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);"
                    )
                )
            engine.dispose()

    # =========================================================================
    # Mutation 3: RLS not enabled on the documents table
    # =========================================================================
    @contextmanager
    def _mutate_3_rls_not_enabled(self):
        lab_admin_url = get_lab_url_from_admin(self.admin_url)
        engine = create_engine(lab_admin_url, isolation_level="AUTOCOMMIT")
        try:
            with engine.connect() as conn:
                conn.execute(stext("ALTER TABLE documents NO FORCE ROW LEVEL SECURITY;"))
                conn.execute(stext("ALTER TABLE documents DISABLE ROW LEVEL SECURITY;"))
            yield
        finally:
            with engine.connect() as conn:
                conn.execute(stext("ALTER TABLE documents ENABLE ROW LEVEL SECURITY;"))
                conn.execute(stext("ALTER TABLE documents FORCE ROW LEVEL SECURITY;"))
            engine.dispose()

    # =========================================================================
    # Mutation 4: Application connecting as a role with BYPASSRLS
    # =========================================================================
    @contextmanager
    def _mutate_4_bypassrls_role(self):
        lab_admin_url = get_lab_url_from_admin(self.admin_url)
        engine = create_engine(lab_admin_url, isolation_level="AUTOCOMMIT")
        bypass_role = "tenantshield_lab_bypass"
        bypass_pwd = "lab_bypass_pass_secure_123"

        # Create lab-only bypass role
        with engine.connect() as conn:
            conn.execute(
                stext(f"""
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{bypass_role}') THEN
                        CREATE ROLE {bypass_role} WITH LOGIN PASSWORD '{bypass_pwd}' BYPASSRLS;
                    ELSE
                        ALTER ROLE {bypass_role} WITH BYPASSRLS;
                    END IF;
                END
                $$;
                GRANT USAGE ON SCHEMA public TO {bypass_role};
                GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO {bypass_role};
                GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO {bypass_role};
                """)
            )

        # Derive bypass connection URL
        parsed = urlparse(settings.LAB_DATABASE_URL)
        bypass_netloc = f"{bypass_role}:{bypass_pwd}@{parsed.hostname}:{parsed.port or 5432}"
        bypass_url = urlunparse((parsed.scheme, bypass_netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))

        try:
            reconfigure_engine(bypass_url)
            yield
        finally:
            # Revert to standard application role
            reconfigure_engine(settings.LAB_DATABASE_URL)
            with engine.connect() as conn:
                conn.execute(
                    stext(
                        f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                        f"WHERE usename = '{bypass_role}'"
                    )
                )
                conn.execute(stext(f"DROP OWNED BY {bypass_role};"))
                conn.execute(stext(f"DROP ROLE IF EXISTS {bypass_role};"))
            engine.dispose()

    # =========================================================================
    # Mutation 5: Tenant context leaking through connection pooling
    # =========================================================================
    @contextmanager
    def _mutate_5_connection_pool_leakage(self):
        orig_session_ctx = settings.MUTATION_SESSION_TENANT_CONTEXT
        try:
            settings.MUTATION_SESSION_TENANT_CONTEXT = True
            # Reconfigure engine with pool_size=1, max_overflow=0 to guarantee connection reuse
            reconfigure_engine(settings.LAB_DATABASE_URL, pool_size=1, max_overflow=0)
            yield
        finally:
            settings.MUTATION_SESSION_TENANT_CONTEXT = orig_session_ctx
            reconfigure_engine(settings.LAB_DATABASE_URL)

    async def execute_uncontextualized_leak_test(self) -> Dict[str, Any]:
        """
        Special test for Mutation 5:
        1. Tenant B executes a request that sets app.current_tenant_id at session level (is_local=false).
        2. Next request on the same pooled connection sets NO tenant context.
        3. Queries documents table: returns Tenant B's rows because context leaked across connection checkout!
        Returns the captured rows demonstrating cross-tenant leakage.
        """
        from app.core.database import AsyncSessionLocal, set_tenant_context

        # Fetch Tenant B ID from database
        lab_admin_url = get_lab_url_from_admin(self.admin_url)
        engine = create_engine(lab_admin_url, isolation_level="AUTOCOMMIT")
        with engine.connect() as conn:
            tb_row = conn.execute(stext("SELECT id FROM tenants WHERE slug = 'beta'")).fetchone()
            tenant_id_b = str(tb_row[0]) if tb_row else None
            # Seed a canary row for Tenant B directly if not present
            doc_row = conn.execute(
                stext("SELECT id, title, tenant_id FROM documents WHERE tenant_id = :tid"),
                {"tid": tenant_id_b},
            ).fetchone()
            if not doc_row:
                conn.execute(
                    stext(
                        "INSERT INTO documents (tenant_id, title, created_at, updated_at) "
                        "VALUES (:tid, 'Beta Pool Canary Doc', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
                    ),
                    {"tid": tenant_id_b},
                )
        engine.dispose()

        # Request 1: Tenant B sets session-level context on the single connection
        async with AsyncSessionLocal() as session1:
            async with session1.begin():
                await set_tenant_context(session1, tenant_id_b)
                # Session 1 commits; connection returned to pool with session variable still set!

        # Request 2: A request checks out the pooled connection and sets NO tenant context
        rows_observed = []
        async with AsyncSessionLocal() as session2:
            async with session2.begin():
                # NO set_tenant_context called!
                res = await session2.execute(
                    stext("SELECT id, tenant_id::text, title FROM documents")
                )
                rows = res.fetchall()
                for r in rows:
                    rows_observed.append({"id": str(r.id), "tenant_id": r.tenant_id, "title": r.title})

        context_leaked = any(r["tenant_id"] == tenant_id_b for r in rows_observed)
        return {
            "test_name": "Uncontextualized Connection Pool Leak Test",
            "context_leaked": context_leaked,
            "target_tenant_id": tenant_id_b,
            "rows_returned_count": len(rows_observed),
            "rows_returned": rows_observed,
        }

    # =========================================================================
    # Execution Orchestrator
    # =========================================================================
    async def run_single_mutation(
        self,
        mutation_id: str,
        mutation_name: str,
        description: str,
        mutated_layer: str,
        mutation_cm_factory,
        detection_method: str = "ATTACK_SUITE",
    ) -> Dict[str, Any]:
        """
        Executes both ISOLATED and MASKED runs for a single mutation:
        - ISOLATED run: Mutation applied, other controls OFF.
        - MASKED run: Mutation applied, all other controls ON.
        - try/finally ensures clean revert and baseline verification.
        """
        verify_mutation_safety()
        print(f"\n" + "-" * 75)
        print(f"[*] Executing Mutation: {mutation_name}")
        print(f"    Description: {description}")
        print(f"    Mutated Layer: {mutated_layer}")
        print(f"    Detection Method: {detection_method}")
        print("-" * 75)

        isolated_result: Optional[Dict[str, Any]] = None
        masked_result: Optional[Dict[str, Any]] = None
        evidence_during: Optional[Dict[str, Any]] = None
        baseline_restored = False
        uncontextualized_test: Optional[Dict[str, Any]] = None

        # ---------------------------------------------------------------------
        # Part A: ISOLATED RUN
        # ---------------------------------------------------------------------
        print("[*] Starting ISOLATED run (other isolation controls OFF)...")
        self._reset_lab()

        # Switch other controls OFF
        settings.APP_ENV = "lab"
        settings.ENVIRONMENT = "lab"
        # In isolated run, Layer A and Layer C are OFF
        settings.ENABLE_APP_OWNERSHIP_CHECK = False
        settings.ENABLE_QUERY_TENANT_FILTER = False
        # For Layer B, if the mutation itself is NOT an RLS disablement, RLS is active on DB
        # (e.g. for flipped policy or bypassrls, RLS is on table, but flawed or bypassed)
        settings.ENABLE_DB_RLS = (mutated_layer != "Layer C (Application Query Filter)")

        # In Mutation 1 (query filter missing), Layer B RLS must also be switched OFF so only the query filter layer stood
        if mutation_id == "mut_1_missing_query_tenant_filter":
            settings.ENABLE_DB_RLS = False
            from scripts.setup_lab_db import set_lab_rls
            set_lab_rls(self.admin_url, enable=False)

        try:
            if mutation_id == "mut_5_connection_pool_leakage":
                with mutation_cm_factory():
                    uncontextualized_test = await self.execute_uncontextualized_leak_test()

            runner = VerificationRunner()
            report_isolated = await runner.run_verification(attack_context=mutation_cm_factory)

            # Record evidence during mutation
            with mutation_cm_factory():
                evidence_during = query_db_evidence(self.admin_url)

            leaks_isolated = report_isolated["summary"]["leaked_attacks"]
            verdict_isolated = report_isolated["summary"]["overall_verdict"]

            # Annotate attacks with observed reason codes
            for a in report_isolated["attack_results"]:
                a["observed_reason"] = derive_attack_reason_code(
                    a,
                    layer_a=settings.ENABLE_APP_OWNERSHIP_CHECK,
                    layer_b=settings.ENABLE_DB_RLS,
                    layer_c=settings.ENABLE_QUERY_TENANT_FILTER,
                    mutation_id=mutation_id,
                )

            # A mutation is CAUGHT if the attack suite reports a leak in its ISOLATED run
            # Or if uncontextualized pool leak test caught cross-tenant leakage
            is_caught = leaks_isolated > 0 or (
                uncontextualized_test and uncontextualized_test.get("context_leaked", False)
            )

            isolated_result = {
                "outcome": "CAUGHT" if is_caught else "MISSED",
                "total_leaks": leaks_isolated,
                "overall_verdict": verdict_isolated,
                "control_passed": report_isolated["summary"]["control_verification"] == "PASSED",
                "canary_integrity": report_isolated["summary"]["tenant_b_canary_integrity"],
                "list_leak_check": report_isolated["summary"]["list_leak_check"],
                "attacks": report_isolated["attack_results"],
            }
        finally:
            # Revert lab switches and state
            settings.ENABLE_APP_OWNERSHIP_CHECK = True
            settings.ENABLE_DB_RLS = True
            settings.ENABLE_QUERY_TENANT_FILTER = True
            settings.MUTATION_SESSION_TENANT_CONTEXT = False
            reconfigure_engine(settings.LAB_DATABASE_URL)
            self._reset_lab()

        # ---------------------------------------------------------------------
        # Part B: MASKED RUN
        # ---------------------------------------------------------------------
        print("[*] Starting MASKED run (all other isolation controls ON)...")
        settings.ENABLE_APP_OWNERSHIP_CHECK = True
        settings.ENABLE_DB_RLS = True
        settings.ENABLE_QUERY_TENANT_FILTER = True
        settings.MUTATION_SESSION_TENANT_CONTEXT = False
        reconfigure_engine(settings.LAB_DATABASE_URL)

        try:
            runner_masked = VerificationRunner()
            report_masked = await runner_masked.run_verification(attack_context=mutation_cm_factory)

            leaks_masked = report_masked["summary"]["leaked_attacks"]
            verdict_masked = report_masked["summary"]["overall_verdict"]

            masked_result = {
                "leak_detected": leaks_masked > 0,
                "total_leaks": leaks_masked,
                "overall_verdict": verdict_masked,
                "masked_by_other_layers": leaks_masked == 0,
                "control_passed": report_masked["summary"]["control_verification"] == "PASSED",
                "canary_integrity": report_masked["summary"]["tenant_b_canary_integrity"],
            }
        finally:
            # Revert and reset
            settings.ENABLE_APP_OWNERSHIP_CHECK = True
            settings.ENABLE_DB_RLS = True
            settings.ENABLE_QUERY_TENANT_FILTER = True
            settings.MUTATION_SESSION_TENANT_CONTEXT = False
            reconfigure_engine(settings.LAB_DATABASE_URL)
            self._reset_lab()

            # Verify baseline restoration
            post_state = check_baseline_state(self.admin_url)
            baseline_restored = post_state["is_baseline"]
            print(f"[+] Revert complete. Baseline restored: {baseline_restored}")

        result_item = {
            "mutation_id": mutation_id,
            "name": mutation_name,
            "description": description,
            "mutated_layer": mutated_layer,
            "detection_method": detection_method,
            "isolated_outcome": isolated_result["outcome"] if isolated_result else "MISSED",
            "isolated_run": isolated_result,
            "masked_run": masked_result,
            "evidence": evidence_during,
            "uncontextualized_test": uncontextualized_test,
            "baseline_restored": baseline_restored,
        }
        self.results.append(result_item)
        return result_item

    async def run_all_mutations(self) -> Dict[str, Any]:
        """
        Executes the clean baseline run, followed by all 5 realistic mutations.
        Generates JSON and CSV reports in results/.
        """
        verify_mutation_safety()

        # Temporarily increase rate limit to prevent 429 masking
        orig_rate_limit = settings.RATE_LIMIT_REQUESTS
        settings.RATE_LIMIT_REQUESTS = 100000

        timestamp_iso = datetime.now(timezone.utc).isoformat()
        timestamp_slug = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        run_id = f"mut_run_{timestamp_slug}"

        try:
            # Step 1: Clean Baseline
            baseline_result = await self.run_clean_baseline()

            # Step 2: 5 Realistic Isolation Mutations
            mutations_specs = [
                (
                    "mut_1_missing_query_tenant_filter",
                    "Mutation 1: Query missing tenant filter in application layer",
                    "Application query omits WHERE tenant_id = :tenant_id clause in document operations.",
                    "Layer C (Application Query Filter)",
                    "ATTACK_SUITE",
                    self._mutate_1_missing_query_tenant_filter,
                ),
                (
                    "mut_2_flipped_rls_policy",
                    "Mutation 2: RLS policy with condition flipped",
                    "PostgreSQL RLS policy uses 'tenant_id != current_setting(...)' allowing cross-tenant rows.",
                    "Layer B (Database RLS Policy)",
                    "ATTACK_SUITE",
                    self._mutate_2_flipped_rls_policy,
                ),
                (
                    "mut_3_rls_not_enabled",
                    "Mutation 3: RLS not enabled on documents table",
                    "Documents table has ROW LEVEL SECURITY disabled or unforced.",
                    "Layer B (Database RLS Table Enforcement)",
                    "ATTACK_SUITE",
                    self._mutate_3_rls_not_enabled,
                ),
                (
                    "mut_4_bypassrls_role",
                    "Mutation 4: Application connecting as role with BYPASSRLS",
                    "Application connects using a database role granted the BYPASSRLS privilege.",
                    "Layer B Bypass (PostgreSQL Role Privilege)",
                    "ATTACK_SUITE",
                    self._mutate_4_bypassrls_role,
                ),
                (
                    "mut_5_connection_pool_leakage",
                    "Mutation 5: Tenant context leaking through connection pooling",
                    "Tenant context set at session level (is_local=false) with pool_size=1, leaking context across checkouts.",
                    "Session Management & Connection Pooling",
                    "DEDICATED_PROBE",
                    self._mutate_5_connection_pool_leakage,
                ),
            ]

            for mid, mname, mdesc, mlayer, dmethod, cm_factory in mutations_specs:
                await self.run_single_mutation(mid, mname, mdesc, mlayer, cm_factory, detection_method=dmethod)

            # Step 3: Compute Score and Findings
            suite_caught = sum(
                1 for m in self.results if m["isolated_outcome"] == "CAUGHT" and m.get("detection_method") == "ATTACK_SUITE"
            )
            probe_caught = sum(
                1 for m in self.results if m["isolated_outcome"] == "CAUGHT" and m.get("detection_method") == "DEDICATED_PROBE"
            )
            total_count = len(self.results)
            caught_count = suite_caught + probe_caught
            score_str = f"{suite_caught} caught by the attack suite and {probe_caught} caught by a dedicated probe, out of {total_count}"
            missed_mutations = [m["name"] for m in self.results if m["isolated_outcome"] == "MISSED"]

            report_data = {
                "suite": "TenantShield: Isolation Mutation Testing",
                "run_id": run_id,
                "timestamp": timestamp_iso,
                "definitions": DEFINITIONS,
                "environment": {
                    "app_env": settings.APP_ENV,
                    "database": "tenantshield_lab",
                    "redis_server": "Memurai Developer (localhost:6379)",
                },
                "baseline_run": baseline_result,
                "isolation_mutation_score": score_str,
                "total_injected": total_count,
                "total_caught": caught_count,
                "attack_suite_caught": suite_caught,
                "dedicated_probe_caught": probe_caught,
                "missed_mutations": missed_mutations,
                "mutations": self.results,
            }

            # Step 4: Save JSON and CSV reports
            results_dir = Path(__file__).resolve().parent.parent / "results"
            results_dir.mkdir(parents=True, exist_ok=True)

            json_path = results_dir / f"mutation_report_{timestamp_slug}.json"
            csv_path = results_dir / f"mutation_report_{timestamp_slug}.csv"

            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2, default=str)

            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "Mutation ID",
                    "Mutation Name",
                    "Mutated Layer",
                    "Detection Method",
                    "Isolated Outcome",
                    "Isolated Leaks",
                    "Masked Leak Detected",
                    "Baseline Restored",
                    "Description",
                ])
                for m in self.results:
                    writer.writerow([
                        m["mutation_id"],
                        m["name"],
                        m["mutated_layer"],
                        m.get("detection_method", "ATTACK_SUITE"),
                        m["isolated_outcome"],
                        m["isolated_run"]["total_leaks"] if m.get("isolated_run") else "N/A",
                        m["masked_run"]["leak_detected"] if m.get("masked_run") else "N/A",
                        m["baseline_restored"],
                        m["description"],
                    ])

            self._print_console_summary(report_data, json_path, csv_path)
            return report_data
        finally:
            settings.RATE_LIMIT_REQUESTS = orig_rate_limit

    def _print_console_summary(self, report: Dict[str, Any], json_path: Path, csv_path: Path) -> None:
        """Prints observed executive summary table using strict factual wording."""
        print("\n" + "=" * 105)
        print(" TENANTSHIELD: ISOLATION MUTATION TESTING SUMMARY")
        print(" Target: tenantshield_lab | No Docker | Native Windows PostgreSQL 16")
        print("=" * 105)
        print(f" Run ID:    {report['run_id']}")
        print(f" Timestamp: {report['timestamp']}")
        print(f" Score:     {report['isolation_mutation_score']}")
        print("-" * 105)
        print(f"{'#':<3} {'Mutation Name':<38} {'Layer':<18} {'Method':<16} {'Isolated':<10} {'Masked':<10} {'Restored':<8}")
        print("-" * 105)

        for i, m in enumerate(report["mutations"], start=1):
            isolated_status = m["isolated_outcome"]
            masked_status = "LEAK" if m["masked_run"]["leak_detected"] else "NO_LEAK"
            restored = "YES" if m["baseline_restored"] else "NO"
            layer_short = m["mutated_layer"][:17]
            method_short = m.get("detection_method", "ATTACK_SUITE")[:15]
            print(f"{i:<3} {m['name'][:37]:<38} {layer_short:<18} {method_short:<16} {isolated_status:<10} {masked_status:<10} {restored:<8}")

        print("-" * 105)
        if report["missed_mutations"]:
            print(f" MISSED Mutations ({len(report['missed_mutations'])}):")
            for missed in report["missed_mutations"]:
                print(f"  - {missed}")
        else:
            print(" MISSED Mutations: None (0)")

        print(f"\n Reports saved:")
        print(f"  JSON: {json_path}")
        print(f"  CSV:  {csv_path}")
        print("=" * 90 + "\n")
