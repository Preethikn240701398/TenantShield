"""
TenantShield - Admin Dashboard & UI Support Endpoints
=====================================================
Protected administrative endpoints providing sanitized reporting data:
1. Latest verification attack report
2. Layer-kill matrix results
3. Isolation mutation test results
4. Noisy-neighbour experiment summary
5. Per-tenant key status (safe metadata only, zero key material)
6. Authenticated user context (with tenant name)

Security Boundaries:
- Strict requirement: current_user.role == 'platform_admin' for all dashboard data endpoints.
- Path Traversal Immunity: File names are resolved server-side with fixed patterns only.
- Secret Sanitization: Canary strings, tokens, and cryptographic keys are stripped.
- Empty State Integrity: Returns exact status and reproduction commands when no data exists.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import text

from app.api.deps import get_current_user
from app.core.database import AsyncSessionLocal, tenant_session
from app.schemas.auth import AuthenticatedUser

router = APIRouter(prefix="/admin/dashboard", tags=["Admin Dashboard"])

RESULTS_DIR = Path(__file__).resolve().parent.parent.parent / "results"

# Regex for stripping canary secrets and tokens from text
_SECRET_PATTERNS = [
    re.compile(r"canary_[a-zA-Z0-9_\-]+", re.IGNORECASE),
    re.compile(r"eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+"),  # JWT tokens
    re.compile(r"Bearer\s+[a-zA-Z0-9_\-\.]+", re.IGNORECASE),
]


def sanitize_value(val: Any) -> Any:
    """Recursively removes or redacts secret tokens and canary strings."""
    if isinstance(val, str):
        cleaned = val
        for pat in _SECRET_PATTERNS:
            cleaned = pat.sub("[REDACTED]", cleaned)
        return cleaned
    elif isinstance(val, dict):
        # Exclude sensitive keys entirely
        forbidden_keys = {"token", "password", "wrapped_dek", "wrapping_nonce", "ciphertext", "nonce"}
        return {
            k: sanitize_value(v)
            for k, v in val.items()
            if k.lower() not in forbidden_keys
        }
    elif isinstance(val, list):
        return [sanitize_value(item) for item in val]
    return val


def get_latest_result_file(prefix: str, extension: str = ".json") -> Optional[Path]:
    """
    Safely resolves the newest file matching a fixed prefix and extension
    strictly within the results/ directory. Does not accept external path inputs.
    """
    if not RESULTS_DIR.exists() or not RESULTS_DIR.is_dir():
        return None

    # Fixed glob pattern prevents any path traversal
    safe_pattern = f"{prefix}_*{extension}"
    candidates = list(RESULTS_DIR.glob(safe_pattern))
    if not candidates:
        return None

    # Sort by mtime, breaking ties with filename for deterministic sorting
    candidates.sort(key=lambda p: (p.stat().st_mtime, p.name), reverse=True)
    return candidates[0]


def get_latest_baseline_verification_file() -> Optional[Path]:
    """
    Resolves the newest verification report strictly matching run_type == 'BASELINE'.
    Reports without run_type are UNKNOWN and ignored.
    """
    if not RESULTS_DIR.exists() or not RESULTS_DIR.is_dir():
        return None

    safe_pattern = "verification_attack_report_*.json"
    candidates = list(RESULTS_DIR.glob(safe_pattern))
    if not candidates:
        return None

    candidates.sort(key=lambda p: (p.stat().st_mtime, p.name), reverse=True)
    for c in candidates:
        try:
            with open(c, "r", encoding="utf-8") as f:
                data = json.load(f)
            run_type = data.get("run_type") or data.get("summary", {}).get("run_type")
            if run_type == "BASELINE":
                return c
        except Exception:
            continue
    return None


def require_platform_admin(current_user: AuthenticatedUser) -> None:
    if current_user.role != "platform_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Platform administrator privileges required.",
        )


@router.get("/me", summary="Current User UI Context")
async def get_ui_user_context(
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Returns verified user identity including human-readable tenant name.
    Accessible to any authenticated user (tenant user or platform admin).
    """
    tenant_name = "TenantShield System"
    try:
        async with AsyncSessionLocal() as session:
            res = await session.execute(
                text("SELECT name FROM tenants WHERE id = :tid"),
                {"tid": current_user.tenant_id},
            )
            row = res.fetchone()
            if row:
                tenant_name = row[0]
    except Exception:
        pass

    return {
        "user_id": str(current_user.user_id),
        "tenant_id": str(current_user.tenant_id),
        "email": current_user.email,
        "role": current_user.role,
        "tenant_name": tenant_name,
    }


@router.get("/verification", summary="Latest Verification Attack Report")
async def get_verification_report(
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Returns latest verification run data with exact stored verdict and per-attack breakdown.
    Requires platform_admin role. Only returns newest report where run_type == 'BASELINE'.
    """
    require_platform_admin(current_user)

    target_file = get_latest_baseline_verification_file()
    if not target_file:
        return {
            "status": "empty",
            "message": "No verification run found. Run: python scripts/run_verifier.py (or python -m verifier.runner)",
        }

    try:
        with open(target_file, "r", encoding="utf-8") as f:
            raw_data = json.load(f)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error reading verification report: {str(exc)}",
        ) from exc

    raw_summary = raw_data.get("summary", {})
    raw_attacks = raw_data.get("attack_results", [])

    # Extract exact metrics as stored
    summary = {
        "generated_at_utc": raw_data.get("generated_at_utc"),
        "total_attacks_run": raw_summary.get("total_attacks_run", len(raw_attacks)),
        "blocked_attacks": raw_summary.get("blocked_attacks", 0),
        "leaked_attacks": raw_summary.get("leaked_attacks", 0),
        "inconclusive_attacks": raw_summary.get("inconclusive_attacks", 0),
        "tenant_b_canary_integrity": raw_summary.get("tenant_b_canary_integrity", "UNKNOWN"),
        "list_leak_check": raw_summary.get("list_leak_check", "UNKNOWN"),
        "overall_verdict": raw_summary.get("overall_verdict", "UNKNOWN"),
    }

    # Format attacks table safely without secrets
    attacks = []
    for att in raw_attacks:
        attacks.append({
            "attack_name": att.get("attack_name", "Unknown Attack"),
            "category": att.get("category", "generic"),
            "method": att.get("method", "GET"),
            "target_path": sanitize_value(att.get("target_path", "")),
            "status_code": att.get("status_code", 0),
            "outcome": att.get("outcome", "UNKNOWN"),
            "blocking_control": att.get("blocking_control", att.get("observed_reason", "none")),
        })

    return {
        "status": "success",
        "file_name": target_file.name,
        "summary": summary,
        "attacks": attacks,
        "note": "Results describe these runs only.",
    }


@router.get("/layer-kill", summary="Layer-Kill Matrix Results")
async def get_layer_kill_matrix(
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Returns layer-kill matrix results across configurations (a) to (e).
    Requires platform_admin role.
    """
    require_platform_admin(current_user)

    target_file = get_latest_result_file("layer_kill_matrix")
    if not target_file:
        return {
            "status": "empty",
            "message": "No layer-kill matrix run found. Run: python -m verifier.layer_kill",
        }

    try:
        with open(target_file, "r", encoding="utf-8") as f:
            raw_data = json.load(f)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error reading layer-kill matrix: {str(exc)}",
        ) from exc

    raw_matrix = raw_data.get("matrix", [])
    configurations = []
    for item in raw_matrix:
        leaks = item.get("leaks", {})
        configurations.append({
            "config_id": item.get("config_id", ""),
            "configuration": item.get("configuration", ""),
            "layer_a_app_check": item.get("layer_a_app_check", "OFF"),
            "layer_b_db_rls": item.get("layer_b_db_rls", "OFF"),
            "layer_c_query_filter": item.get("layer_c_query_filter", "OFF"),
            "leaks": {
                "read": leaks.get("read", 0),
                "write": leaks.get("write", 0),
                "update": leaks.get("update", 0),
                "delete": leaks.get("delete", 0),
                "total": leaks.get("total", 0),
            },
            "active_protections": item.get("active_protections", []),
            "config_verdict": item.get("config_verdict", "UNKNOWN"),
        })

    return {
        "status": "success",
        "file_name": target_file.name,
        "generated_at_utc": raw_data.get("generated_at_utc"),
        "overall_verdict": raw_data.get("overall_verdict", "UNKNOWN"),
        "configurations": configurations,
        "note": "Results describe these runs only.",
    }


@router.get("/mutation", summary="Isolation Mutation Test Results")
async def get_mutation_results(
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Returns isolation mutation testing results and per-mutation evaluation.
    Requires platform_admin role.
    """
    require_platform_admin(current_user)

    target_file = get_latest_result_file("mutation_report")
    if not target_file:
        return {
            "status": "empty",
            "message": "No mutation run found. Run: python scripts/run_mutation.py",
        }

    try:
        with open(target_file, "r", encoding="utf-8") as f:
            raw_data = json.load(f)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error reading mutation report: {str(exc)}",
        ) from exc

    score = raw_data.get(
        "isolation_mutation_score",
        f"{raw_data.get('attack_suite_caught', 0)} caught by the attack suite and "
        f"{raw_data.get('dedicated_probe_caught', 0)} caught by a dedicated probe, "
        f"out of {raw_data.get('total_injected', 0)}",
    )

    mutations = []
    for mut in raw_data.get("mutations", []):
        # Extract isolated and masked results
        isolated_res = mut.get("isolated_outcome") or mut.get("isolated_run", {}).get("outcome") or "UNKNOWN"
        masked_info = mut.get("masked_run", {})
        masked_res = masked_info.get("overall_verdict")
        if not masked_res:
            masked_res = "LEAK_DETECTED" if masked_info.get("leak_detected") else "NO_LEAK_DETECTED"

        mutations.append({
            "mutation_id": mut.get("mutation_id", ""),
            "name": mut.get("name", ""),
            "description": mut.get("description", ""),
            "mutated_layer": mut.get("mutated_layer", ""),
            "detection_method": mut.get("detection_method", "ATTACK_SUITE"),
            "isolated_result": isolated_res,
            "masked_result": masked_res,
            "baseline_restored": bool(mut.get("baseline_restored", False)),
        })

    return {
        "status": "success",
        "file_name": target_file.name,
        "timestamp": raw_data.get("timestamp"),
        "isolation_mutation_score": score,
        "total_injected": raw_data.get("total_injected", len(mutations)),
        "total_caught": raw_data.get("total_caught", 0),
        "attack_suite_caught": raw_data.get("attack_suite_caught", 0),
        "dedicated_probe_caught": raw_data.get("dedicated_probe_caught", 0),
        "mutations": mutations,
        "note": "Results describe these runs only.",
    }


@router.get("/noisy-neighbour", summary="Noisy-Neighbour Experiment Summary")
async def get_noisy_neighbour_summary(
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Returns noisy-neighbour experiment aggregated results by strategy and load type.
    Includes quiet-only baseline first and lists plan amendments.
    Requires platform_admin role.
    """
    require_platform_admin(current_user)

    target_file = get_latest_result_file("noisy_neighbour_summary")
    if not target_file:
        return {
            "status": "empty",
            "message": "No noisy-neighbour experiment found. Run: python -m loadtests.runner",
        }

    try:
        with open(target_file, "r", encoding="utf-8") as f:
            raw_data = json.load(f)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error reading noisy-neighbour summary: {str(exc)}",
        ) from exc

    raw_summaries = raw_data.get("summaries", [])

    # Order: quiet_baseline first, harness_overhead second, then other strategies
    def sort_key(item: dict) -> int:
        lt = item.get("load_type", "")
        if lt == "quiet_baseline":
            return 0
        if lt == "harness_overhead":
            return 1
        return 2

    ordered_summaries = sorted(raw_summaries, key=sort_key)

    formatted_summaries = []
    for s in ordered_summaries:
        p50 = s.get("beta_p50_ms", {})
        p95 = s.get("beta_p95_ms", {})
        err = s.get("beta_error_rate", {})
        acme_429 = s.get("acme_429", {})
        acme_timeouts = s.get("acme_timeouts", {})

        formatted_summaries.append({
            "strategy": s.get("strategy", ""),
            "strategy_label": s.get("strategy_label", s.get("strategy", "")),
            "load_type": s.get("load_type", ""),
            "repeats_count": s.get("repeats_count", 3),
            "beta_p50_ms": {
                "mean": round(p50.get("mean", 0.0), 2),
                "std": round(p50.get("std", 0.0), 2),
            },
            "beta_p95_ms": {
                "mean": round(p95.get("mean", 0.0), 2),
                "std": round(p95.get("std", 0.0), 2),
            },
            "beta_error_rate": {
                "mean": round(err.get("mean", 0.0), 4),
                "std": round(err.get("std", 0.0), 4),
            },
            "acme_429": {
                "mean": round(acme_429.get("mean", 0.0), 2),
                "std": round(acme_429.get("std", 0.0), 2),
            },
            "acme_timeouts": {
                "mean": round(acme_timeouts.get("mean", 0.0), 2),
                "std": round(acme_timeouts.get("std", 0.0), 2),
            },
        })

    # Plan amendments note (link-free text)
    amendments = [
        "Amendment 1: Limiter configuration settings explicit binding (LIMITER_REQUESTS_LIMIT=15, LIMITER_WINDOW_SECONDS=10).",
        "Amendment 2: Heavy query duration bounded and stabilized (~370 ms).",
        "Amendment 3: Added X-Process-Time-Ms response header to separate server latency from client harness overhead.",
        "Amendment 4: Extended measurement window to 30.0s for reliable p95 estimates.",
    ]

    return {
        "status": "success",
        "file_name": target_file.name,
        "generated_at_utc": raw_data.get("generated_at_utc"),
        "environment": raw_data.get("environment", {}),
        "plan": raw_data.get("plan", {}),
        "amendments": amendments,
        "summaries": formatted_summaries,
        "note": "Results describe these runs only.",
    }


@router.get("/keys", summary="Tenant Key Status")
async def get_tenant_keys_status(
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Returns cryptographic key status (active, retired, destroyed) per tenant.
    Never exposes key material, nonces, or ciphertext.
    Requires platform_admin role.
    """
    require_platform_admin(current_user)

    tenants_result = []
    async with AsyncSessionLocal() as session:
        # 1. Fetch all tenants
        t_rows = await session.execute(
            text("SELECT id, name, slug, is_active FROM tenants ORDER BY name ASC")
        )
        tenants = t_rows.fetchall()

    if not tenants:
        return {
            "status": "empty",
            "message": "No tenant keys found. Keys are initialized when tenants are provisioned.",
        }

    # 2. Query key status per tenant using transaction-local context
    for tid, name, slug, active in tenants:
        keys_for_tenant = []
        try:
            async with tenant_session(tid) as t_session:
                k_rows = await t_session.execute(
                    text(
                        "SELECT key_version, status, created_at, retired_at, destroyed_at "
                        "FROM tenant_keys WHERE tenant_id = :tid ORDER BY key_version ASC"
                    ),
                    {"tid": tid},
                )
                for kv, status_str, created, retired, destroyed in k_rows.fetchall():
                    keys_for_tenant.append({
                        "key_version": kv,
                        "status": status_str,
                        "created_at": created.isoformat() if created else None,
                        "retired_at": retired.isoformat() if retired else None,
                        "destroyed_at": destroyed.isoformat() if destroyed else None,
                    })
        except Exception:
            keys_for_tenant = []

        tenants_result.append({
            "tenant_id": str(tid),
            "tenant_name": name,
            "tenant_slug": slug,
            "is_active": active,
            "keys": keys_for_tenant,
        })

    return {
        "status": "success",
        "tenants": tenants_result,
        "note": "Results describe these runs only.",
    }
