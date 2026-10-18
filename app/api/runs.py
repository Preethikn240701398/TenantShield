"""
TenantShield - Verification Run Management API
==============================================
Provides endpoints to trigger normal-mode verification runs asynchronously
as separate processes, monitor status, and retrieve sanitized results.

Rules:
- Admin-only (401 without token, 403 for tenant users).
- Refuses when APP_ENV is 'lab' (400 Bad Request).
- Exactly one run at a time (409 Conflict if running).
- At most one start per 10 seconds (429 Too Many Requests).
- Separate process, fixed arguments, no client-supplied parameters.
- Timeout after 120 seconds.
- Status validated against in-memory UUID registry.
- Never returns logs, tokens, canary strings, or secrets.
"""

import asyncio
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import sys
import time
from typing import Any, Dict, Optional
import uuid
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status

from app.api.deps import get_current_user
from app.api.dashboard import (
    require_platform_admin,
    sanitize_value,
    get_latest_baseline_verification_file,
)
from app.core.config import settings
from app.schemas.auth import AuthenticatedUser

logger = logging.getLogger("tenantshield.runs")

router = APIRouter(prefix="/admin/dashboard", tags=["Verification Runs"])

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent

# In-memory registry: run_id -> run metadata dict
RUNS_REGISTRY: Dict[str, Dict[str, Any]] = {}
_active_process: Optional[asyncio.subprocess.Process] = None
_active_run_id: Optional[str] = None
_last_start_timestamp: float = 0.0
_registry_lock = asyncio.Lock()


def _is_lab_mode() -> bool:
    env = (getattr(settings, "APP_ENV", "") or getattr(settings, "ENVIRONMENT", "")).lower()
    return env == "lab"


async def _monitor_verification_process(run_id: str, proc: asyncio.subprocess.Process) -> None:
    global _active_process, _active_run_id
    try:
        # 120 second timeout cap
        await asyncio.wait_for(proc.wait(), timeout=120.0)
        finish_iso = datetime.now(timezone.utc).isoformat()

        if proc.returncode == 0:
            # Load newest BASELINE verification report
            target_file = get_latest_baseline_verification_file()
            summary = None
            attacks = []
            if target_file and target_file.exists():
                try:
                    with open(target_file, "r", encoding="utf-8") as f:
                        raw = json.load(f)
                    raw_sum = raw.get("summary", {})
                    raw_att = raw.get("attack_results", [])

                    summary = {
                        "generated_at_utc": raw.get("generated_at_utc"),
                        "total_attacks_run": raw_sum.get("total_attacks_run", len(raw_att)),
                        "blocked_attacks": raw_sum.get("blocked_attacks", 0),
                        "leaked_attacks": raw_sum.get("leaked_attacks", 0),
                        "inconclusive_attacks": raw_sum.get("inconclusive_attacks", 0),
                        "tenant_b_canary_integrity": raw_sum.get("tenant_b_canary_integrity", "UNKNOWN"),
                        "list_leak_check": raw_sum.get("list_leak_check", "UNKNOWN"),
                        "overall_verdict": raw_sum.get("overall_verdict", "UNKNOWN"),
                    }
                    for a in raw_att:
                        attacks.append({
                            "method": a.get("method"),
                            "target_path": a.get("target_path"),
                            "status_code": a.get("status_code"),
                            "outcome": a.get("outcome"),
                            "blocking_control": a.get("blocking_control"),
                        })
                except Exception as read_err:
                    logger.warning("Error reading newly produced report for run %s: %s", run_id, read_err)

            RUNS_REGISTRY[run_id]["state"] = "finished"
            RUNS_REGISTRY[run_id]["finish_time"] = finish_iso
            RUNS_REGISTRY[run_id]["summary"] = sanitize_value(summary)
            RUNS_REGISTRY[run_id]["attacks"] = sanitize_value(attacks)
        else:
            RUNS_REGISTRY[run_id]["state"] = "failed"
            RUNS_REGISTRY[run_id]["finish_time"] = finish_iso
            RUNS_REGISTRY[run_id]["error"] = f"Process exited with non-zero code {proc.returncode}"
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        finish_iso = datetime.now(timezone.utc).isoformat()
        RUNS_REGISTRY[run_id]["state"] = "failed"
        RUNS_REGISTRY[run_id]["finish_time"] = finish_iso
        RUNS_REGISTRY[run_id]["error"] = "Process timed out after 120 seconds"
    except Exception as exc:
        finish_iso = datetime.now(timezone.utc).isoformat()
        RUNS_REGISTRY[run_id]["state"] = "failed"
        RUNS_REGISTRY[run_id]["finish_time"] = finish_iso
        RUNS_REGISTRY[run_id]["error"] = "Process failed unexpectedly"
    finally:
        async with _registry_lock:
            if _active_run_id == run_id:
                _active_process = None
                _active_run_id = None


@router.post("/run-verification", summary="Trigger Normal Verification Run")
async def start_verification_run(
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Starts existing normal-mode verification as a separate background process.
    Refuses if APP_ENV is lab, if another run is active (409), or if requested
    within 10 seconds of previous start (429).
    """
    global _active_process, _active_run_id, _last_start_timestamp

    require_platform_admin(current_user)

    if _is_lab_mode():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Refused: Verification runner cannot be started when APP_ENV is lab.",
        )

    async with _registry_lock:
        now = time.time()
        # Check active process
        if _active_process is not None and _active_process.returncode is None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A verification run is currently in progress.",
            )

        # Rate limiting: at most 1 start per 10 seconds
        elapsed = now - _last_start_timestamp
        if elapsed < 10.0:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Please wait {int(10.0 - elapsed) + 1}s before starting another run.",
            )

        run_id = str(uuid.uuid4())
        start_iso = datetime.now(timezone.utc).isoformat()

        # Command: fixed path to scripts/run_verifier.py, no client arguments
        script_path = str(WORKSPACE_ROOT / "scripts" / "run_verifier.py")
        cmd = [sys.executable, script_path]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=str(WORKSPACE_ROOT),
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
        except Exception as exc:
            logger.error("Failed to spawn verification process: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to launch verification process.",
            ) from exc

        _active_process = proc
        _active_run_id = run_id
        _last_start_timestamp = now

        RUNS_REGISTRY[run_id] = {
            "run_id": run_id,
            "state": "running",
            "start_time": start_iso,
            "finish_time": None,
            "summary": None,
            "attacks": None,
        }

        # Spawn asynchronous monitor
        asyncio.create_task(_monitor_verification_process(run_id, proc))

        return {
            "run_id": run_id,
            "state": "running",
            "start_time": start_iso,
        }


@router.get("/run-status/{run_id}", summary="Check Verification Run Status")
async def get_verification_run_status(
    run_id: str,
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Returns state and sanitized outcome for a server-generated UUID run id.
    Refuses if APP_ENV is lab, if run_id is malformed, or if run_id is unknown.
    """
    require_platform_admin(current_user)

    if _is_lab_mode():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Refused: Verification run status cannot be queried when APP_ENV is lab.",
        )

    # Validate UUID syntax strictly
    try:
        valid_uuid = str(UUID(run_id))
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid run ID format; must be a valid UUID.",
        )

    async with _registry_lock:
        run_data = RUNS_REGISTRY.get(valid_uuid)
        if not run_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Run ID not found in registry.",
            )

        resp = {
            "run_id": run_data["run_id"],
            "state": run_data["state"],
            "start_time": run_data["start_time"],
            "finish_time": run_data["finish_time"],
        }
        if run_data.get("summary"):
            resp["summary"] = sanitize_value(run_data["summary"])
        if run_data.get("attacks"):
            resp["attacks"] = sanitize_value(run_data["attacks"])

        return resp
