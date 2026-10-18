"""
TenantShield - Part 5 Single Attack Demo Endpoints
===================================================
Administrative endpoints to configure, launch, and monitor a single cross-tenant attack.

Enforces:
- Platform Admin authentication strictly required (401 / 403).
- Refusal when APP_ENV is 'lab' (HTTP 400).
- Fixed list validation: attacker and victim in ["Acme", "Beta", "Demo Co"], attacker != victim,
  action in ["read", "update", "delete", "create-into-victim"].
- Subprocess execution with 30-second timeout and 5-second cooldown between starts.
- Concurrency guard: HTTP 409 Conflict if an attack run is active.
- Strictly sanitized responses: never exposes tokens, passwords, or credentials.
"""

import asyncio
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.api.deps import get_current_user
from app.api.dashboard import require_platform_admin
from app.core.config import settings
from app.schemas.auth import AuthenticatedUser

logger = logging.getLogger("tenantshield.attack_demo")

router = APIRouter(prefix="/admin/demo/attack", tags=["Attack Demo"])

ALLOWED_TENANTS = ["Acme", "Beta", "Demo Co"]
ALLOWED_ACTIONS = ["read", "update", "delete", "create-into-victim"]

# In-memory registry for attack runs
ATTACK_REGISTRY: Dict[str, Dict[str, Any]] = {}
_attack_lock = asyncio.Lock()
_active_attack_proc: Optional[asyncio.subprocess.Process] = None
_active_attack_run_id: Optional[str] = None
_last_attack_start_time: float = 0.0

SCRATCH_DIR = Path(__file__).resolve().parent.parent.parent / "scratch"
SCRATCH_DIR.mkdir(parents=True, exist_ok=True)


class AttackStartRequest(BaseModel):
    attacker: str = Field(..., description="Attacking tenant: Acme, Beta, or Demo Co")
    victim: str = Field(..., description="Victim tenant: Acme, Beta, or Demo Co")
    action: str = Field(..., description="Attack action: read, update, delete, or create-into-victim")


def _is_lab_mode() -> bool:
    env = (getattr(settings, "APP_ENV", "") or getattr(settings, "ENVIRONMENT", "")).lower()
    return env == "lab"


def _check_lab_refusal() -> None:
    if _is_lab_mode():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Refused: Attack demo endpoints are disabled when APP_ENV is lab.",
        )


async def _monitor_attack_process(run_id: str, proc: asyncio.subprocess.Process, output_path: Path):
    global _active_attack_proc, _active_attack_run_id
    try:
        await asyncio.wait_for(proc.wait(), timeout=30.0)
        finish_iso = datetime.now(timezone.utc).isoformat()

        # Load final output result if generated
        result_data = None
        if output_path.exists():
            try:
                with open(output_path, "r", encoding="utf-8") as f:
                    result_data = json.load(f)
            except Exception as e:
                logger.warning("Could not read attack output file: %s", e)

        ATTACK_REGISTRY[run_id]["state"] = "finished" if proc.returncode == 0 else "failed"
        ATTACK_REGISTRY[run_id]["finish_time"] = finish_iso
        ATTACK_REGISTRY[run_id]["result"] = result_data
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        finish_iso = datetime.now(timezone.utc).isoformat()
        ATTACK_REGISTRY[run_id]["state"] = "failed"
        ATTACK_REGISTRY[run_id]["finish_time"] = finish_iso
        ATTACK_REGISTRY[run_id]["error"] = "Process timed out after 30 seconds"
    except Exception as exc:
        finish_iso = datetime.now(timezone.utc).isoformat()
        ATTACK_REGISTRY[run_id]["state"] = "failed"
        ATTACK_REGISTRY[run_id]["finish_time"] = finish_iso
        ATTACK_REGISTRY[run_id]["error"] = f"Attack run failed: {exc}"
    finally:
        async with _attack_lock:
            if _active_attack_run_id == run_id:
                _active_attack_proc = None
                _active_attack_run_id = None


# ------------------------------------------------------------------------------
# 1. POST /admin/demo/attack/start
# ------------------------------------------------------------------------------
@router.post("/start", summary="Start Single Attack Execution")
async def start_single_attack(
    req: AttackStartRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> Dict[str, Any]:
    global _active_attack_proc, _active_attack_run_id, _last_attack_start_time

    require_platform_admin(current_user)
    _check_lab_refusal()

    # Validate inputs against fixed lists
    if req.attacker not in ALLOWED_TENANTS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid attacker '{req.attacker}'. Must be one of: {', '.join(ALLOWED_TENANTS)}",
        )
    if req.victim not in ALLOWED_TENANTS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid victim '{req.victim}'. Must be one of: {', '.join(ALLOWED_TENANTS)}",
        )
    if req.attacker == req.victim:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Attacker and victim must be different tenants.",
        )
    if req.action not in ALLOWED_ACTIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid action '{req.action}'. Must be one of: {', '.join(ALLOWED_ACTIONS)}",
        )

    now = time.time()
    async with _attack_lock:
        if _active_attack_proc is not None and _active_attack_proc.returncode is None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="An attack run is currently active.",
            )

        if now - _last_attack_start_time < 5.0:
            remaining = round(5.0 - (now - _last_attack_start_time), 1)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit: please wait {remaining} seconds before starting another attack run.",
            )

        run_id = str(uuid4())
        start_iso = datetime.now(timezone.utc).isoformat()
        progress_path = SCRATCH_DIR / f"attack_progress_{run_id}.jsonl"
        output_path = SCRATCH_DIR / f"attack_output_{run_id}.json"

        script_path = Path(__file__).resolve().parent.parent.parent / "scripts" / "single_attack.py"
        try:
            proc = await asyncio.create_subprocess_exec(
                sys.executable,
                str(script_path),
                "--attacker",
                req.attacker,
                "--victim",
                req.victim,
                "--action",
                req.action,
                "--progress-file",
                str(progress_path),
                "--output-file",
                str(output_path),
                "--target-url",
                "http://127.0.0.1:8000",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to launch attack process.",
            ) from exc

        _active_attack_proc = proc
        _active_attack_run_id = run_id
        _last_attack_start_time = now

        ATTACK_REGISTRY[run_id] = {
            "run_id": run_id,
            "state": "running",
            "start_time": start_iso,
            "finish_time": None,
            "attacker": req.attacker,
            "victim": req.victim,
            "action": req.action,
            "progress_file": str(progress_path),
            "output_file": str(output_path),
            "result": None,
        }

        asyncio.create_task(_monitor_attack_process(run_id, proc, output_path))

        return {
            "run_id": run_id,
            "state": "running",
            "start_time": start_iso,
        }


# ------------------------------------------------------------------------------
# 2. GET /admin/demo/attack/status/{run_id}
# ------------------------------------------------------------------------------
@router.get("/status/{run_id}", summary="Check Attack Run Status & Result")
async def get_attack_status(
    run_id: str,
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> Dict[str, Any]:
    require_platform_admin(current_user)
    _check_lab_refusal()

    # Validate UUID syntax strictly
    try:
        valid_uuid = str(UUID(run_id))
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid run ID format; must be a valid UUID.",
        )

    async with _attack_lock:
        data = ATTACK_REGISTRY.get(valid_uuid)
        if not data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Attack run ID not found in registry.",
            )

    # Read progress lines
    progress_records: List[Dict[str, Any]] = []
    progress_file = Path(data["progress_file"])
    if progress_file.exists():
        try:
            with open(progress_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            progress_records.append(json.loads(line))
                        except Exception:
                            pass
        except Exception as read_err:
            logger.warning("Could not read attack progress file: %s", read_err)

    return {
        "run_id": data["run_id"],
        "state": data["state"],
        "start_time": data["start_time"],
        "finish_time": data.get("finish_time"),
        "progress": progress_records,
        "result": data.get("result"),
    }
