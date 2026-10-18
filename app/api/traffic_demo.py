"""
TenantShield - Part 4 Send Test Traffic Demo Endpoints
======================================================
Administrative endpoints to initiate and monitor background test traffic for Demo Co.

Enforces:
- Platform Admin authentication strictly required (401 / 403).
- Refusal when APP_ENV is 'lab' (HTTP 400).
- Subprocess execution with 30-second timeout and 10-second cooldown between starts.
- Concurrency guard: HTTP 409 Conflict if a traffic run is active.
- Computes Before, After, and Change for Requests, Errors, and Average Latency.
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

from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from sqlalchemy import text

from app.api.deps import get_current_user
from app.api.dashboard import require_platform_admin
from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.schemas.auth import AuthenticatedUser
from app.services.metrics import MetricsService

logger = logging.getLogger("tenantshield.traffic_demo")

router = APIRouter(prefix="/admin/demo/traffic", tags=["Traffic Demo"])

# In-memory registry for traffic runs
TRAFFIC_REGISTRY: Dict[str, Dict[str, Any]] = {}
_traffic_lock = asyncio.Lock()
_active_traffic_proc: Optional[Any] = None
_active_traffic_run_id: Optional[str] = None
_last_traffic_start_time: float = 0.0

SCRATCH_DIR = Path(__file__).resolve().parent.parent.parent / "scratch"
SCRATCH_DIR.mkdir(parents=True, exist_ok=True)


def _is_lab_mode() -> bool:
    env = (getattr(settings, "APP_ENV", "") or getattr(settings, "ENVIRONMENT", "")).lower()
    return env == "lab"


def _check_lab_refusal() -> None:
    if _is_lab_mode():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Refused: Traffic demo endpoints are disabled when APP_ENV is lab.",
        )


async def _resolve_target_tenant(target: str = "demo") -> tuple[UUID, str, str]:
    t = (target or "demo").strip().lower()
    if "acme" in t:
        name_pattern = "Acme%"
        slug = "acme"
        display_name = "Acme Corp"
        canonical_key = "acme"
    elif "beta" in t:
        name_pattern = "Beta%"
        slug = "beta"
        display_name = "Beta Industries"
        canonical_key = "beta"
    else:
        name_pattern = "Demo Co%"
        slug = "demo-co"
        display_name = "Demo Co"
        canonical_key = "demo"

    async with AsyncSessionLocal() as session:
        res = await session.execute(
            text("SELECT id, name FROM tenants WHERE name ILIKE :pattern OR slug = :slug LIMIT 1"),
            {"pattern": name_pattern, "slug": slug},
        )
        row = res.fetchone()
        if not row:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Target tenant '{display_name}' not found.",
            )
        return row[0], canonical_key, display_name


async def _resolve_demo_tenant_id() -> UUID:
    uid, _, _ = await _resolve_target_tenant("demo")
    return uid


async def _get_demo_tenant_metrics(tenant_id: UUID) -> Dict[str, float]:
    """Reads current 60-min window metrics for Demo Co."""
    try:
        data = await MetricsService.get_aggregated_metrics(window_minutes=60, tenant_id=tenant_id)
        tenants = data.get("tenants", [])
        for t in tenants:
            if str(t.get("tenant_id")) == str(tenant_id):
                return {
                    "requests": float(t.get("request_count", 0)),
                    "errors": float(t.get("error_count", 0)),
                    "avg_latency_ms": float(t.get("avg_latency_ms", 0.0)),
                }
    except Exception as exc:
        logger.warning("Could not read demo tenant metrics: %s", exc)
    return {"requests": 0.0, "errors": 0.0, "avg_latency_ms": 0.0}


async def _monitor_traffic_process(run_id: str, proc: Any, demo_tenant_id: UUID):
    global _active_traffic_proc, _active_traffic_run_id
    try:
        await asyncio.wait_for(proc.wait(), timeout=30.0)
        finish_iso = datetime.now(timezone.utc).isoformat()

        # Wait 2 seconds per requirement for Redis metrics consolidation
        await asyncio.sleep(2.0)

        after_metrics = await _get_demo_tenant_metrics(demo_tenant_id)
        before_metrics = TRAFFIC_REGISTRY[run_id]["metrics"]["before"]

        comparison = {
            "requests": {
                "before": int(before_metrics["requests"]),
                "after": int(after_metrics["requests"]),
                "diff": int(after_metrics["requests"] - before_metrics["requests"]),
            },
            "errors": {
                "before": int(before_metrics["errors"]),
                "after": int(after_metrics["errors"]),
                "diff": int(after_metrics["errors"] - before_metrics["errors"]),
            },
            "avg_latency_ms": {
                "before": round(before_metrics["avg_latency_ms"], 2),
                "after": round(after_metrics["avg_latency_ms"], 2),
                "diff": round(after_metrics["avg_latency_ms"] - before_metrics["avg_latency_ms"], 2),
            },
        }

        TRAFFIC_REGISTRY[run_id]["state"] = "finished" if proc.returncode == 0 else "failed"
        TRAFFIC_REGISTRY[run_id]["finish_time"] = finish_iso
        TRAFFIC_REGISTRY[run_id]["metrics"]["after"] = after_metrics
        TRAFFIC_REGISTRY[run_id]["comparison"] = comparison
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        finish_iso = datetime.now(timezone.utc).isoformat()
        TRAFFIC_REGISTRY[run_id]["state"] = "failed"
        TRAFFIC_REGISTRY[run_id]["finish_time"] = finish_iso
        TRAFFIC_REGISTRY[run_id]["error"] = "Process timed out after 30 seconds"
    except Exception as exc:
        finish_iso = datetime.now(timezone.utc).isoformat()
        TRAFFIC_REGISTRY[run_id]["state"] = "failed"
        TRAFFIC_REGISTRY[run_id]["finish_time"] = finish_iso
        TRAFFIC_REGISTRY[run_id]["error"] = f"Traffic run failed: {exc}"
    finally:
        async with _traffic_lock:
            if _active_traffic_run_id == run_id:
                _active_traffic_proc = None
                _active_traffic_run_id = None


# ------------------------------------------------------------------------------
# 1. POST /admin/demo/traffic/start
# ------------------------------------------------------------------------------
@router.post("/start", summary="Start Test Traffic Generation")
async def start_test_traffic(
    request: Request,
    payload: Optional[Dict[str, Any]] = Body(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> Dict[str, Any]:
    global _active_traffic_proc, _active_traffic_run_id, _last_traffic_start_time

    require_platform_admin(current_user)
    _check_lab_refusal()

    target_tenant_arg = (payload or {}).get("tenant", "demo") if payload else "demo"
    target_id, canonical_key, display_name = await _resolve_target_tenant(target_tenant_arg)

    now = time.time()
    async with _traffic_lock:
        if _active_traffic_proc is not None and _active_traffic_proc.returncode is None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A test traffic run is currently active.",
            )

        if now - _last_traffic_start_time < 10.0:
            remaining = round(10.0 - (now - _last_traffic_start_time), 1)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit: please wait {remaining} seconds before starting another traffic run.",
            )

        before_metrics = await _get_demo_tenant_metrics(target_id)

        run_id = str(uuid4())
        start_iso = datetime.now(timezone.utc).isoformat()
        progress_path = SCRATCH_DIR / f"traffic_progress_{run_id}.jsonl"

        # Launch background process with fixed arguments
        workspace_root = Path(__file__).resolve().parent.parent.parent
        script_path = workspace_root / "scripts" / "send_test_traffic.py"
        cmd = [
            sys.executable,
            str(script_path),
            "--progress-file",
            str(progress_path),
            "--target-url",
            "http://127.0.0.1:8000",
            "--tenant",
            canonical_key,
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=str(workspace_root),
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
        except NotImplementedError:
            import subprocess
            from app.api.runs import PopenProcessAdapter
            p = subprocess.Popen(
                cmd,
                cwd=str(workspace_root),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            proc = PopenProcessAdapter(p)
        except Exception as exc:
            logger.error("Failed to spawn traffic process: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to launch traffic process.",
            ) from exc

        _active_traffic_proc = proc
        _active_traffic_run_id = run_id
        _last_traffic_start_time = now

        TRAFFIC_REGISTRY[run_id] = {
            "run_id": run_id,
            "target_tenant": display_name,
            "state": "running",
            "start_time": start_iso,
            "finish_time": None,
            "progress_file": str(progress_path),
            "metrics": {
                "before": before_metrics,
                "after": None,
            },
            "comparison": None,
        }

        asyncio.create_task(_monitor_traffic_process(run_id, proc, target_id))

        return {
            "run_id": run_id,
            "target_tenant": display_name,
            "state": "running",
            "start_time": start_iso,
        }


# ------------------------------------------------------------------------------
# 2. GET /admin/demo/traffic/status/{run_id}
# ------------------------------------------------------------------------------
@router.get("/status/{run_id}", summary="Check Traffic Run Status & Progress")
async def get_traffic_status(
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

    async with _traffic_lock:
        data = TRAFFIC_REGISTRY.get(valid_uuid)
        if not data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Traffic run ID not found in registry.",
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
            logger.warning("Could not read traffic progress file: %s", read_err)

    return {
        "run_id": data["run_id"],
        "state": data["state"],
        "start_time": data["start_time"],
        "finish_time": data.get("finish_time"),
        "progress": progress_records,
        "comparison": data.get("comparison"),
    }
