"""
TenantShield - Live Dynamic Noisy Neighbour Benchmark API
=========================================================
Endpoints to launch, monitor, and retrieve results for dynamic real-time
noisy-neighbour experiments across any selectable tenants.
"""

import asyncio
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import sys
import time
from typing import Any, Dict, Optional
from uuid import uuid4

from fastapi import APIRouter, Body, Depends, HTTPException, Request, status

from app.api.deps import get_current_user
from app.api.dashboard import require_platform_admin
from app.schemas.auth import AuthenticatedUser

logger = logging.getLogger("tenantshield.benchmark_demo")

router = APIRouter(prefix="/admin/demo/benchmark", tags=["Benchmark Demo"])

BENCHMARK_REGISTRY: Dict[str, Dict[str, Any]] = {}
_benchmark_lock = asyncio.Lock()
_active_benchmark_proc: Optional[Any] = None
_active_benchmark_run_id: Optional[str] = None
_last_benchmark_start_time: float = 0.0

SCRATCH_DIR = Path(__file__).resolve().parent.parent.parent / "scratch"
SCRATCH_DIR.mkdir(parents=True, exist_ok=True)


async def _monitor_benchmark_process(run_id: str, proc: Any, timeout_seconds: float):
    global _active_benchmark_proc, _active_benchmark_run_id
    try:
        await asyncio.wait_for(proc.wait(), timeout=timeout_seconds)
        finish_iso = datetime.now(timezone.utc).isoformat()
        BENCHMARK_REGISTRY[run_id]["finish_time"] = finish_iso

        # Read last line from progress file
        prog_path = Path(BENCHMARK_REGISTRY[run_id]["progress_file"])
        summary = None
        if prog_path.exists():
            with open(prog_path, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]
            for line in reversed(lines):
                try:
                    data = json.loads(line)
                    if data.get("type") == "summary":
                        summary = data
                        break
                except Exception:
                    continue

        if summary:
            BENCHMARK_REGISTRY[run_id]["state"] = "completed"
            BENCHMARK_REGISTRY[run_id]["summary"] = summary
        else:
            BENCHMARK_REGISTRY[run_id]["state"] = "failed"
            BENCHMARK_REGISTRY[run_id]["error"] = "No summary recorded by benchmark script"
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        BENCHMARK_REGISTRY[run_id]["state"] = "failed"
        BENCHMARK_REGISTRY[run_id]["error"] = f"Benchmark timed out after {timeout_seconds} seconds"
    except Exception as exc:
        BENCHMARK_REGISTRY[run_id]["state"] = "failed"
        BENCHMARK_REGISTRY[run_id]["error"] = str(exc)
    finally:
        async with _benchmark_lock:
            if _active_benchmark_run_id == run_id:
                _active_benchmark_proc = None
                _active_benchmark_run_id = None


@router.post("/start", summary="Start Live Dynamic Benchmark")
async def start_live_benchmark(
    request: Request,
    payload: Optional[Dict[str, Any]] = Body(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> Dict[str, Any]:
    global _active_benchmark_proc, _active_benchmark_run_id, _last_benchmark_start_time

    require_platform_admin(current_user)

    data = payload or {}
    noisy_tenant = str(data.get("noisy_tenant", "acme")).lower().strip()
    victim_tenant = str(data.get("victim_tenant", "beta")).lower().strip()
    load_type = str(data.get("load_type", "high_volume")).lower().strip()
    strategy = str(data.get("strategy", "request_count")).lower().strip()
    duration = float(data.get("duration_seconds", 10.0))
    duration = max(3.0, min(duration, 30.0))

    if noisy_tenant == victim_tenant:
        victim_tenant = "beta" if noisy_tenant != "beta" else "acme"

    now = time.time()
    async with _benchmark_lock:
        if _active_benchmark_proc is not None and _active_benchmark_proc.returncode is None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A live benchmark run is currently in progress. Please wait for it to finish.",
            )

        if now - _last_benchmark_start_time < 3.0:
            remaining = round(3.0 - (now - _last_benchmark_start_time), 1)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Please wait {remaining} seconds before starting another benchmark run.",
            )

        run_id = str(uuid4())
        start_iso = datetime.now(timezone.utc).isoformat()
        progress_path = SCRATCH_DIR / f"benchmark_{run_id}.jsonl"

        workspace_root = Path(__file__).resolve().parent.parent.parent
        script_path = workspace_root / "scripts" / "live_benchmark.py"

        cmd = [
            sys.executable,
            str(script_path),
            "--noisy-tenant",
            noisy_tenant,
            "--victim-tenant",
            victim_tenant,
            "--load-type",
            load_type,
            "--duration",
            str(duration),
            "--strategy",
            strategy,
            "--progress-file",
            str(progress_path),
            "--target-url",
            "http://127.0.0.1:8000",
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
            logger.error("Failed to spawn benchmark process: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to launch benchmark process.",
            ) from exc

        _active_benchmark_proc = proc
        _active_benchmark_run_id = run_id
        _last_benchmark_start_time = now

        BENCHMARK_REGISTRY[run_id] = {
            "run_id": run_id,
            "noisy_tenant": noisy_tenant,
            "victim_tenant": victim_tenant,
            "load_type": load_type,
            "strategy": strategy,
            "duration": duration,
            "state": "running",
            "start_time": start_iso,
            "finish_time": None,
            "progress_file": str(progress_path),
            "summary": None,
            "error": None,
        }

        # Monitor in background with duration + 8s grace timeout
        asyncio.create_task(_monitor_benchmark_process(run_id, proc, duration + 8.0))

        return {
            "run_id": run_id,
            "state": "running",
            "noisy_tenant": noisy_tenant,
            "victim_tenant": victim_tenant,
            "load_type": load_type,
            "duration_seconds": duration,
        }


@router.get("/status/{run_id}", summary="Get Live Benchmark Status")
async def get_live_benchmark_status(
    run_id: str,
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> Dict[str, Any]:
    require_platform_admin(current_user)

    info = BENCHMARK_REGISTRY.get(run_id)
    if not info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Benchmark run '{run_id}' not found.",
        )

    # Check progress file for latest progress line
    prog_path = Path(info["progress_file"])
    latest_progress = None
    if prog_path.exists():
        try:
            with open(prog_path, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]
            for line in reversed(lines):
                try:
                    data = json.loads(line)
                    if data.get("type") == "summary":
                        info["summary"] = data
                        info["state"] = "completed"
                        break
                    elif data.get("type") == "progress" and latest_progress is None:
                        latest_progress = data
                except Exception:
                    continue
        except Exception as e:
            logger.warning("Error reading progress file: %s", e)

    return {
        "run_id": run_id,
        "state": info["state"],
        "noisy_tenant": info["noisy_tenant"],
        "victim_tenant": info["victim_tenant"],
        "load_type": info["load_type"],
        "duration": info["duration"],
        "start_time": info["start_time"],
        "finish_time": info.get("finish_time"),
        "progress": latest_progress,
        "summary": info.get("summary"),
        "error": info.get("error"),
    }
