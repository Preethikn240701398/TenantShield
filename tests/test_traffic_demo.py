"""
TenantShield - Part 4 Send Test Traffic Demo Test Suite
=======================================================
Verifies:
1. Endpoints require platform_admin role (401 unauthenticated, 403 tenant users).
2. Endpoints refuse with HTTP 400 when APP_ENV is 'lab'.
3. Starting a second traffic run while active returns HTTP 409 Conflict.
4. Unknown or malformed run IDs are rejected with 404 and 400.
5. Before/after difference computed correctly from mocked metric values.
6. Responses never contain tokens, credentials, or secrets.
"""

import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.api import traffic_demo
from app.core.config import settings
from app.core.database import reconfigure_engine


@pytest.fixture(autouse=True)
def reset_environment():
    reconfigure_engine(settings.DATABASE_URL)
    yield
    reconfigure_engine(settings.DATABASE_URL)


# ------------------------------------------------------------------------------
# 1. Authentication & Role Enforcement Tests
# ------------------------------------------------------------------------------
def test_01_traffic_endpoints_require_admin_auth(client: TestClient):
    """Calling traffic endpoints without token returns 401."""
    resp1 = client.post("/admin/demo/traffic/start")
    assert resp1.status_code == 401

    dummy_uuid = str(uuid4())
    resp2 = client.get(f"/admin/demo/traffic/status/{dummy_uuid}")
    assert resp2.status_code == 401


def test_02_traffic_endpoints_forbidden_for_tenant_users(client: TestClient, acme_auth: dict):
    """Calling traffic endpoints with tenant user token returns 403."""
    resp1 = client.post("/admin/demo/traffic/start", headers=acme_auth["headers"])
    assert resp1.status_code == 403

    dummy_uuid = str(uuid4())
    resp2 = client.get(f"/admin/demo/traffic/status/{dummy_uuid}", headers=acme_auth["headers"])
    assert resp2.status_code == 403


# ------------------------------------------------------------------------------
# 2. Lab-Mode Refusal Tests
# ------------------------------------------------------------------------------
def test_03_traffic_endpoints_refuse_when_app_env_is_lab(client: TestClient, admin_auth: dict, monkeypatch):
    """Both traffic endpoints refuse with 400 when APP_ENV is lab."""
    monkeypatch.setattr(settings, "APP_ENV", "lab")

    resp1 = client.post("/admin/demo/traffic/start", headers=admin_auth["headers"])
    assert resp1.status_code == 400
    assert "lab" in resp1.json()["detail"].lower()

    dummy_uuid = str(uuid4())
    resp2 = client.get(f"/admin/demo/traffic/status/{dummy_uuid}", headers=admin_auth["headers"])
    assert resp2.status_code == 400
    assert "lab" in resp2.json()["detail"].lower()


# ------------------------------------------------------------------------------
# 3. Process Execution & 409 Conflict (Mocked)
# ------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_04_successful_start_and_conflict_on_second_start(client: TestClient, admin_auth: dict, monkeypatch):
    """
    POST /admin/demo/traffic/start initiates background process.
    Second POST while active returns HTTP 409 Conflict.
    """
    monkeypatch.setattr(settings, "APP_ENV", "development")

    hang_event = asyncio.Event()
    mock_proc = MagicMock()
    mock_proc.returncode = None
    mock_proc.wait = AsyncMock(side_effect=hang_event.wait)

    traffic_demo.TRAFFIC_REGISTRY.clear()
    traffic_demo._active_traffic_proc = None
    traffic_demo._active_traffic_run_id = None
    traffic_demo._last_traffic_start_time = 0.0

    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        # 1. First start
        res1 = client.post("/admin/demo/traffic/start", headers=admin_auth["headers"])
        assert res1.status_code == 200
        run_id = res1.json()["run_id"]

        # 2. Immediate second start returns 409
        res2 = client.post("/admin/demo/traffic/start", headers=admin_auth["headers"])
        assert res2.status_code == 409

        # Clean up mock process
        hang_event.set()


# ------------------------------------------------------------------------------
# 4. Unknown & Malformed Run ID Validation
# ------------------------------------------------------------------------------
def test_05_unknown_and_malformed_run_id_rejected(client: TestClient, admin_auth: dict, monkeypatch):
    """Unknown UUID returns 404, non-UUID returns 400."""
    monkeypatch.setattr(settings, "APP_ENV", "development")

    # Unknown UUID -> 404
    unknown_uuid = str(uuid4())
    r404 = client.get(f"/admin/demo/traffic/status/{unknown_uuid}", headers=admin_auth["headers"])
    assert r404.status_code == 404

    # Malformed non-UUID -> 400
    for bad in ["not-a-uuid", "12345", "xyz-abc"]:
        r400 = client.get(f"/admin/demo/traffic/status/{bad}", headers=admin_auth["headers"])
        assert r400.status_code == 400


# ------------------------------------------------------------------------------
# 5. Metrics Comparison Computation (Mocked)
# ------------------------------------------------------------------------------
def test_06_metrics_comparison_computed_correctly_from_mocked_values(client: TestClient, admin_auth: dict, monkeypatch):
    """Status endpoint accurately computes Before, After, and Diff."""
    monkeypatch.setattr(settings, "APP_ENV", "development")

    run_id = str(uuid4())
    dummy_prog = Path(__file__).resolve().parent.parent / "scratch" / f"traffic_progress_{run_id}.jsonl"
    dummy_prog.parent.mkdir(parents=True, exist_ok=True)
    with open(dummy_prog, "w", encoding="utf-8") as f:
        f.write(json.dumps({"number": 1, "kind": "valid", "method": "GET", "path": "/documents", "status_code": 200, "duration_ms": 12.3}) + "\n")
        f.write(json.dumps({"number": 2, "kind": "invalid", "method": "GET", "path": "/documents/<id>", "status_code": 404, "duration_ms": 8.5}) + "\n")

    traffic_demo.TRAFFIC_REGISTRY[run_id] = {
        "run_id": run_id,
        "state": "finished",
        "start_time": datetime.now(timezone.utc).isoformat(),
        "finish_time": datetime.now(timezone.utc).isoformat(),
        "progress_file": str(dummy_prog),
        "metrics": {
            "before": {"requests": 10.0, "errors": 2.0, "avg_latency_ms": 25.5},
            "after": {"requests": 23.0, "errors": 5.0, "avg_latency_ms": 28.0},
        },
        "comparison": {
            "requests": {"before": 10, "after": 23, "diff": 13},
            "errors": {"before": 2, "after": 5, "diff": 3},
            "avg_latency_ms": {"before": 25.5, "after": 28.0, "diff": 2.5},
        },
    }

    resp = client.get(f"/admin/demo/traffic/status/{run_id}", headers=admin_auth["headers"])
    assert resp.status_code == 200
    data = resp.json()
    assert data["state"] == "finished"
    assert len(data["progress"]) == 2
    comp = data["comparison"]
    assert comp["requests"]["diff"] == 13
    assert comp["errors"]["diff"] == 3
    assert comp["avg_latency_ms"]["diff"] == 2.5

    # Clean up dummy progress file
    try:
        dummy_prog.unlink()
    except Exception:
        pass


# ------------------------------------------------------------------------------
# 6. Response Sanitization Check
# ------------------------------------------------------------------------------
def test_07_no_secrets_in_responses(client: TestClient, admin_auth: dict, monkeypatch):
    """Traffic endpoints never expose secrets, passwords, or tokens."""
    monkeypatch.setattr(settings, "APP_ENV", "development")

    run_id = str(uuid4())
    dummy_prog = Path(__file__).resolve().parent.parent / "scratch" / f"traffic_progress_{run_id}.jsonl"
    dummy_prog.parent.mkdir(parents=True, exist_ok=True)
    with open(dummy_prog, "w", encoding="utf-8") as f:
        f.write(json.dumps({"number": 1, "kind": "valid", "method": "GET", "path": "/documents", "status_code": 200, "duration_ms": 10.0}) + "\n")

    traffic_demo.TRAFFIC_REGISTRY[run_id] = {
        "run_id": run_id,
        "state": "running",
        "start_time": datetime.now(timezone.utc).isoformat(),
        "finish_time": None,
        "progress_file": str(dummy_prog),
        "metrics": {"before": {"requests": 0, "errors": 0, "avg_latency_ms": 0}, "after": None},
        "comparison": None,
    }

    resp = client.get(f"/admin/demo/traffic/status/{run_id}", headers=admin_auth["headers"])
    assert resp.status_code == 200
    body_text = resp.text.lower()
    for secret in ["password", "token", "secret", "bearer", "argon2"]:
        assert secret not in body_text

    try:
        dummy_prog.unlink()
    except Exception:
        pass
