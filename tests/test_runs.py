"""
TenantShield - Part 2 Verification Runs API Test Suite
======================================================
Verifies:
1. POST /admin/dashboard/run-verification returns 401 without token, 403 for tenant users.
2. GET /admin/dashboard/run-status/{run_id} returns 401 without token, 403 for tenant users.
3. Both endpoints refuse with HTTP 400 when APP_ENV is 'lab'.
4. POST starts verification (mocked process), returning a valid UUID run_id.
5. A second POST while a run is active returns HTTP 409 Conflict.
6. Unknown UUID returns HTTP 404 Not Found.
7. Malformed / invalid UUID returns HTTP 400 Bad Request.
8. Status response contains no secrets, tokens, canary strings, or passwords.
9. GET /admin/dashboard/verification prefers a BASELINE report over a newer report without run_type.
"""

import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import time
from unittest.mock import AsyncMock, MagicMock, patch
import uuid

import pytest
from fastapi.testclient import TestClient

from app.api import dashboard, runs
from app.core.config import settings


from app.core.database import reconfigure_engine


@pytest.fixture(autouse=True)
def reset_db_engine_to_default():
    """Ensure engine is connected to standard DATABASE_URL, restoring from any prior test mutation."""
    reconfigure_engine(settings.DATABASE_URL)
    yield
    reconfigure_engine(settings.DATABASE_URL)


# ------------------------------------------------------------------------------
# 1. Authentication & Role Enforcement Tests
# ------------------------------------------------------------------------------
def test_01_run_verification_endpoints_require_authentication(client: TestClient):
    """Calling run-verification endpoints without token returns 401."""
    resp1 = client.post("/admin/dashboard/run-verification")
    assert resp1.status_code == 401

    dummy_uuid = str(uuid.uuid4())
    resp2 = client.get(f"/admin/dashboard/run-status/{dummy_uuid}")
    assert resp2.status_code == 401


def test_02_run_verification_endpoints_forbidden_for_tenant_users(client: TestClient, acme_auth: dict):
    """Calling run-verification endpoints with tenant user token returns 403."""
    resp1 = client.post("/admin/dashboard/run-verification", headers=acme_auth["headers"])
    assert resp1.status_code == 403, f"Expected 403, got {resp1.status_code}: {resp1.text}"

    dummy_uuid = str(uuid.uuid4())
    resp2 = client.get(f"/admin/dashboard/run-status/{dummy_uuid}", headers=acme_auth["headers"])
    assert resp2.status_code == 403, f"Expected 403, got {resp2.status_code}: {resp2.text}"


# ------------------------------------------------------------------------------
# 2. Lab-Mode Refusal Tests
# ------------------------------------------------------------------------------
def test_03_run_verification_refuses_when_app_env_is_lab(client: TestClient, admin_auth: dict, monkeypatch):
    """Both run-verification and run-status refuse with 400 when APP_ENV is lab."""
    monkeypatch.setattr(settings, "APP_ENV", "lab")

    resp1 = client.post("/admin/dashboard/run-verification", headers=admin_auth["headers"])
    assert resp1.status_code == 400, f"Expected 400, got {resp1.status_code}: {resp1.text}"
    assert "lab" in resp1.json()["detail"].lower()

    dummy_uuid = str(uuid.uuid4())
    resp2 = client.get(f"/admin/dashboard/run-status/{dummy_uuid}", headers=admin_auth["headers"])
    assert resp2.status_code == 400
    assert "lab" in resp2.json()["detail"].lower()


# ------------------------------------------------------------------------------
# 3. Process Execution & 409 Conflict Tests (Mocked)
# ------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_04_successful_start_and_conflict_on_second_start(client: TestClient, admin_auth: dict, monkeypatch):
    """
    POST /admin/dashboard/run-verification starts a process and returns a UUID.
    A second POST while active returns HTTP 409 Conflict.
    """
    monkeypatch.setattr(settings, "APP_ENV", "development")

    # Create a mock process that is still running (hangs on wait until released)
    hang_event = asyncio.Event()
    mock_proc = MagicMock()
    mock_proc.returncode = None
    mock_proc.wait = AsyncMock(side_effect=hang_event.wait)

    # Reset module state
    runs.RUNS_REGISTRY.clear()
    runs._active_process = None
    runs._active_run_id = None
    runs._last_start_timestamp = 0.0

    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        # 1. First start
        res1 = client.post("/admin/dashboard/run-verification", headers=admin_auth["headers"])
        assert res1.status_code == 200
        data1 = res1.json()
        assert "run_id" in data1
        run_id = data1["run_id"]
        # Verify valid UUID
        val_uuid = uuid.UUID(run_id)
        assert str(val_uuid) == run_id
        assert data1["state"] == "running"

        # 2. Second start while active process is running
        res2 = client.post("/admin/dashboard/run-verification", headers=admin_auth["headers"])
        assert res2.status_code == 409
        assert "in progress" in res2.json()["detail"].lower()

    # Clean up mock process
    hang_event.set()
    runs._active_process = None
    runs._active_run_id = None


# ------------------------------------------------------------------------------
# 4. Status Validation & Input Validation Tests
# ------------------------------------------------------------------------------
def test_05_unknown_run_id_rejected(client: TestClient, admin_auth: dict, monkeypatch):
    """Querying an unknown valid UUID returns 404."""
    monkeypatch.setattr(settings, "APP_ENV", "development")
    unknown_uuid = str(uuid.uuid4())
    resp = client.get(f"/admin/dashboard/run-status/{unknown_uuid}", headers=admin_auth["headers"])
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_06_malformed_run_id_rejected(client: TestClient, admin_auth: dict, monkeypatch):
    """Querying a malformed non-UUID run ID is rejected with 400 Bad Request."""
    monkeypatch.setattr(settings, "APP_ENV", "development")
    bad_ids = ["not-a-uuid", "12345", "00000000-0000-0000-0000-notauuid", "xyz-123-abc"]
    for bad in bad_ids:
        resp = client.get(f"/admin/dashboard/run-status/{bad}", headers=admin_auth["headers"])
        assert resp.status_code == 400
        assert "invalid" in resp.json()["detail"].lower()


# ------------------------------------------------------------------------------
# 5. Secret Sanitization & Result Formatting
# ------------------------------------------------------------------------------
def test_07_status_response_contains_no_secrets_or_canaries(client: TestClient, admin_auth: dict, monkeypatch):
    """Status endpoint never returns secrets, tokens, passwords, or canary strings."""
    monkeypatch.setattr(settings, "APP_ENV", "development")

    test_run_id = str(uuid.uuid4())
    runs.RUNS_REGISTRY[test_run_id] = {
        "run_id": test_run_id,
        "state": "finished",
        "start_time": datetime.now(timezone.utc).isoformat(),
        "finish_time": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_attacks_run": 11,
            "blocked_attacks": 11,
            "leaked_attacks": 0,
            "inconclusive_attacks": 0,
            "overall_verdict": "PASS",
            "canary_token": "canary_secret_12345",  # should be sanitized
        },
        "attacks": [
            {"method": "GET", "target_path": "/documents/test", "status_code": 404, "outcome": "BLOCKED"}
        ]
    }

    resp = client.get(f"/admin/dashboard/run-status/{test_run_id}", headers=admin_auth["headers"])
    assert resp.status_code == 200
    text_data = resp.text
    assert "canary_secret" not in text_data
    assert "password" not in text_data
    assert "eyJ" not in text_data


# ------------------------------------------------------------------------------
# 6. Baseline Report Selection Tests
# ------------------------------------------------------------------------------
def test_08_verification_section_prefers_baseline_report_over_newer_unknown_report(
    client: TestClient, admin_auth: dict, tmp_path: Path, monkeypatch
):
    """
    The Latest verification section shows only the newest BASELINE report.
    Reports without run_type are UNKNOWN and ignored, even if newer.
    If none exists, returns empty state with python scripts/run_verifier.py.
    """
    monkeypatch.setattr(settings, "APP_ENV", "development")
    test_dir = tmp_path / "results_baseline_test"
    test_dir.mkdir()
    monkeypatch.setattr(dashboard, "RESULTS_DIR", test_dir)

    # 1. Older report WITH run_type BASELINE
    baseline_file = test_dir / "verification_attack_report_20261017_100000.json"
    baseline_file.write_text(json.dumps({
        "generated_at_utc": "2026-10-17T10:00:00Z",
        "run_type": "BASELINE",
        "summary": {
            "run_type": "BASELINE",
            "total_attacks_run": 11,
            "blocked_attacks": 11,
            "leaked_attacks": 0,
            "inconclusive_attacks": 0,
            "tenant_b_canary_integrity": "INTACT",
            "list_leak_check": "PASSED",
            "overall_verdict": "PASS",
        },
        "attack_results": []
    }), encoding="utf-8")

    # 2. Newer report WITHOUT run_type (treated as UNKNOWN)
    unknown_file = test_dir / "verification_attack_report_20261017_200000.json"
    unknown_file.write_text(json.dumps({
        "generated_at_utc": "2026-10-17T20:00:00Z",
        "summary": {
            "total_attacks_run": 99,
            "overall_verdict": "UNKNOWN_FAIL",
        },
        "attack_results": []
    }), encoding="utf-8")

    # Ensure mtime reflects unknown_file is newer
    import os
    os.utime(baseline_file, (1000, 1000))
    os.utime(unknown_file, (2000, 2000))

    resp = client.get("/admin/dashboard/verification", headers=admin_auth["headers"])
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] != "empty"
    # Must show the older BASELINE file, NOT the newer UNKNOWN file
    assert data["summary"]["generated_at_utc"] == "2026-10-17T10:00:00Z"
    assert data["summary"]["total_attacks_run"] == 11
    assert data["summary"]["overall_verdict"] == "PASS"

    # 3. If ONLY unknown report exists, returns empty state
    baseline_file.unlink()
    resp_empty = client.get("/admin/dashboard/verification", headers=admin_auth["headers"])
    assert resp_empty.status_code == 200
    data_empty = resp_empty.json()
    assert data_empty["status"] == "empty"
    assert "python scripts/run_verifier.py" in data_empty["message"]


def test_09_run_verification_supports_mode_parameter(client: TestClient, admin_auth: dict, monkeypatch):
    """
    Validates that /admin/dashboard/run-verification accepts valid modes:
    1. ?mode=vulnerable_only passes cleanly to background process.
    2. ?mode=invalid_mode returns 422 Unprocessable Entity.
    """
    from unittest.mock import patch, MagicMock, AsyncMock
    from app.api import runs

    monkeypatch.setattr(settings, "APP_ENV", "development")

    # Reset module state
    runs.RUNS_REGISTRY.clear()
    runs._active_process = None
    runs._active_run_id = None
    runs._last_start_timestamp = 0.0

    mock_proc = MagicMock()
    mock_proc.returncode = None
    mock_proc.wait = AsyncMock(return_value=0)

    # 1. Invalid mode is rejected
    res_bad = client.post("/admin/dashboard/run-verification?mode=invalid_mode", headers=admin_auth["headers"])
    assert res_bad.status_code == 422

    # 2. Valid mode is accepted and command includes --mode
    with patch("asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec:
        res_ok = client.post("/admin/dashboard/run-verification?mode=vulnerable_only", headers=admin_auth["headers"])
        assert res_ok.status_code == 200
        assert res_ok.json()["state"] == "running"
        assert mock_exec.called
        call_args = mock_exec.call_args[0]
        assert "--mode" in call_args
        mode_idx = call_args.index("--mode")
        assert call_args[mode_idx + 1] == "vulnerable_only"

    runs._active_process = None
    runs._active_run_id = None

