"""
TenantShield - Part 5 Single Attack Demo Test Suite
====================================================
Verifies:
1. Endpoints require platform_admin role (401 unauthenticated, 403 tenant users).
2. Endpoints refuse with HTTP 400 when APP_ENV is 'lab'.
3. Input validation:
   - Attacker and victim must be in ["Acme", "Beta", "Demo Co"].
   - Attacker and victim must not be the same.
   - Action must be in ["read", "update", "delete", "create-into-victim"].
4. Starting a second attack run while active returns HTTP 409 Conflict.
5. Unknown or malformed run IDs return 404 and 400.
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

from app.api import attack_demo
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
def test_01_attack_endpoints_require_admin_auth(client: TestClient):
    """Calling attack endpoints without token returns 401."""
    resp1 = client.post("/admin/demo/attack/start", json={"attacker": "Acme", "victim": "Beta", "action": "read"})
    assert resp1.status_code == 401

    dummy_uuid = str(uuid4())
    resp2 = client.get(f"/admin/demo/attack/status/{dummy_uuid}")
    assert resp2.status_code == 401


def test_02_attack_endpoints_forbidden_for_tenant_users(client: TestClient, acme_auth: dict):
    """Calling attack endpoints with tenant user token returns 403."""
    resp1 = client.post(
        "/admin/demo/attack/start",
        json={"attacker": "Acme", "victim": "Beta", "action": "read"},
        headers=acme_auth["headers"],
    )
    assert resp1.status_code == 403

    dummy_uuid = str(uuid4())
    resp2 = client.get(f"/admin/demo/attack/status/{dummy_uuid}", headers=acme_auth["headers"])
    assert resp2.status_code == 403


# ------------------------------------------------------------------------------
# 2. Lab-Mode Refusal Tests
# ------------------------------------------------------------------------------
def test_03_attack_endpoints_refuse_when_app_env_is_lab(client: TestClient, admin_auth: dict, monkeypatch):
    """Both attack endpoints refuse with 400 when APP_ENV is lab."""
    monkeypatch.setattr(settings, "APP_ENV", "lab")

    resp1 = client.post(
        "/admin/demo/attack/start",
        json={"attacker": "Acme", "victim": "Beta", "action": "read"},
        headers=admin_auth["headers"],
    )
    assert resp1.status_code == 400
    assert "lab" in resp1.json()["detail"].lower()

    dummy_uuid = str(uuid4())
    resp2 = client.get(f"/admin/demo/attack/status/{dummy_uuid}", headers=admin_auth["headers"])
    assert resp2.status_code == 400
    assert "lab" in resp2.json()["detail"].lower()


# ------------------------------------------------------------------------------
# 3. Input Validation Tests
# ------------------------------------------------------------------------------
def test_04_attack_input_validation(client: TestClient, admin_auth: dict, monkeypatch):
    """Refuses invalid tenants, identical attacker/victim, or invalid actions."""
    monkeypatch.setattr(settings, "APP_ENV", "development")

    # Invalid attacker
    r1 = client.post(
        "/admin/demo/attack/start",
        json={"attacker": "UnknownCorp", "victim": "Beta", "action": "read"},
        headers=admin_auth["headers"],
    )
    assert r1.status_code == 400
    assert "attacker" in r1.json()["detail"].lower()

    # Invalid victim
    r2 = client.post(
        "/admin/demo/attack/start",
        json={"attacker": "Acme", "victim": "UnknownCorp", "action": "read"},
        headers=admin_auth["headers"],
    )
    assert r2.status_code == 400
    assert "victim" in r2.json()["detail"].lower()

    # Attacker == Victim
    r3 = client.post(
        "/admin/demo/attack/start",
        json={"attacker": "Acme", "victim": "Acme", "action": "read"},
        headers=admin_auth["headers"],
    )
    assert r3.status_code == 400
    assert "different" in r3.json()["detail"].lower()

    # Invalid action
    r4 = client.post(
        "/admin/demo/attack/start",
        json={"attacker": "Acme", "victim": "Beta", "action": "drop_tables"},
        headers=admin_auth["headers"],
    )
    assert r4.status_code == 400
    assert "action" in r4.json()["detail"].lower()


# ------------------------------------------------------------------------------
# 4. Process Execution & 409 Conflict (Mocked)
# ------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_05_successful_start_and_conflict_on_second_start(client: TestClient, admin_auth: dict, monkeypatch):
    """
    POST /admin/demo/attack/start initiates background process.
    Second POST while active returns HTTP 409 Conflict.
    """
    monkeypatch.setattr(settings, "APP_ENV", "development")

    hang_event = asyncio.Event()
    mock_proc = MagicMock()
    mock_proc.returncode = None
    mock_proc.wait = AsyncMock(side_effect=hang_event.wait)

    attack_demo.ATTACK_REGISTRY.clear()
    attack_demo._active_attack_proc = None
    attack_demo._active_attack_run_id = None
    attack_demo._last_attack_start_time = 0.0

    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        # 1. First start
        res1 = client.post(
            "/admin/demo/attack/start",
            json={"attacker": "Acme", "victim": "Beta", "action": "read"},
            headers=admin_auth["headers"],
        )
        assert res1.status_code == 200
        run_id = res1.json()["run_id"]
        assert res1.json()["state"] == "running"

        # 2. Immediate second start returns 409
        res2 = client.post(
            "/admin/demo/attack/start",
            json={"attacker": "Demo Co", "victim": "Beta", "action": "read"},
            headers=admin_auth["headers"],
        )
        assert res2.status_code == 409

        # Clean up mock process
        hang_event.set()


# ------------------------------------------------------------------------------
# 5. Unknown & Malformed Run ID Validation
# ------------------------------------------------------------------------------
def test_06_unknown_and_malformed_run_id_rejected(client: TestClient, admin_auth: dict, monkeypatch):
    """Unknown UUID returns 404, non-UUID returns 400."""
    monkeypatch.setattr(settings, "APP_ENV", "development")

    # Unknown UUID -> 404
    unknown_uuid = str(uuid4())
    r404 = client.get(f"/admin/demo/attack/status/{unknown_uuid}", headers=admin_auth["headers"])
    assert r404.status_code == 404

    # Malformed non-UUID -> 400
    r400 = client.get("/admin/demo/attack/status/not-a-valid-uuid", headers=admin_auth["headers"])
    assert r400.status_code == 400


# ------------------------------------------------------------------------------
# 6. Status Response & No Secrets Exposure
# ------------------------------------------------------------------------------
def test_07_status_output_contains_no_secrets(client: TestClient, admin_auth: dict, monkeypatch, tmp_path):
    """Status endpoint correctly returns progress and sanitized result without secrets."""
    monkeypatch.setattr(settings, "APP_ENV", "development")

    run_id = str(uuid4())
    progress_file = tmp_path / f"attack_prog_{run_id}.jsonl"
    with open(progress_file, "w", encoding="utf-8") as f:
        f.write(json.dumps({"step": 1, "total": 6, "message": "Authenticating..."}) + "\n")
        f.write(json.dumps({"step": 2, "total": 6, "message": "Planting canary..."}) + "\n")

    output_file = tmp_path / f"attack_out_{run_id}.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(
            {
                "request": {"method": "GET", "path": "/documents/test-doc-id"},
                "status_code": 404,
                "outcome": "BLOCKED",
                "blocking_control": "unknown",
                "victim_doc_state": "INTACT",
                "explanation": "Cross-tenant read attack was blocked with HTTP 404.",
            },
            f,
        )

    attack_demo.ATTACK_REGISTRY[run_id] = {
        "run_id": run_id,
        "state": "finished",
        "start_time": datetime.now(timezone.utc).isoformat(),
        "finish_time": datetime.now(timezone.utc).isoformat(),
        "attacker": "Acme",
        "victim": "Beta",
        "action": "read",
        "progress_file": str(progress_file),
        "output_file": str(output_file),
        "result": {
            "request": {"method": "GET", "path": "/documents/test-doc-id"},
            "status_code": 404,
            "outcome": "BLOCKED",
            "blocking_control": "unknown",
            "victim_doc_state": "INTACT",
            "explanation": "Cross-tenant read attack was blocked with HTTP 404.",
        },
    }

    resp = client.get(f"/admin/demo/attack/status/{run_id}", headers=admin_auth["headers"])
    assert resp.status_code == 200
    data = resp.json()

    assert data["state"] == "finished"
    assert len(data["progress"]) == 2
    assert data["result"]["outcome"] == "BLOCKED"
    assert data["result"]["status_code"] == 404

    # Strict check: No sensitive keywords or secrets in JSON
    raw_text = resp.text.lower()
    for forbidden in ["password", "token", "secret", "bearer", "private_key"]:
        assert forbidden not in raw_text, f"Forbidden keyword '{forbidden}' leaked in response."
