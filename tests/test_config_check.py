"""
TenantShield - Part 6 Configuration Check Test Suite
=====================================================
Verifies:
1. Endpoint requires platform_admin role (401 unauthenticated, 403 tenant users).
2. Endpoint refuses with HTTP 400 when APP_ENV is 'lab'.
3. Successful call returns expected fields (overall_status, checks list, etc.).
4. Each check entry contains name, status (PASS/FAIL), and detail fields.
5. Responses never contain tokens, passwords, or key material.
6. RLS check correctly identifies documents table RLS state (mocked db query).
"""

import pytest
from fastapi.testclient import TestClient

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
def test_01_config_check_requires_admin_auth(client: TestClient):
    """Calling config-check without token returns 401."""
    resp = client.get("/admin/dashboard/config-check")
    assert resp.status_code == 401


def test_02_config_check_forbidden_for_tenant_users(client: TestClient, acme_auth: dict):
    """Calling config-check with tenant user token returns 403."""
    resp = client.get("/admin/dashboard/config-check", headers=acme_auth["headers"])
    assert resp.status_code == 403


# ------------------------------------------------------------------------------
# 2. Lab-Mode Refusal Tests
# ------------------------------------------------------------------------------
def test_03_config_check_refuses_in_lab_mode(client: TestClient, admin_auth: dict, monkeypatch):
    """Config-check refuses with 400 when APP_ENV is lab."""
    monkeypatch.setattr(settings, "APP_ENV", "lab")

    resp = client.get("/admin/dashboard/config-check", headers=admin_auth["headers"])
    assert resp.status_code == 400
    assert "lab" in resp.json()["detail"].lower()


# ------------------------------------------------------------------------------
# 3. Successful Response Structure Tests
# ------------------------------------------------------------------------------
def test_04_config_check_returns_expected_structure(client: TestClient, admin_auth: dict, monkeypatch):
    """Config-check returns a well-formed response with required fields."""
    monkeypatch.setattr(settings, "APP_ENV", "development")

    resp = client.get("/admin/dashboard/config-check", headers=admin_auth["headers"])
    assert resp.status_code == 200

    data = resp.json()
    # Top-level fields
    assert "overall_status" in data
    assert data["overall_status"] in ("PASS", "FAIL")
    assert "total_checks" in data
    assert "passed" in data
    assert "failed" in data
    assert "checks" in data
    assert isinstance(data["checks"], list)
    assert len(data["checks"]) > 0
    assert data["total_checks"] == len(data["checks"])
    assert data["passed"] + data["failed"] == data["total_checks"]


def test_05_config_check_entries_have_required_fields(client: TestClient, admin_auth: dict, monkeypatch):
    """Each check entry has name, status, detail, and recommendation fields."""
    monkeypatch.setattr(settings, "APP_ENV", "development")

    resp = client.get("/admin/dashboard/config-check", headers=admin_auth["headers"])
    assert resp.status_code == 200

    data = resp.json()
    for check in data["checks"]:
        assert "name" in check, f"Check missing 'name': {check}"
        assert "status" in check, f"Check missing 'status': {check}"
        assert check["status"] in ("PASS", "FAIL"), f"Status not PASS/FAIL: {check}"
        assert "detail" in check, f"Check missing 'detail': {check}"
        assert "recommendation" in check, f"Check missing 'recommendation': {check}"
        # PASS checks should have empty recommendation
        if check["status"] == "PASS":
            assert check["recommendation"] == "", f"PASS check should have empty recommendation: {check}"


def test_06_config_check_includes_security_control_flags(client: TestClient, admin_auth: dict, monkeypatch):
    """Config-check verifies Layer A, B, C control flags."""
    monkeypatch.setattr(settings, "APP_ENV", "development")

    resp = client.get("/admin/dashboard/config-check", headers=admin_auth["headers"])
    assert resp.status_code == 200
    data = resp.json()

    names = [c["name"] for c in data["checks"]]
    assert any("Layer A" in n or "ownership" in n.lower() for n in names), "Missing Layer A check"
    assert any("Layer B" in n or "rls" in n.lower() or "db rls" in n.lower() for n in names), "Missing Layer B check"
    assert any("Layer C" in n or "query" in n.lower() for n in names), "Missing Layer C check"


def test_07_config_check_includes_rls_database_check(client: TestClient, admin_auth: dict, monkeypatch):
    """Config-check includes a check for RLS on the documents table."""
    monkeypatch.setattr(settings, "APP_ENV", "development")

    resp = client.get("/admin/dashboard/config-check", headers=admin_auth["headers"])
    assert resp.status_code == 200
    data = resp.json()

    rls_check = next((c for c in data["checks"] if "RLS" in c["name"] and "documents" in c["name"]), None)
    assert rls_check is not None, "Missing RLS-on-documents check"
    # In the test DB, RLS should be enabled so check should PASS
    assert rls_check["status"] == "PASS"


def test_08_config_check_includes_app_role_check(client: TestClient, admin_auth: dict, monkeypatch):
    """Config-check verifies app role does not have elevated privileges."""
    monkeypatch.setattr(settings, "APP_ENV", "development")

    resp = client.get("/admin/dashboard/config-check", headers=admin_auth["headers"])
    assert resp.status_code == 200
    data = resp.json()

    role_check = next((c for c in data["checks"] if "privilege" in c["name"].lower() or "role" in c["name"].lower()), None)
    assert role_check is not None, "Missing app role privileges check"
    assert role_check["status"] == "PASS", f"App role has elevated privileges: {role_check['detail']}"


# ------------------------------------------------------------------------------
# 4. Security - No Secrets in Response
# ------------------------------------------------------------------------------
def test_09_config_check_never_exposes_secrets(client: TestClient, admin_auth: dict, monkeypatch):
    """Ensure config-check response never exposes credentials, tokens, or key material."""
    monkeypatch.setattr(settings, "APP_ENV", "development")

    resp = client.get("/admin/dashboard/config-check", headers=admin_auth["headers"])
    assert resp.status_code == 200

    raw_text = resp.text.lower()
    for forbidden in ["password", "change_this", "wrapped_dek", "private_key", "eyj"]:
        assert forbidden not in raw_text, f"Forbidden keyword '{forbidden}' leaked in config-check response."


# ------------------------------------------------------------------------------
# 5. Degraded state: security controls disabled
# ------------------------------------------------------------------------------
def test_10_config_check_detects_disabled_layer_a(client: TestClient, admin_auth: dict, monkeypatch):
    """Config-check returns FAIL for Layer A when ENABLE_APP_OWNERSHIP_CHECK is off (in lab mode monkeypatched)."""
    # We monkeypatch APP_ENV to development but disable the flag via Settings attribute
    monkeypatch.setattr(settings, "APP_ENV", "development")
    monkeypatch.setattr(settings, "ENABLE_APP_OWNERSHIP_CHECK", False)

    resp = client.get("/admin/dashboard/config-check", headers=admin_auth["headers"])
    assert resp.status_code == 200
    data = resp.json()

    layer_a_check = next((c for c in data["checks"] if "Layer A" in c["name"] or "ownership" in c["name"].lower()), None)
    assert layer_a_check is not None
    assert layer_a_check["status"] == "FAIL"
    assert layer_a_check["recommendation"] != ""
