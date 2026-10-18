"""
TenantShield - Part 3 Key Lifecycle Demo Test Suite
===================================================
Verifies:
1. All demo endpoints require platform_admin role (401 unauthenticated, 403 tenant users).
2. All demo endpoints refuse with HTTP 400 when APP_ENV is 'lab'.
3. Client attempts to specify tenant parameters are rejected with HTTP 400.
4. Key rotation preserves readability of old documents and stamps new ones with N+1.
5. Crypto-shredding requires exact 'DESTROY' confirmation string.
6. Post-shredding reads return FAILED_SAFELY with zero leaked content or key material.
7. Other tenants (Acme) remain completely unaffected by Demo Co key destruction.
8. Application database role permissions remain strictly unprivileged.
"""

import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.core.config import settings
from app.core.database import AsyncSessionLocal, reconfigure_engine
from scripts.seed_demo_tenant import seed_demo_tenant


@pytest.fixture(autouse=True)
def ensure_clean_environment():
    """Ensure engine is connected to standard DATABASE_URL and Demo Co is seeded."""
    reconfigure_engine(settings.DATABASE_URL)
    # Ensure Demo Co is initialized
    try:
        seed_demo_tenant()
    except Exception:
        pass
    yield
    reconfigure_engine(settings.DATABASE_URL)


# ------------------------------------------------------------------------------
# 1. Authentication & Role Enforcement Tests
# ------------------------------------------------------------------------------
def test_01_demo_endpoints_require_authentication(client: TestClient):
    """Calling demo endpoints without token returns 401."""
    endpoints = [
        ("POST", "/admin/demo/keys/create-document", {"label": "before"}),
        ("POST", "/admin/demo/keys/rotate", None),
        ("POST", "/admin/demo/keys/read", None),
        ("POST", "/admin/demo/keys/destroy", {"confirm": "DESTROY"}),
        ("POST", "/admin/demo/keys/read-other", None),
        ("GET", "/admin/demo/keys/state", None),
    ]

    for method, path, body in endpoints:
        if method == "POST":
            resp = client.post(path, json=body) if body else client.post(path)
        else:
            resp = client.get(path)
        assert resp.status_code == 401, f"{path} expected 401, got {resp.status_code}"


def test_02_demo_endpoints_forbidden_for_tenant_users(client: TestClient, acme_auth: dict):
    """Calling demo endpoints with tenant user token returns 403."""
    endpoints = [
        ("POST", "/admin/demo/keys/create-document", {"label": "before"}),
        ("POST", "/admin/demo/keys/rotate", None),
        ("POST", "/admin/demo/keys/read", None),
        ("POST", "/admin/demo/keys/destroy", {"confirm": "DESTROY"}),
        ("POST", "/admin/demo/keys/read-other", None),
        ("GET", "/admin/demo/keys/state", None),
    ]

    for method, path, body in endpoints:
        if method == "POST":
            resp = client.post(path, json=body, headers=acme_auth["headers"]) if body else client.post(path, headers=acme_auth["headers"])
        else:
            resp = client.get(path, headers=acme_auth["headers"])
        assert resp.status_code == 403, f"{path} expected 403, got {resp.status_code}"


# ------------------------------------------------------------------------------
# 2. Lab-Mode Refusal Tests
# ------------------------------------------------------------------------------
def test_03_demo_endpoints_refuse_when_app_env_is_lab(client: TestClient, admin_auth: dict, monkeypatch):
    """All demo endpoints return 400 Bad Request when APP_ENV is lab."""
    monkeypatch.setattr(settings, "APP_ENV", "lab")

    endpoints = [
        ("POST", "/admin/demo/keys/create-document", {"label": "before"}),
        ("POST", "/admin/demo/keys/rotate", None),
        ("POST", "/admin/demo/keys/read", None),
        ("POST", "/admin/demo/keys/destroy", {"confirm": "DESTROY"}),
        ("POST", "/admin/demo/keys/read-other", None),
        ("GET", "/admin/demo/keys/state", None),
    ]

    for method, path, body in endpoints:
        if method == "POST":
            resp = client.post(path, json=body, headers=admin_auth["headers"]) if body else client.post(path, headers=admin_auth["headers"])
        else:
            resp = client.get(path, headers=admin_auth["headers"])
        assert resp.status_code == 400, f"{path} expected 400 in lab mode, got {resp.status_code}: {resp.text}"
        assert "lab" in resp.json()["detail"].lower()


# ------------------------------------------------------------------------------
# 3. Input Validation & Tenant Parameter Rejection
# ------------------------------------------------------------------------------
def test_04_demo_endpoints_reject_client_specified_tenant_parameters(client: TestClient, admin_auth: dict, monkeypatch):
    """Any client-supplied tenant identifier in query or body is rejected with 400."""
    monkeypatch.setattr(settings, "APP_ENV", "development")

    # Rejected in query parameter
    resp_query = client.post(
        "/admin/demo/keys/create-document?tenant_id=00000000-0000-0000-0000-000000000000",
        headers=admin_auth["headers"],
    )
    assert resp_query.status_code == 400
    assert "prohibited" in resp_query.json()["detail"].lower()

    # Rejected in body
    resp_body = client.post(
        "/admin/demo/keys/create-document",
        json={"label": "before", "tenant_name": "Beta Industries"},
        headers=admin_auth["headers"],
    )
    assert resp_body.status_code == 400
    assert "prohibited" in resp_body.json()["detail"].lower()


# ------------------------------------------------------------------------------
# 4. Key Lifecycle End-to-End: Create, Rotate, Read, Destroy, Read-Other
# ------------------------------------------------------------------------------
def test_05_create_document_and_state(client: TestClient, admin_auth: dict, monkeypatch):
    """POST /admin/demo/keys/create-document creates encrypted document and updates state."""
    monkeypatch.setattr(settings, "APP_ENV", "development")

    # 1. Create 'before' document
    res_create = client.post(
        "/admin/demo/keys/create-document",
        json={"label": "before"},
        headers=admin_auth["headers"],
    )
    assert res_create.status_code == 200
    data = res_create.json()
    assert data["status"] == "created"
    assert "document_id" in data
    assert data["label"] == "before"
    assert isinstance(data["key_version"], int)

    # 2. Check state
    res_state = client.get("/admin/demo/keys/state", headers=admin_auth["headers"])
    assert res_state.status_code == 200
    state_data = res_state.json()
    assert state_data["tenant_name"] == "Demo Co"
    assert len(state_data["keys"]) >= 1
    assert any(d["label"] == "before" for d in state_data["documents"])


def test_06_rotate_key_and_verify_dual_version_reads(client: TestClient, admin_auth: dict, monkeypatch):
    """
    Rotating key provisions version N+1.
    New documents use version N+1.
    Old documents created under version N remain decryptable (OK).
    """
    monkeypatch.setattr(settings, "APP_ENV", "development")

    # 1. Create 'before' doc
    r1 = client.post("/admin/demo/keys/create-document", json={"label": "before"}, headers=admin_auth["headers"])
    assert r1.status_code == 200
    v1 = r1.json()["key_version"]

    # 2. Rotate key
    r2 = client.post("/admin/demo/keys/rotate", headers=admin_auth["headers"])
    assert r2.status_code == 200
    v2 = r2.json()["new_key_version"]
    assert v2 > v1

    # 3. Create 'after' doc
    r3 = client.post("/admin/demo/keys/create-document", json={"label": "after"}, headers=admin_auth["headers"])
    assert r3.status_code == 200
    assert r3.json()["key_version"] == v2

    # 4. Read both documents
    r4 = client.post("/admin/demo/keys/read", headers=admin_auth["headers"])
    assert r4.status_code == 200
    read_data = r4.json()
    docs = read_data["documents"]
    assert len(docs) >= 2

    # Both must decrypt with status OK
    before_docs = [d for d in docs if d["label"] == "before"]
    after_docs = [d for d in docs if d["label"] == "after"]
    assert any(d["status"] == "OK" for d in before_docs)
    assert any(d["status"] == "OK" for d in after_docs)


def test_07_destroy_key_validation_and_failed_safely_reads(client: TestClient, admin_auth: dict, monkeypatch):
    """
    Destroy requires exact confirmation string 'DESTROY'.
    After destroy, reading returns FAILED_SAFELY with zero content or key exposure.
    """
    monkeypatch.setattr(settings, "APP_ENV", "development")

    # 1. Invalid confirmation strings are rejected
    for invalid_confirm in ["destroy", "yes", "CONFIRM", "true", ""]:
        bad_res = client.post(
            "/admin/demo/keys/destroy",
            json={"confirm": invalid_confirm},
            headers=admin_auth["headers"],
        )
        assert bad_res.status_code == 400
        assert "DESTROY" in bad_res.json()["detail"]

    # 2. Destroy key with exact 'DESTROY'
    destroy_res = client.post(
        "/admin/demo/keys/destroy",
        json={"confirm": "DESTROY"},
        headers=admin_auth["headers"],
    )
    assert destroy_res.status_code == 200
    assert destroy_res.json()["status"] == "destroyed"
    assert destroy_res.json()["keys_shredded"] >= 1

    # 3. Read documents: all must report FAILED_SAFELY
    read_res = client.post("/admin/demo/keys/read", headers=admin_auth["headers"])
    assert read_res.status_code == 200
    read_data = read_res.json()
    for doc in read_data["documents"]:
        assert doc["status"] == "FAILED_SAFELY"
        assert "shredded" in doc["reason"].lower() or "not found" in doc["reason"].lower()
        # Verify no content or ciphertext leakage
        assert "content" not in doc
        assert "plaintext" not in doc
        assert "ciphertext" not in doc
        assert "nonce" not in doc


def test_08_read_other_tenant_document_remains_unaffected(client: TestClient, admin_auth: dict, monkeypatch):
    """
    Destroying Demo Co keys has zero impact on Acme Corp's document decryption.
    read-other in Acme context returns OK.
    """
    monkeypatch.setattr(settings, "APP_ENV", "development")

    resp = client.post("/admin/demo/keys/read-other", headers=admin_auth["headers"])
    assert resp.status_code == 200
    data = resp.json()
    assert data["target_tenant"] == "Acme Corp"
    assert data["status"] == "OK"
    assert "content" not in data


# ------------------------------------------------------------------------------
# 5. Database Privileges Security Check
# ------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_09_app_database_role_retains_no_elevated_privileges():
    """
    Ensures that the application role 'tenantshield_app' has NOT been granted
    SUPERUSER, BYPASSRLS, CREATEDB, or CREATEROLE privileges.
    """
    async with AsyncSessionLocal() as session:
        res = await session.execute(
            text(
                "SELECT rolname, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb "
                "FROM pg_roles WHERE rolname = 'tenantshield_app'"
            )
        )
        row = res.fetchone()
        assert row is not None, "Role tenantshield_app must exist"
        assert row.rolsuper is False, "tenantshield_app must NOT be a superuser"
        assert row.rolbypassrls is False, "tenantshield_app must NOT have BYPASSRLS privilege"
        assert row.rolcreaterole is False, "tenantshield_app must NOT be able to create roles"
        assert row.rolcreatedb is False, "tenantshield_app must NOT be able to create databases"
