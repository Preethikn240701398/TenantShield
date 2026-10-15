"""
TenantShield - Level 3 Authentication and Trusted Tenant Context Tests
======================================================================
Verifies:
1. Valid login returns a usable JWT.
2. Incorrect password returns HTTP 401.
3. Missing bearer token is rejected (HTTP 401).
4. Expired JWT is rejected (HTTP 401).
5. Tampered JWT is rejected (HTTP 401).
6. Invalid signature or algorithm is rejected (HTTP 401).
7. Missing required claims are rejected (HTTP 401).
8. Tenant A token cannot obtain Tenant B context via X-Tenant-ID header.
9. Tenant A token cannot obtain Tenant B context via query parameter.
10. Tenant A token cannot override tenant_id during document creation.
11. Database tenant context is derived strictly from verified token.
12. Deleted or disabled users cannot use old tokens.
13. Platform admin authentication works without bypassing document RLS.
"""

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4
import httpx
import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.main import app
from app.services.auth import AuthService


@pytest.fixture(scope="module")
def acme_credentials():
    return {
        "email": settings.DEV_ACME_USER_EMAIL,
        "password": settings.DEV_ACME_USER_PASSWORD,
    }


@pytest.fixture(scope="module")
def beta_credentials():
    return {
        "email": settings.DEV_BETA_USER_EMAIL,
        "password": settings.DEV_BETA_USER_PASSWORD,
    }


@pytest.fixture(scope="module")
def admin_credentials():
    return {
        "email": settings.DEV_ADMIN_USER_EMAIL,
        "password": settings.DEV_ADMIN_USER_PASSWORD,
    }


# ------------------------------------------------------------------------------
# 1. Password-Based Login Tests
# ------------------------------------------------------------------------------

def test_01_valid_login_returns_usable_jwt(client: TestClient, acme_credentials):
    """Test that valid login returns 200 OK and a signed, usable JWT."""
    response = client.post("/auth/login", json=acme_credentials)
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] > 0

    token = data["access_token"]
    # Verify token allows access to protected /auth/me
    me_resp = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_resp.status_code == 200
    user_data = me_resp.json()
    assert user_data["email"] == acme_credentials["email"]
    assert user_data["role"] == "tenant_user"
    assert "tenant_id" in user_data


def test_02_incorrect_password_returns_401(client: TestClient, acme_credentials):
    """Test that incorrect password returns 401 without user enumeration."""
    bad_login = {"email": acme_credentials["email"], "password": "WrongPassword999!"}
    response = client.post("/auth/login", json=bad_login)
    assert response.status_code == 401
    assert "Invalid email or password" in response.json()["detail"]


def test_03_nonexistent_account_returns_401(client: TestClient):
    """Test that non-existent email returns generic 401 without enumeration."""
    bad_login = {"email": "nonexistent_ghost@acme.test", "password": "AnyPassword123!"}
    response = client.post("/auth/login", json=bad_login)
    assert response.status_code == 401
    assert "Invalid email or password" in response.json()["detail"]


# ------------------------------------------------------------------------------
# 2. Token Verification & Security Rejections
# ------------------------------------------------------------------------------

def test_04_missing_bearer_token_is_rejected(client: TestClient):
    """Test that requests lacking Authorization header receive 401."""
    resp_me = client.get("/auth/me")
    assert resp_me.status_code == 401

    resp_docs = client.get("/documents")
    assert resp_docs.status_code == 401


def test_05_expired_jwt_is_rejected(client: TestClient, acme_credentials):
    """Test that expired JWT is rejected with 401."""
    # Obtain user details from DB
    res = client.post("/auth/login", json=acme_credentials)
    token = res.json()["access_token"]
    claims = AuthService.verify_token(token)

    # Issue token expired 10 seconds ago
    expired_token, _ = AuthService.create_access_token(
        user_id=UUID(claims["user_id"]),
        tenant_id=UUID(claims["tenant_id"]),
        role=claims["role"],
        email=claims["email"],
        expires_delta=timedelta(seconds=-10),
    )

    resp = client.get("/auth/me", headers={"Authorization": f"Bearer {expired_token}"})
    assert resp.status_code == 401
    assert "expired" in resp.json()["detail"].lower()


def test_06_tampered_jwt_is_rejected(client: TestClient, acme_credentials):
    """Test that tampered token payload/signature is rejected with 401."""
    res = client.post("/auth/login", json=acme_credentials)
    token = res.json()["access_token"]

    # Tamper with the signature portion
    tampered_token = token[:-4] + "ABCD"
    resp = client.get("/auth/me", headers={"Authorization": f"Bearer {tampered_token}"})
    assert resp.status_code == 401


def test_07_invalid_signing_secret_or_algorithm_rejected(client: TestClient, acme_credentials):
    """Test that tokens signed with wrong secret or wrong algorithm are rejected."""
    res = client.post("/auth/login", json=acme_credentials)
    claims = AuthService.verify_token(res.json()["access_token"])

    now = datetime.now(timezone.utc)
    payload = {
        "sub": claims["sub"],
        "user_id": claims["user_id"],
        "tenant_id": claims["tenant_id"],
        "role": claims["role"],
        "email": claims["email"],
        "exp": int((now + timedelta(hours=1)).timestamp()),
    }

    # 1. Signed with invalid secret
    fake_token = jwt.encode(payload, "completely_wrong_attacker_secret_key", algorithm="HS256")
    resp_fake = client.get("/auth/me", headers={"Authorization": f"Bearer {fake_token}"})
    assert resp_fake.status_code == 401

    # 2. Algorithm confusion / 'none' algorithm
    none_token = jwt.encode(payload, key="", algorithm="none")
    resp_none = client.get("/auth/me", headers={"Authorization": f"Bearer {none_token}"})
    assert resp_none.status_code == 401


def test_08_missing_required_claims_rejected(client: TestClient):
    """Test that tokens missing tenant_id or user_id claims are rejected."""
    now = datetime.now(timezone.utc)

    # Missing tenant_id
    payload_no_tenant = {
        "sub": str(uuid4()),
        "user_id": str(uuid4()),
        "role": "tenant_user",
        "exp": int((now + timedelta(hours=1)).timestamp()),
    }
    token_no_tenant = jwt.encode(payload_no_tenant, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    resp = client.get("/auth/me", headers={"Authorization": f"Bearer {token_no_tenant}"})
    assert resp.status_code == 401


# ------------------------------------------------------------------------------
# 3. Trusted Tenant Context & Client Override Immunity
# ------------------------------------------------------------------------------

def test_09_tenant_a_token_cannot_override_context_via_header(client: TestClient, acme_credentials, beta_credentials):
    """
    Test that supplying an X-Tenant-ID header with Beta's ID does NOT switch
    Acme's context to Beta. Acme still receives only Acme documents.
    """
    # 1. Login as Acme and Beta to obtain tokens and tenant IDs
    acme_token = client.post("/auth/login", json=acme_credentials).json()["access_token"]
    beta_token = client.post("/auth/login", json=beta_credentials).json()["access_token"]

    acme_user = client.get("/auth/me", headers={"Authorization": f"Bearer {acme_token}"}).json()
    beta_user = client.get("/auth/me", headers={"Authorization": f"Bearer {beta_token}"}).json()

    acme_tenant_id = acme_user["tenant_id"]
    beta_tenant_id = beta_user["tenant_id"]
    assert acme_tenant_id != beta_tenant_id

    # 2. Acme requests documents while attempting to spoof X-Tenant-ID: beta_tenant_id
    spoofed_resp = client.get(
        "/documents",
        headers={
            "Authorization": f"Bearer {acme_token}",
            "X-Tenant-ID": beta_tenant_id,
        },
    )
    assert spoofed_resp.status_code == 200
    docs = spoofed_resp.json()

    # Must contain only Acme documents; zero Beta documents returned
    assert len(docs) >= 1
    for doc in docs:
        assert doc["tenant_id"] == acme_tenant_id, "Spoofed header leaked cross-tenant document!"
        assert doc["tenant_id"] != beta_tenant_id


def test_10_tenant_a_token_cannot_override_context_via_query_param(client: TestClient, acme_credentials, beta_credentials):
    """
    Test that supplying ?tenant_id=<beta_id> does NOT switch Acme's context to Beta.
    """
    acme_token = client.post("/auth/login", json=acme_credentials).json()["access_token"]
    beta_token = client.post("/auth/login", json=beta_credentials).json()["access_token"]

    acme_user = client.get("/auth/me", headers={"Authorization": f"Bearer {acme_token}"}).json()
    beta_user = client.get("/auth/me", headers={"Authorization": f"Bearer {beta_token}"}).json()

    acme_tenant_id = acme_user["tenant_id"]
    beta_tenant_id = beta_user["tenant_id"]

    # Acme requests documents with query param tenant_id=<beta_tenant_id>
    spoofed_resp = client.get(
        f"/documents?tenant_id={beta_tenant_id}",
        headers={"Authorization": f"Bearer {acme_token}"},
    )
    assert spoofed_resp.status_code == 200
    docs = spoofed_resp.json()

    assert len(docs) >= 1
    for doc in docs:
        assert doc["tenant_id"] == acme_tenant_id
        assert doc["tenant_id"] != beta_tenant_id


def test_11_tenant_a_token_creates_document_with_token_tenant_only(client: TestClient, acme_credentials):
    """
    Test that POST /documents derives tenant_id exclusively from verified token.
    """
    acme_token = client.post("/auth/login", json=acme_credentials).json()["access_token"]
    acme_user = client.get("/auth/me", headers={"Authorization": f"Bearer {acme_token}"}).json()

    new_doc_payload = {
        "title": "Level 3 Authenticated Document",
        "content": "Created under trusted tenant context.",
    }
    create_resp = client.post(
        "/documents",
        json=new_doc_payload,
        headers={"Authorization": f"Bearer {acme_token}"},
    )
    assert create_resp.status_code == 201
    created_doc = create_resp.json()
    assert created_doc["tenant_id"] == acme_user["tenant_id"]


# ------------------------------------------------------------------------------
# 4. User Status & Platform Admin Tests
# ------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_12_deactivated_user_token_is_rejected(acme_credentials):
    """
    Test that a token belonging to an inactive user is rejected with 401.
    """
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as async_client:
        # 1. Login to get valid tenant ID
        login_res = await async_client.post("/auth/login", json=acme_credentials)
        claims = AuthService.verify_token(login_res.json()["access_token"])
        tenant_id = UUID(claims["tenant_id"])
        user_id = uuid4()

        # 2. Insert a temporary disabled user in DB
        async with AsyncSessionLocal() as session:
            async with session.begin():
                await session.execute(
                    text(
                        "INSERT INTO users (id, tenant_id, email, hashed_password, role, is_active) "
                        "VALUES (:id, :tenant_id, 'disabled_user@acme.test', :hashed, 'tenant_user', false)"
                    ),
                    {
                        "id": str(user_id),
                        "tenant_id": str(tenant_id),
                        "hashed": AuthService.hash_password("AnyPassword123!"),
                    },
                )

        try:
            # Issue token for this disabled user
            disabled_token, _ = AuthService.create_access_token(
                user_id=user_id,
                tenant_id=tenant_id,
                role="tenant_user",
                email="disabled_user@acme.test",
            )

            resp = await async_client.get("/auth/me", headers={"Authorization": f"Bearer {disabled_token}"})
            assert resp.status_code == 401
            assert "inactive" in resp.json()["detail"].lower()
        finally:
            # Cleanup
            async with AsyncSessionLocal() as session:
                async with session.begin():
                    await session.execute(
                        text("DELETE FROM users WHERE id = :id"),
                        {"id": str(user_id)},
                    )


def test_13_platform_admin_cannot_bypass_document_rls(client: TestClient, admin_credentials, acme_credentials):
    """
    Requirement: Do not assume platform admin automatically bypasses document RLS.
    Platform admin queries documents under their own tenant context and does not see Acme documents.
    """
    admin_token = client.post("/auth/login", json=admin_credentials).json()["access_token"]
    acme_token = client.post("/auth/login", json=acme_credentials).json()["access_token"]

    acme_user = client.get("/auth/me", headers={"Authorization": f"Bearer {acme_token}"}).json()
    admin_user = client.get("/auth/me", headers={"Authorization": f"Bearer {admin_token}"}).json()

    assert admin_user["role"] == "platform_admin"
    assert admin_user["tenant_id"] != acme_user["tenant_id"]

    # Query documents as platform admin
    admin_docs_resp = client.get("/documents", headers={"Authorization": f"Bearer {admin_token}"})
    assert admin_docs_resp.status_code == 200
    admin_docs = admin_docs_resp.json()

    # Platform admin sees zero Acme documents
    for doc in admin_docs:
        assert doc["tenant_id"] != acme_user["tenant_id"], "Platform admin erroneously accessed Acme document!"


# ------------------------------------------------------------------------------
# 5. Audit Logging, Single Document Access & Account Provisioning Safety
# ------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_14_login_audit_events_logged():
    """
    Test that successful and failed logins log audit events to security_events table,
    and that plaintext passwords and hashes are NEVER recorded.
    """
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as async_client:
        # 1. Failed login with unknown email
        fail_resp = await async_client.post(
            "/auth/login",
            json={"email": "nonexistent_audit@acme.test", "password": "WrongPassword123!"},
        )
        assert fail_resp.status_code == 401

        # 2. Successful login
        success_resp = await async_client.post(
            "/auth/login",
            json={"email": settings.DEV_ACME_USER_EMAIL, "password": settings.DEV_ACME_USER_PASSWORD},
        )
        assert success_resp.status_code == 200

    # 3. Verify security_events table
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            text(
                "SELECT event_type, severity, details, created_at "
                "FROM security_events WHERE event_type IN ('LOGIN_FAILURE', 'LOGIN_SUCCESS') "
                "ORDER BY created_at DESC LIMIT 10"
            )
        )
        events = result.fetchall()
        assert len(events) >= 2

        event_types = [e.event_type for e in events]
        assert "LOGIN_FAILURE" in event_types
        assert "LOGIN_SUCCESS" in event_types

        # Ensure passwords or hashes are never recorded in audit events
        for e in events:
            details_str = str(e.details)
            assert "WrongPassword123!" not in details_str
            assert settings.DEV_ACME_USER_PASSWORD not in details_str
            assert "$argon2id$" not in details_str


def test_15_document_by_id_enforces_application_and_rls_isolation(client: TestClient, acme_credentials, beta_credentials):
    """
    Test that GET /documents/{id} combines application-level checks with database RLS:
    Acme can fetch its own document, but Beta receives 404 when querying Acme's document ID.
    """
    acme_token = client.post("/auth/login", json=acme_credentials).json()["access_token"]
    beta_token = client.post("/auth/login", json=beta_credentials).json()["access_token"]

    # Acme creates a document
    create_res = client.post(
        "/documents",
        json={"title": "Acme Single Doc Isolation", "content": "Restricted content."},
        headers={"Authorization": f"Bearer {acme_token}"},
    )
    assert create_res.status_code == 201
    doc_id = create_res.json()["id"]

    # Acme fetches own document
    get_res = client.get(f"/documents/{doc_id}", headers={"Authorization": f"Bearer {acme_token}"})
    assert get_res.status_code == 200
    assert get_res.json()["id"] == doc_id
    assert get_res.json()["title"] == "Acme Single Doc Isolation"

    # Beta attempts to fetch Acme's document -> 404 Not Found
    cross_res = client.get(f"/documents/{doc_id}", headers={"Authorization": f"Bearer {beta_token}"})
    assert cross_res.status_code == 404
    assert cross_res.json()["detail"] == "Document not found"


@pytest.mark.asyncio
async def test_16_seed_script_safety_and_preservation(monkeypatch):
    """
    Test seed script safety:
    1. Rejects execution in production environment.
    2. Preserves existing password hashes when run without --reset-passwords.
    """
    from scripts.seed_tenants import seed_data

    # 1. Test production rejection
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    with pytest.raises(SystemExit) as exc_info:
        await seed_data()
    assert exc_info.value.code == 1

    # Restore environment
    monkeypatch.setattr(settings, "ENVIRONMENT", "development")

    # 2. Get current hash for Acme user
    async with AsyncSessionLocal() as session:
        res = await session.execute(
            text("SELECT hashed_password FROM users WHERE email = :email"),
            {"email": settings.DEV_ACME_USER_EMAIL},
        )
        original_hash = res.scalar_one()

    # Run seed_data without --reset-passwords
    await seed_data()

    # Verify password hash was preserved, not overwritten
    async with AsyncSessionLocal() as session:
        res = await session.execute(
            text("SELECT hashed_password FROM users WHERE email = :email"),
            {"email": settings.DEV_ACME_USER_EMAIL},
        )
        post_seed_hash = res.scalar_one()

    assert original_hash == post_seed_hash, "Seed script unexpectedly reset existing password hash!"
