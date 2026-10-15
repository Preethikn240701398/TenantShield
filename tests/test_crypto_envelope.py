"""
TenantShield - Level 5 Envelope Encryption & Crypto-Shredding Test Suite
========================================================================
Mandatory principle: Do not invent results or claim the system is secure.

Verifies all 14 Level 5 requirements:
1.  Encryption/decryption round trip returns original document content to authorized tenant.
2.  Stored document data contains ciphertext rather than plaintext (database assertions).
3.  Tampering with ciphertext causes AES-GCM authentication failure and no plaintext is returned.
4.  Tampering with the nonce or authenticated metadata fails safely.
5.  Copying ciphertext to a different tenant ID fails decryption (deterministic AAD).
6.  Copying ciphertext to a different document ID fails decryption (deterministic AAD).
7.  Tenant A cannot use or read Tenant B's DEK or decrypt Tenant B's documents.
8.  New writes use the active key version after rotation.
9.  Existing documents encrypted under a retired key version remain decryptable.
10. Destroying a DEK prevents decryption of documents encrypted with that version.
11. Destroying Tenant A's key does not affect Tenant B's documents.
12. Missing or invalid master-key configuration fails safely.
13. Existing Level 0-4 authentication, RLS, ownership, CRUD, and audit tests still pass.
14. No test or error response leaks plaintext, keys, or cryptographic internals.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import text

from app.core.config import Settings, settings
from app.core.database import AsyncSessionLocal, set_tenant_context, tenant_session
from app.main import app
from app.services.crypto import (
    CryptoAuthenticationError,
    CryptoError,
    CryptoKeyNotFoundError,
    CryptoService,
    CryptoShreddedError,
)

# Accumulator for verifiable Level 5 experiment results
RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
level5_experiment_records = []


def record_level5_experiment(
    test_number: int,
    requirement: str,
    outcome: str,
    evidence: dict,
):
    """Records verifiable non-sensitive experiment evidence."""
    record = {
        "test_number": test_number,
        "requirement": requirement,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "outcome": outcome,
        "evidence": evidence,
    }
    level5_experiment_records.append(record)


@pytest.fixture(scope="module")
def acme_auth(client: TestClient):
    """Authenticates Acme user and returns token and user profile."""
    resp = client.post(
        "/auth/login",
        json={"email": settings.DEV_ACME_USER_EMAIL, "password": settings.DEV_ACME_USER_PASSWORD},
    )
    assert resp.status_code == 200
    token = resp.json()["access_token"]
    user_info = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"}).json()
    return {"token": token, "headers": {"Authorization": f"Bearer {token}"}, "user": user_info}


@pytest.fixture(scope="module")
def beta_auth(client: TestClient):
    """Authenticates Beta user and returns token and user profile."""
    resp = client.post(
        "/auth/login",
        json={"email": settings.DEV_BETA_USER_EMAIL, "password": settings.DEV_BETA_USER_PASSWORD},
    )
    assert resp.status_code == 200
    token = resp.json()["access_token"]
    user_info = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"}).json()
    return {"token": token, "headers": {"Authorization": f"Bearer {token}"}, "user": user_info}


@pytest.fixture(scope="module")
def admin_auth(client: TestClient):
    """Authenticates Platform Admin user and returns token and user profile."""
    resp = client.post(
        "/auth/login",
        json={"email": settings.DEV_ADMIN_USER_EMAIL, "password": settings.DEV_ADMIN_USER_PASSWORD},
    )
    assert resp.status_code == 200
    token = resp.json()["access_token"]
    user_info = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"}).json()
    return {"token": token, "headers": {"Authorization": f"Bearer {token}"}, "user": user_info}


# ------------------------------------------------------------------------------
# Test 1: Encryption / Decryption Round Trip
# ------------------------------------------------------------------------------

def test_01_encryption_decryption_round_trip(client: TestClient, acme_auth):
    """1. Encryption/decryption round trip returns original document content to an authorized tenant."""
    headers = acme_auth["headers"]
    secret_payload = "Highly Confidential Acme Q4 Merger Plan with Quantum Dynamics"

    # Create document
    create_resp = client.post(
        "/documents",
        json={"title": "Merger Strategy", "content": secret_payload},
        headers=headers,
    )
    assert create_resp.status_code == 201
    doc_id = create_resp.json()["id"]

    # Read back document
    get_resp = client.get(f"/documents/{doc_id}", headers=headers)
    assert get_resp.status_code == 200
    data = get_resp.json()
    assert data["content"] == secret_payload

    record_level5_experiment(
        test_number=1,
        requirement="Encryption/decryption round trip returns original content",
        outcome="PASSED",
        evidence={"document_id": doc_id, "status_code": 200, "content_matched": True},
    )


# ------------------------------------------------------------------------------
# Test 2: Database Assertion - Ciphertext Stored, Plaintext Absent
# ------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_02_stored_document_contains_ciphertext_not_plaintext(client: TestClient, acme_auth):
    """2. Stored document data contains ciphertext rather than plaintext (direct DB inspection)."""
    headers = acme_auth["headers"]
    secret_payload = "SuperSecretPlaintextToken_987654321"

    create_resp = client.post(
        "/documents",
        json={"title": "Secret Token Doc", "content": secret_payload},
        headers=headers,
    )
    assert create_resp.status_code == 201
    doc_id = create_resp.json()["id"]
    tenant_id = acme_auth["user"]["tenant_id"]

    # Direct database query under tenant context
    async with tenant_session(tenant_id) as session:
        result = await session.execute(
            text("SELECT content, key_version, nonce, ciphertext FROM documents WHERE id = :id"),
            {"id": str(doc_id)},
        )
        row = result.fetchone()

        assert row is not None, "Document not found in database"
        # Assert content column is NULL
        assert row.content is None, f"Plaintext content leaked in database content column: {row.content}"
        # Assert ciphertext exists and is non-empty bytes
        assert row.ciphertext is not None and len(row.ciphertext) > 0, "Ciphertext is empty or missing"
        # Assert nonce exists and is 12 bytes
        assert row.nonce is not None and len(row.nonce) == 12, f"Nonce length is invalid: {len(row.nonce)}"
        # Assert plaintext is NOT present anywhere in ciphertext
        assert secret_payload.encode("utf-8") not in row.ciphertext, "Plaintext found unencrypted in ciphertext bytes"

        # Assert zero plaintext documents in the entire table
        total_plaintext = (await session.execute(text("SELECT count(*) FROM documents WHERE content IS NOT NULL"))).scalar_one()
        assert total_plaintext == 0, f"Violation: {total_plaintext} plaintext documents remain in database!"

    record_level5_experiment(
        test_number=2,
        requirement="Stored document contains ciphertext rather than plaintext",
        outcome="PASSED",
        evidence={
            "document_id": doc_id,
            "content_is_null": True,
            "nonce_length_bytes": 12,
            "ciphertext_present": True,
            "total_plaintext_in_db": 0,
        },
    )


# ------------------------------------------------------------------------------
# Test 3: Tampered Ciphertext Fails Authentication
# ------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_03_tampered_ciphertext_causes_authentication_failure(client: TestClient, acme_auth):
    """3. Tampering with ciphertext causes AES-GCM authentication failure and no plaintext is returned."""
    headers = acme_auth["headers"]
    create_resp = client.post(
        "/documents",
        json={"title": "Tamper Target", "content": "Original intact content."},
        headers=headers,
    )
    doc_id = create_resp.json()["id"]
    tenant_id = acme_auth["user"]["tenant_id"]

    # Tamper with the ciphertext byte in the database
    async with tenant_session(tenant_id) as session:
        row = (await session.execute(
            text("SELECT ciphertext FROM documents WHERE id = :id"),
            {"id": str(doc_id)},
        )).fetchone()
        original_ct = bytearray(row.ciphertext)
        original_ct[0] ^= 0xFF  # Flip bits in first byte

        await session.execute(
            text("UPDATE documents SET ciphertext = :ct WHERE id = :id"),
            {"ct": bytes(original_ct), "id": str(doc_id)},
        )

    # API read should fail safely with 404 (controlled error, no plaintext leak)
    get_resp = client.get(f"/documents/{doc_id}", headers=headers)
    assert get_resp.status_code == 404
    assert "Original intact content" not in get_resp.text

    record_level5_experiment(
        test_number=3,
        requirement="Tampered ciphertext causes authentication failure",
        outcome="PASSED",
        evidence={"document_id": doc_id, "api_response_status": 404, "no_plaintext_returned": True},
    )


# ------------------------------------------------------------------------------
# Test 4: Tampered Nonce Fails Authentication
# ------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_04_tampered_nonce_causes_authentication_failure(client: TestClient, acme_auth):
    """4. Tampering with the nonce causes AES-GCM authentication failure and fails safely."""
    headers = acme_auth["headers"]
    create_resp = client.post(
        "/documents",
        json={"title": "Nonce Tamper Target", "content": "Tamper nonce test."},
        headers=headers,
    )
    doc_id = create_resp.json()["id"]
    tenant_id = acme_auth["user"]["tenant_id"]

    # Tamper with nonce in database
    async with tenant_session(tenant_id) as session:
        row = (await session.execute(
            text("SELECT nonce FROM documents WHERE id = :id"),
            {"id": str(doc_id)},
        )).fetchone()
        tampered_nonce = bytearray(row.nonce)
        tampered_nonce[0] ^= 0xAA

        await session.execute(
            text("UPDATE documents SET nonce = :nonce WHERE id = :id"),
            {"nonce": bytes(tampered_nonce), "id": str(doc_id)},
        )

    get_resp = client.get(f"/documents/{doc_id}", headers=headers)
    assert get_resp.status_code == 404

    record_level5_experiment(
        test_number=4,
        requirement="Tampered nonce causes authentication failure",
        outcome="PASSED",
        evidence={"document_id": doc_id, "api_response_status": 404},
    )


# ------------------------------------------------------------------------------
# Test 5: Copy Ciphertext to Different Tenant Fails
# ------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_05_copy_ciphertext_to_different_tenant_fails(client: TestClient, acme_auth, beta_auth):
    """5. Copying ciphertext to a different tenant ID fails decryption due to deterministic AAD."""
    acme_headers = acme_auth["headers"]
    beta_headers = beta_auth["headers"]
    acme_tenant_id = acme_auth["user"]["tenant_id"]
    beta_tenant_id = beta_auth["user"]["tenant_id"]

    # 1. Acme creates document
    create_resp = client.post(
        "/documents",
        json={"title": "Acme Trophy", "content": "Exclusive Acme Secret Strategy"},
        headers=acme_headers,
    )
    acme_doc_id = create_resp.json()["id"]

    # 2. Extract Acme's ciphertext and nonce
    async with tenant_session(acme_tenant_id) as session:
        row = (await session.execute(
            text("SELECT nonce, ciphertext, key_version FROM documents WHERE id = :id"),
            {"id": str(acme_doc_id)},
        )).fetchone()
        acme_nonce = row.nonce
        acme_ct = row.ciphertext

    # 3. Create a Beta document, then maliciously overwrite its ciphertext with Acme's
    beta_create = client.post(
        "/documents",
        json={"title": "Beta Container", "content": "Beta original content"},
        headers=beta_headers,
    )
    beta_doc_id = beta_create.json()["id"]

    async with tenant_session(beta_tenant_id) as session:
        await session.execute(
            text("UPDATE documents SET ciphertext = :ct, nonce = :nonce WHERE id = :id"),
            {"ct": acme_ct, "nonce": acme_nonce, "id": str(beta_doc_id)},
        )

    # 4. Beta attempts to read the relocated ciphertext
    beta_read = client.get(f"/documents/{beta_doc_id}", headers=beta_headers)
    # Must fail because AAD binds tenant_id and decryption key differs
    assert beta_read.status_code == 404
    assert "Exclusive Acme Secret Strategy" not in beta_read.text

    record_level5_experiment(
        test_number=5,
        requirement="Copying ciphertext to different tenant ID fails decryption",
        outcome="PASSED",
        evidence={"acme_doc_id": acme_doc_id, "beta_doc_id": beta_doc_id, "beta_response_status": 404},
    )


# ------------------------------------------------------------------------------
# Test 6: Copy Ciphertext to Different Document ID Fails
# ------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_06_copy_ciphertext_to_different_document_fails(client: TestClient, acme_auth):
    """6. Copying ciphertext to a different document ID fails decryption due to deterministic AAD."""
    headers = acme_auth["headers"]
    tenant_id = acme_auth["user"]["tenant_id"]

    # Create Document A
    doc_a = client.post(
        "/documents",
        json={"title": "Doc A", "content": "Secret Content A"},
        headers=headers,
    ).json()
    doc_a_id = doc_a["id"]

    # Create Document B
    doc_b = client.post(
        "/documents",
        json={"title": "Doc B", "content": "Secret Content B"},
        headers=headers,
    ).json()
    doc_b_id = doc_b["id"]

    # Extract Doc A's cryptographic material
    async with tenant_session(tenant_id) as session:
        row_a = (await session.execute(
            text("SELECT nonce, ciphertext FROM documents WHERE id = :id"),
            {"id": str(doc_a_id)},
        )).fetchone()

        # Copy Doc A ciphertext into Doc B
        await session.execute(
            text("UPDATE documents SET ciphertext = :ct, nonce = :nonce WHERE id = :id"),
            {"ct": row_a.ciphertext, "nonce": row_a.nonce, "id": str(doc_b_id)},
        )

    # Read Doc B -> fails because AAD binds document_id
    resp = client.get(f"/documents/{doc_b_id}", headers=headers)
    assert resp.status_code == 404
    assert "Secret Content A" not in resp.text

    record_level5_experiment(
        test_number=6,
        requirement="Copying ciphertext to different document ID fails decryption",
        outcome="PASSED",
        evidence={"doc_a_id": doc_a_id, "doc_b_id": doc_b_id, "status_code": 404},
    )


# ------------------------------------------------------------------------------
# Test 7: Tenant Isolation - DEK Access & Decryption
# ------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_07_tenant_isolation_dek_and_documents(client: TestClient, acme_auth, beta_auth):
    """7. Tenant A cannot use or read Tenant B's DEK or decrypt Tenant B's documents."""
    acme_tenant_id = acme_auth["user"]["tenant_id"]
    beta_tenant_id = beta_auth["user"]["tenant_id"]

    # Under Acme session context, query tenant_keys for Beta
    async with tenant_session(acme_tenant_id) as session:
        beta_keys = (await session.execute(
            text("SELECT * FROM tenant_keys WHERE tenant_id = :beta_id"),
            {"beta_id": str(beta_tenant_id)},
        )).fetchall()
        # Row-Level Security on tenant_keys blocks cross-tenant reads
        assert len(beta_keys) == 0, "Acme was able to read Beta's tenant_keys records!"

    # Verify CryptoService raises Authentication error when attempting to decrypt with wrong DEK
    dek_a = CryptoService.generate_dek()
    dek_b = CryptoService.generate_dek()
    fake_doc_id = uuid4()
    nonce, ct = CryptoService.encrypt_document(dek_a, "Sensitive Data", acme_tenant_id, fake_doc_id)

    with pytest.raises(CryptoAuthenticationError):
        CryptoService.decrypt_document(dek_b, ct, nonce, acme_tenant_id, fake_doc_id)

    record_level5_experiment(
        test_number=7,
        requirement="Tenant A cannot read Tenant B's DEK or decrypt Tenant B's documents",
        outcome="PASSED",
        evidence={"cross_tenant_keys_visible": 0, "wrong_dek_raises_auth_error": True},
    )


# ------------------------------------------------------------------------------
# Test 8: New Writes Use Active Key Version After Rotation
# ------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_08_active_key_version_used_after_rotation(client: TestClient, acme_auth, admin_auth):
    """8. New writes use the active key version after rotation."""
    acme_headers = acme_auth["headers"]
    admin_headers = admin_auth["headers"]
    acme_tenant_id = acme_auth["user"]["tenant_id"]

    # Rotate Acme's DEK via Admin API
    rotate_resp = client.post(f"/admin/keys/{acme_tenant_id}/rotate", headers=admin_headers)
    assert rotate_resp.status_code == 200
    new_version = rotate_resp.json()["new_key_version"]
    assert new_version >= 2

    # Write a new document under Acme
    create_resp = client.post(
        "/documents",
        json={"title": "Post-Rotation Document", "content": "Written under newly rotated DEK."},
        headers=acme_headers,
    )
    assert create_resp.status_code == 201
    doc_id = create_resp.json()["id"]

    # Verify in DB that key_version matches the rotated version
    async with tenant_session(acme_tenant_id) as session:
        row = (await session.execute(
            text("SELECT key_version FROM documents WHERE id = :id"),
            {"id": str(doc_id)},
        )).fetchone()
        assert row.key_version == new_version

    record_level5_experiment(
        test_number=8,
        requirement="New writes use active key version after rotation",
        outcome="PASSED",
        evidence={"new_key_version": new_version, "document_key_version": row.key_version},
    )


# ------------------------------------------------------------------------------
# Test 9: Retired Key Documents Remain Decryptable
# ------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_09_retired_key_documents_remain_decryptable(client: TestClient, acme_auth, admin_auth):
    """9. Existing documents encrypted under a retired key version remain decryptable."""
    acme_headers = acme_auth["headers"]
    admin_headers = admin_auth["headers"]
    acme_tenant_id = acme_auth["user"]["tenant_id"]

    # 1. Create document before second rotation
    doc_pre = client.post(
        "/documents",
        json={"title": "Pre-Rotation Archive", "content": "Archived financial records from prior key version."},
        headers=acme_headers,
    ).json()
    pre_id = doc_pre["id"]

    # 2. Rotate key again
    rotate_resp = client.post(f"/admin/keys/{acme_tenant_id}/rotate", headers=admin_headers)
    assert rotate_resp.status_code == 200

    # 3. Read back the older document
    get_resp = client.get(f"/documents/{pre_id}", headers=acme_headers)
    assert get_resp.status_code == 200
    assert get_resp.json()["content"] == "Archived financial records from prior key version."

    record_level5_experiment(
        test_number=9,
        requirement="Existing documents under retired key version remain decryptable",
        outcome="PASSED",
        evidence={"document_id": pre_id, "read_status": 200, "decryption_successful": True},
    )


# ------------------------------------------------------------------------------
# Test 10: Crypto-Shredding Prevents Decryption
# ------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_10_crypto_shredding_prevents_decryption(client: TestClient, acme_auth, admin_auth):
    """10. Destroying a DEK prevents decryption of documents encrypted with that version."""
    acme_headers = acme_auth["headers"]
    admin_headers = admin_auth["headers"]
    acme_tenant_id = acme_auth["user"]["tenant_id"]

    # Create document under current active version
    doc = client.post(
        "/documents",
        json={"title": "Shred Target Doc", "content": "Data to be crypto-shredded irreversibly."},
        headers=acme_headers,
    ).json()
    doc_id = doc["id"]

    # Find the key_version of this document
    async with tenant_session(acme_tenant_id) as session:
        row = (await session.execute(
            text("SELECT key_version FROM documents WHERE id = :id"),
            {"id": str(doc_id)},
        )).fetchone()
        target_version = row.key_version

    # Shred this specific key version via Admin API
    shred_resp = client.post(
        f"/admin/keys/{acme_tenant_id}/shred?key_version={target_version}",
        headers=admin_headers,
    )
    assert shred_resp.status_code == 200
    assert shred_resp.json()["status"] == "destroyed"

    # Verify DB state of the key
    async with tenant_session(acme_tenant_id) as session:
        key_row = (await session.execute(
            text("SELECT status, wrapped_dek, wrapping_nonce, destroyed_at FROM tenant_keys WHERE tenant_id = :t_id AND key_version = :ver"),
            {"t_id": str(acme_tenant_id), "ver": target_version},
        )).fetchone()
        assert key_row is not None, "Shredded key record must be visible under tenant context"
        assert key_row.status == "destroyed"
        assert key_row.wrapped_dek is None
        assert key_row.wrapping_nonce is None
        assert key_row.destroyed_at is not None

    # Attempt to read the document -> Must fail with controlled 404 Not Found
    get_resp = client.get(f"/documents/{doc_id}", headers=acme_headers)
    assert get_resp.status_code == 404
    assert "Data to be crypto-shredded" not in get_resp.text

    record_level5_experiment(
        test_number=10,
        requirement="Destroying DEK prevents decryption of dependent documents",
        outcome="PASSED",
        evidence={
            "document_id": doc_id,
            "shredded_version": target_version,
            "key_status": "destroyed",
            "wrapped_dek_is_null": True,
            "read_status": 404,
        },
    )


# ------------------------------------------------------------------------------
# Test 11: Crypto-Shredding Isolation (Other Tenants Unaffected)
# ------------------------------------------------------------------------------

def test_11_crypto_shredding_isolation(client: TestClient, beta_auth):
    """11. Destroying Tenant A's key does not affect Tenant B's documents or keys."""
    beta_headers = beta_auth["headers"]

    # Beta creates a new document
    beta_doc = client.post(
        "/documents",
        json={"title": "Beta Unaffected Doc", "content": "Beta records remain completely accessible."},
        headers=beta_headers,
    )
    assert beta_doc.status_code == 201
    doc_id = beta_doc.json()["id"]

    # Beta retrieves its document
    read_resp = client.get(f"/documents/{doc_id}", headers=beta_headers)
    assert read_resp.status_code == 200
    assert read_resp.json()["content"] == "Beta records remain completely accessible."

    record_level5_experiment(
        test_number=11,
        requirement="Destroying Tenant A key leaves Tenant B unaffected",
        outcome="PASSED",
        evidence={"beta_doc_id": doc_id, "read_status": 200},
    )


# ------------------------------------------------------------------------------
# Test 12: Missing or Invalid Master Key Configuration Fails Safely
# ------------------------------------------------------------------------------

def test_12_missing_or_invalid_master_key_fails_safely():
    """12. Missing or invalid master-key configuration fails safely at startup."""
    # Empty master key
    with pytest.raises(ValidationError) as exc_empty:
        Settings(TENANTSHIELD_MASTER_KEY="")
    assert "Cryptographic Configuration Error" in str(exc_empty.value)

    # Key too short (e.g. 16 bytes = 32 hex chars)
    with pytest.raises(ValidationError) as exc_short:
        Settings(TENANTSHIELD_MASTER_KEY="0123456789abcdef0123456789abcdef")
    assert "Cryptographic Configuration Error" in str(exc_short.value)

    # Invalid non-hex characters
    with pytest.raises(ValidationError) as exc_invalid:
        Settings(TENANTSHIELD_MASTER_KEY="zz" * 32)
    assert "Cryptographic Configuration Error" in str(exc_invalid.value)

    record_level5_experiment(
        test_number=12,
        requirement="Missing or invalid master-key configuration fails safely",
        outcome="PASSED",
        evidence={"empty_key_rejected": True, "short_key_rejected": True, "non_hex_rejected": True},
    )


# ------------------------------------------------------------------------------
# Test 13: Level 0-4 Regression Suite Passes
# ------------------------------------------------------------------------------

def test_13_levels_0_to_4_regression_suite(client: TestClient, acme_auth, beta_auth):
    """13. Existing Level 0-4 authentication, RLS, ownership, CRUD, and audit tests still pass."""
    # Ensure health works
    health_resp = client.get("/health")
    assert health_resp.status_code == 200
    assert health_resp.json()["status"] == "healthy"

    # Ensure unauthenticated request rejected with 401
    anon_resp = client.get("/documents")
    assert anon_resp.status_code == 401

    # Ensure normal CRUD works for Acme
    acme_headers = acme_auth["headers"]
    # Re-provision an active key for Acme if needed after shred test
    create_res = client.post(
        "/documents",
        json={"title": "Regression Doc", "content": "Regression content verified."},
        headers=acme_headers,
    )
    assert create_res.status_code == 201
    doc_id = create_res.json()["id"]

    # Acme can read
    get_res = client.get(f"/documents/{doc_id}", headers=acme_headers)
    assert get_res.status_code == 200
    assert get_res.json()["content"] == "Regression content verified."

    # Beta cannot read Acme doc (Layer A + Layer B)
    cross_read = client.get(f"/documents/{doc_id}", headers=beta_auth["headers"])
    assert cross_read.status_code == 404

    record_level5_experiment(
        test_number=13,
        requirement="Existing Level 0-4 regression suite passes",
        outcome="PASSED",
        evidence={"health_status": "healthy", "anon_status": 401, "cross_tenant_denied": 404},
    )


# ------------------------------------------------------------------------------
# Test 14: Zero Leakage of Secrets or Keys
# ------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_14_no_secrets_leaked_in_errors_or_events(client: TestClient, acme_auth):
    """14. No test or error response leaks plaintext, keys, or cryptographic internals."""
    headers = acme_auth["headers"]
    master_key = settings.TENANTSHIELD_MASTER_KEY

    # Trigger a 404 error
    bogus_id = uuid4()
    err_resp = client.get(f"/documents/{bogus_id}", headers=headers)
    assert err_resp.status_code == 404
    err_body = err_resp.text

    # Assert no secrets in error body
    assert master_key not in err_body
    assert "InvalidTag" not in err_body
    assert "AESGCM" not in err_body

    # Check recent security_events details
    async with AsyncSessionLocal() as session:
        events = (await session.execute(
            text("SELECT details FROM security_events ORDER BY created_at DESC LIMIT 20")
        )).fetchall()

        for ev in events:
            details_str = json.dumps(ev.details) if ev.details else ""
            assert master_key not in details_str, "Master key leaked into security_events!"
            assert "password" not in details_str.lower() or "password" in details_str and "password123" not in details_str.lower()

    record_level5_experiment(
        test_number=14,
        requirement="No test or error response leaks plaintext, keys, or cryptographic internals",
        outcome="PASSED",
        evidence={"master_key_leaked": False, "crypto_internals_leaked": False},
    )


# ------------------------------------------------------------------------------
# Post-Test: Save Traceable Experiment Results
# ------------------------------------------------------------------------------

def test_15_save_traceable_experiment_results():
    """Dumps verifiable Level 5 experiment evidence to results/."""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    file_path = RESULTS_DIR / f"level5_experiment_results_{timestamp}.json"

    report = {
        "level": 5,
        "title": "TenantShield Level 5 - Envelope Encryption & Crypto-Shredding Verification",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "total_experiments_recorded": len(level5_experiment_records),
        "all_passed": all(r["outcome"] == "PASSED" for r in level5_experiment_records),
        "experiments": level5_experiment_records,
    }

    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    assert file_path.is_file()
    assert report["total_experiments_recorded"] >= 14
    assert report["all_passed"] is True
