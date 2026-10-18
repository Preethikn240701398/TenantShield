"""
TenantShield - Part 3 Key Lifecycle Demo Endpoints
==================================================
Administrative endpoints demonstrating envelope encryption, key rotation,
crypto-shredding, and multi-tenant cryptographic isolation.

Enforces:
- Platform Admin authentication strictly required (401 without token, 403 for tenant users).
- Complete refusal when APP_ENV is 'lab' (HTTP 400).
- Actions apply EXCLUSIVELY to DEMO_TENANT_NAME ("Demo Co").
- Client requests that name or supply a tenant parameter are strictly rejected with HTTP 400.
- Responses never expose secrets, tokens, passwords, key material, or document content.
"""

from datetime import datetime, timezone
import logging
import os
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlalchemy import text

from app.api.deps import get_current_user
from app.api.dashboard import require_platform_admin
from app.core.config import settings
from app.core.database import AsyncSessionLocal, tenant_session
from app.schemas.auth import AuthenticatedUser
from app.services.crypto import (
    CryptoAuthenticationError,
    CryptoKeyNotFoundError,
    CryptoService,
    CryptoShreddedError,
)

logger = logging.getLogger("tenantshield.demo")

router = APIRouter(prefix="/admin/demo/keys", tags=["Key Lifecycle Demo"])


def _is_lab_mode() -> bool:
    env = (getattr(settings, "APP_ENV", "") or getattr(settings, "ENVIRONMENT", "")).lower()
    return env == "lab"


def _check_lab_refusal() -> None:
    if _is_lab_mode():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Refused: Key lifecycle demo endpoints are disabled when APP_ENV is lab.",
        )


def _reject_tenant_parameters(request: Request, body_dict: Optional[dict] = None) -> None:
    """Rejects any client attempt to supply a tenant parameter via query, path or body."""
    forbidden_keys = {"tenant", "tenant_id", "tenant_name", "target_tenant", "target_tenant_id", "x_tenant_id"}
    query_params = {k.lower() for k in request.query_params.keys()}
    if query_params.intersection(forbidden_keys):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Client-specified tenant parameters are prohibited in demo endpoints.",
        )
    if body_dict:
        body_keys = {k.lower() for k in body_dict.keys()}
        if body_keys.intersection(forbidden_keys):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Client-specified tenant parameters are prohibited in demo endpoints.",
            )


async def _resolve_demo_tenant_id() -> UUID:
    """Resolves Demo Co tenant ID exclusively on the server from database."""
    demo_name = os.getenv("DEMO_TENANT_NAME", getattr(settings, "DEMO_TENANT_NAME", "Demo Co"))
    async with AsyncSessionLocal() as session:
        res = await session.execute(
            text("SELECT id FROM tenants WHERE name = :name OR slug = 'demo-co'"),
            {"name": demo_name},
        )
        row = res.fetchone()
        if not row:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Demo tenant '{demo_name}' not found. Please run scripts/seed_demo_tenant.py.",
            )
        return row[0]


class CreateDocRequest(BaseModel):
    label: str = "before"


class DestroyKeyRequest(BaseModel):
    confirm: str


# ------------------------------------------------------------------------------
# 1. POST /admin/demo/keys/create-document
# ------------------------------------------------------------------------------
@router.post("/create-document", summary="Create Demo Document Encrypted Under Active Key")
async def create_demo_document(
    request: Request,
    payload: Optional[Dict[str, Any]] = Body(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> Dict[str, Any]:
    require_platform_admin(current_user)
    _check_lab_refusal()
    _reject_tenant_parameters(request, payload)

    label = (payload or {}).get("label", "before")
    if not isinstance(label, str) or label.strip().lower() not in ("before", "after"):
        label = "before"
    label = label.strip().lower()

    demo_id = await _resolve_demo_tenant_id()
    doc_id = uuid4()
    title = f"[Demo] Document ({label})"
    plaintext = f"Confidential demo payload created {label} key rotation at {datetime.now(timezone.utc).isoformat()}."

    # Encrypt strictly under Demo Co's active DEK within Demo Co's tenant context
    async with tenant_session(demo_id) as session:
        key_version, dek = await CryptoService.get_or_create_active_dek(session, demo_id)
        nonce, ciphertext = CryptoService.encrypt_document(
            dek=dek,
            plaintext=plaintext,
            tenant_id=demo_id,
            document_id=doc_id,
        )

        await session.execute(
            text(
                "INSERT INTO documents (id, tenant_id, owner_id, title, key_version, nonce, ciphertext) "
                "VALUES (:id, :tenant_id, :owner_id, :title, :key_version, :nonce, :ciphertext)"
            ),
            {
                "id": str(doc_id),
                "tenant_id": str(demo_id),
                "owner_id": str(current_user.user_id),
                "title": title,
                "key_version": key_version,
                "nonce": nonce,
                "ciphertext": ciphertext,
            },
        )

    return {
        "status": "created",
        "document_id": str(doc_id),
        "label": label,
        "key_version": key_version,
    }


# ------------------------------------------------------------------------------
# 2. POST /admin/demo/keys/rotate
# ------------------------------------------------------------------------------
@router.post("/rotate", summary="Rotate Demo Co Active DEK")
async def rotate_demo_key(
    request: Request,
    payload: Optional[Dict[str, Any]] = Body(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> Dict[str, Any]:
    require_platform_admin(current_user)
    _check_lab_refusal()
    _reject_tenant_parameters(request, payload)

    demo_id = await _resolve_demo_tenant_id()

    async with tenant_session(demo_id) as session:
        new_version = await CryptoService.rotate_tenant_dek(session, demo_id)

    return {
        "status": "rotated",
        "new_key_version": new_version,
    }


# ------------------------------------------------------------------------------
# 3. POST /admin/demo/keys/read
# ------------------------------------------------------------------------------
@router.post("/read", summary="Attempt Decryption of All Demo Documents")
async def read_demo_documents(
    request: Request,
    payload: Optional[Dict[str, Any]] = Body(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> Dict[str, Any]:
    require_platform_admin(current_user)
    _check_lab_refusal()
    _reject_tenant_parameters(request, payload)

    demo_id = await _resolve_demo_tenant_id()
    results = []

    async with tenant_session(demo_id) as session:
        rows = (
            await session.execute(
                text(
                    "SELECT id, title, key_version, nonce, ciphertext, created_at "
                    "FROM documents WHERE tenant_id = :tid ORDER BY created_at ASC"
                ),
                {"tid": str(demo_id)},
            )
        ).fetchall()

        for r in rows:
            # Determine label from title
            label = "unknown"
            if "before" in r.title.lower():
                label = "before"
            elif "after" in r.title.lower():
                label = "after"
            elif "[demo]" in r.title.lower():
                label = "demo"

            doc_status = "OK"
            reason = None

            try:
                dek = await CryptoService.get_dek_for_version(session, demo_id, r.key_version or 1)
                # Attempt decryption (never return plaintext)
                _ = CryptoService.decrypt_document(
                    dek=dek,
                    ciphertext=r.ciphertext,
                    nonce=r.nonce,
                    tenant_id=demo_id,
                    document_id=r.id,
                )
                doc_status = "OK"
            except CryptoShreddedError:
                doc_status = "FAILED_SAFELY"
                reason = "Key permanently shredded"
            except CryptoKeyNotFoundError:
                doc_status = "FAILED_SAFELY"
                reason = "Key version not found"
            except CryptoAuthenticationError:
                doc_status = "FAILED_SAFELY"
                reason = "Authentication tag verification failed"
            except Exception as exc:
                doc_status = "FAILED_SAFELY"
                reason = f"Decryption failure ({type(exc).__name__})"

            results.append({
                "document_id": str(r.id),
                "label": label,
                "key_version": r.key_version,
                "status": doc_status,
                "reason": reason,
            })

    return {
        "status": "completed",
        "total_documents": len(results),
        "documents": results,
    }


# ------------------------------------------------------------------------------
# 4. POST /admin/demo/keys/destroy
# ------------------------------------------------------------------------------
@router.post("/destroy", summary="Crypto-Shred Demo Tenant Keys")
async def destroy_demo_key(
    request: Request,
    payload: Dict[str, Any] = Body(...),
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> Dict[str, Any]:
    require_platform_admin(current_user)
    _check_lab_refusal()
    _reject_tenant_parameters(request, payload)

    confirm_str = payload.get("confirm")
    if confirm_str != "DESTROY":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Confirmation required: field 'confirm' must equal exactly 'DESTROY'.",
        )

    demo_id = await _resolve_demo_tenant_id()

    async with tenant_session(demo_id) as session:
        shredded_count = await CryptoService.crypto_shred_tenant_dek(session, demo_id, key_version=None)

    return {
        "status": "destroyed",
        "keys_shredded": shredded_count,
    }


# ------------------------------------------------------------------------------
# 5. POST /admin/demo/keys/read-other
# ------------------------------------------------------------------------------
@router.post("/read-other", summary="Read Acme Document to Verify Isolation")
async def read_other_tenant_document(
    request: Request,
    payload: Optional[Dict[str, Any]] = Body(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> Dict[str, Any]:
    require_platform_admin(current_user)
    _check_lab_refusal()
    _reject_tenant_parameters(request, payload)

    # 1. Resolve Acme Corp tenant ID
    async with AsyncSessionLocal() as session:
        acme_row = (
            await session.execute(
                text("SELECT id, name FROM tenants WHERE slug = 'acme' OR name ILIKE '%acme%' LIMIT 1")
            )
        ).fetchone()

        if not acme_row:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Acme Corp tenant not found in database.",
            )
        acme_id = acme_row.id
        acme_name = acme_row.name

    # 2. Read and decrypt one Acme document in Acme's own tenant context
    read_status = "FAILED"
    async with tenant_session(acme_id) as session:
        doc_row = (
            await session.execute(
                text(
                    "SELECT id, key_version, nonce, ciphertext "
                    "FROM documents WHERE tenant_id = :tid ORDER BY created_at ASC LIMIT 1"
                ),
                {"tid": str(acme_id)},
            )
        ).fetchone()

        if doc_row and doc_row.ciphertext and doc_row.nonce:
            try:
                dek = await CryptoService.get_dek_for_version(session, acme_id, doc_row.key_version or 1)
                _ = CryptoService.decrypt_document(
                    dek=dek,
                    ciphertext=doc_row.ciphertext,
                    nonce=doc_row.nonce,
                    tenant_id=acme_id,
                    document_id=doc_row.id,
                )
                read_status = "OK"
            except Exception as exc:
                logger.warning("Decryption of Acme document in Acme context failed: %s", exc)
                read_status = "FAILED"
        elif doc_row:
            # Document exists without encryption
            read_status = "OK"

    return {
        "target_tenant": acme_name,
        "status": read_status,
    }


# ------------------------------------------------------------------------------
# 6. GET /admin/demo/keys/state
# ------------------------------------------------------------------------------
@router.get("/state", summary="Query Demo Tenant Key Versions & Document States")
async def get_demo_keys_state(
    request: Request,
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> Dict[str, Any]:
    require_platform_admin(current_user)
    _check_lab_refusal()
    _reject_tenant_parameters(request)

    demo_id = await _resolve_demo_tenant_id()

    async with tenant_session(demo_id) as session:
        # Key versions & statuses
        key_rows = (
            await session.execute(
                text(
                    "SELECT key_version, status, created_at, retired_at "
                    "FROM tenant_keys WHERE tenant_id = :tid ORDER BY key_version ASC"
                ),
                {"tid": str(demo_id)},
            )
        ).fetchall()

        keys = [
            {
                "key_version": k.key_version,
                "status": k.status,
                "created_at": k.created_at.isoformat() if k.created_at else None,
                "retired_at": k.retired_at.isoformat() if k.retired_at else None,
            }
            for k in key_rows
        ]

        # Documents & key versions
        doc_rows = (
            await session.execute(
                text(
                    "SELECT id, title, key_version, created_at "
                    "FROM documents WHERE tenant_id = :tid ORDER BY created_at ASC"
                ),
                {"tid": str(demo_id)},
            )
        ).fetchall()

        docs = []
        for d in doc_rows:
            label = "unknown"
            if "before" in d.title.lower():
                label = "before"
            elif "after" in d.title.lower():
                label = "after"
            elif "[demo]" in d.title.lower():
                label = "demo"

            docs.append({
                "id": str(d.id),
                "title": d.title,
                "label": label,
                "key_version": d.key_version,
                "created_at": d.created_at.isoformat() if d.created_at else None,
            })

    return {
        "tenant_name": "Demo Co",
        "keys": keys,
        "documents": docs,
    }
