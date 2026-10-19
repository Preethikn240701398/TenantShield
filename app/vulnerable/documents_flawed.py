"""
TenantShield - Intentionally Flawed / Vulnerable Endpoints
==========================================================
LOCATION: app/vulnerable/documents_flawed.py

PURPOSE:
Educational demonstration module showing common multi-tenant architectural mistakes:
- ❌ OMITTED: check_document_ownership() (OWASP API1: Broken Object Level Authorization / IDOR)
- ❌ OMITTED: WHERE tenant_id = :current_tenant_id scoping in SQL
- ❌ OMITTED: Setting session-level PostgreSQL RLS context

This file allows judges and security auditors to contrast the hardened
TenantShield defense-in-depth architecture (app/api/documents.py) with typical
vulnerable multi-tenant implementations.
"""

from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.config import settings
from app.schemas.auth import AuthenticatedUser
from app.schemas.document import DocumentResponse, DocumentUpdate
from app.services.crypto import CryptoService
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

logger = logging.getLogger("tenantshield.vulnerable")

# Simulate standard unhardened database pool (without RLS enforcement)
_raw_admin_url = getattr(settings, "POSTGRES_ADMIN_URL", None) or os.getenv("POSTGRES_ADMIN_URL", "")
_vuln_db_url = _raw_admin_url.replace("postgresql+psycopg://", "postgresql+asyncpg://").replace("postgresql://", "postgresql+asyncpg://") if _raw_admin_url else settings.DATABASE_URL
_vuln_engine = create_async_engine(_vuln_db_url, pool_pre_ping=True)
AsyncFlawedSessionLocal = async_sessionmaker(bind=_vuln_engine, autocommit=False, autoflush=False, expire_on_commit=False)

router = APIRouter(prefix="/vulnerable/documents", tags=["Vulnerable Demo Endpoints"])


@router.get(
    "/{document_id}",
    summary="[VULNERABLE] Read Document Without Ownership Verification",
    description="Intentionally flawed endpoint: Missing Layer A ownership check and tenant filter. Demonstrates cross-tenant data leak.",
)
async def vulnerable_get_document(
    document_id: UUID,
    request: Request,
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    ❌ CRITICAL FLAW 1: Queries documents solely by document_id without filtering tenant_id.
    ❌ CRITICAL FLAW 2: Never invokes check_document_ownership().
    ❌ CRITICAL FLAW 3: Connects directly without RLS tenant context.
    """
    async with AsyncFlawedSessionLocal() as session:
        # FLAW: Query lacks "AND tenant_id = :tenant_id"
        result = await session.execute(
            text(
                "SELECT id, tenant_id, owner_id, title, key_version, nonce, ciphertext, created_at, updated_at "
                "FROM documents WHERE id = :doc_id"
            ),
            {"doc_id": str(document_id)},
        )
        row = result.fetchone()

        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Document not found",
            )

        # ❌ FLAW: Did NOT call check_document_ownership(row.tenant_id, current_user.tenant_id, row.id)
        # ❌ The attacker belongs to current_user.tenant_id, but the document belongs to row.tenant_id!

        content = ""
        if row.ciphertext is not None and row.nonce is not None:
            try:
                # Decrypt using document's tenant DEK
                dek = await CryptoService.get_dek_for_version(session, row.tenant_id, row.key_version or 1)
                content = CryptoService.decrypt_document(
                    dek=dek,
                    ciphertext=row.ciphertext,
                    nonce=row.nonce,
                    tenant_id=row.tenant_id,
                    document_id=row.id,
                )
            except Exception as dec_err:
                content = f"[DECRYPT_FAILED: {dec_err}]"

        return {
            "id": str(row.id),
            "tenant_id": str(row.tenant_id),
            "owner_id": str(row.owner_id),
            "title": row.title,
            "content": content,
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "updated_at": row.updated_at.isoformat() if row.updated_at else None,
            "_security_warning": "LEAK DETECTED: Returned across tenant boundary without ownership verification!",
            "_requested_by_tenant": str(current_user.tenant_id),
            "_document_actual_tenant": str(row.tenant_id),
        }


@router.put(
    "/{document_id}",
    summary="[VULNERABLE] Update Document Across Tenant Boundary",
)
async def vulnerable_update_document(
    document_id: UUID,
    doc_update: DocumentUpdate,
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    ❌ FLAW: Updates victim document without verifying that caller owns the document!
    """
    async with AsyncFlawedSessionLocal() as session:
        async with session.begin():
            # Check document existence without tenant scoping
            res = await session.execute(
                text("SELECT id, tenant_id FROM documents WHERE id = :doc_id"),
                {"doc_id": str(document_id)},
            )
            row = res.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Document not found")

            # ❌ FLAW: Caller (Attacker) overwrites Victim's document!
            key_version, dek = await CryptoService.get_or_create_active_dek(session, row.tenant_id)
            doc_nonce, ciphertext = CryptoService.encrypt_document(
                dek=dek,
                plaintext=doc_update.content,
                tenant_id=row.tenant_id,
                document_id=row.id,
            )

            await session.execute(
                text(
                    "UPDATE documents SET title = :title, ciphertext = :ciphertext, nonce = :nonce, "
                    "key_version = :key_version, updated_at = :updated_at WHERE id = :doc_id"
                ),
                {
                    "doc_id": str(document_id),
                    "title": doc_update.title,
                    "ciphertext": ciphertext,
                    "nonce": doc_nonce,
                    "key_version": key_version,
                    "updated_at": datetime.now(timezone.utc),
                },
            )

            return {
                "id": str(document_id),
                "title": doc_update.title,
                "content": doc_update.content,
                "status": "TAMPERED_BY_ATTACKER",
                "_security_warning": "TAMPER LEAK: Foreign tenant modified victim record!",
            }


@router.delete(
    "/{document_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="[VULNERABLE] Delete Document Across Tenant Boundary",
)
async def vulnerable_delete_document(
    document_id: UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> Response:
    """
    ❌ FLAW: Deletes victim document without verifying caller identity!
    """
    async with AsyncFlawedSessionLocal() as session:
        async with session.begin():
            res = await session.execute(
                text("DELETE FROM documents WHERE id = :doc_id"),
                {"doc_id": str(document_id)},
            )
            if res.rowcount == 0:
                raise HTTPException(status_code=404, detail="Document not found")
            return Response(status_code=status.HTTP_204_NO_CONTENT)
