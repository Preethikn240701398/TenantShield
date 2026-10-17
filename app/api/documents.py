"""
TenantShield - Document Workspace Endpoints
===========================================
Protected multi-tenant document endpoints demonstrating dual-layer defense:
- Layer A: Service-layer application ownership checks (check_document_ownership).
- Layer B: PostgreSQL Row-Level Security (RLS) with transaction-local context.
- Security event audit logging on all unauthorized or spoofed access attempts.
"""

import json
from typing import List, Optional
import uuid
from uuid import UUID
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_tenant_db
from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.schemas.auth import AuthenticatedUser
from app.schemas.document import DocumentCreate, DocumentResponse, DocumentUpdate
from app.services.crypto import (
    CryptoAuthenticationError,
    CryptoKeyNotFoundError,
    CryptoService,
    CryptoShreddedError,
)
from app.services.document_ownership import check_document_ownership

router = APIRouter(prefix="/documents", tags=["Documents"])


async def log_security_event(
    event_type: str,
    severity: str,
    details: dict,
    ip_address: Optional[str] = None,
    tenant_id: Optional[UUID] = None,
    user_id: Optional[UUID] = None,
) -> None:
    """
    Safely writes an audit event to security_events in an independent transaction.
    Guarantees that document transaction state or rollbacks do not affect audit integrity.
    Never logs document content, secrets, or passwords.
    """
    try:
        async with AsyncSessionLocal() as session:
            async with session.begin():
                await session.execute(
                    text(
                        "INSERT INTO security_events (tenant_id, user_id, event_type, severity, details, ip_address) "
                        "VALUES (:tenant_id, :user_id, :event_type, :severity, :details, :ip_address)"
                    ),
                    {
                        "tenant_id": str(tenant_id) if tenant_id else None,
                        "user_id": str(user_id) if user_id else None,
                        "event_type": event_type,
                        "severity": severity,
                        "details": json.dumps(details),
                        "ip_address": ip_address,
                    },
                )
    except Exception:
        # Non-blocking: Audit logging errors must not break application flow
        pass


@router.post(
    "",
    response_model=DocumentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Tenant Document",
    description="Creates a new document stamped strictly with the authenticated user's tenant ID.",
)
async def create_document(
    doc: DocumentCreate,
    request: Request,
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID", description="Ignored by authorization"),
    tenant_id_query: Optional[str] = Query(None, alias="tenant_id", description="Ignored by authorization"),
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_tenant_db),
) -> DocumentResponse:
    """
    Creates a new document. Tenant ID is derived exclusively from current_user.tenant_id.
    Encrypts content with tenant's active DEK and deterministic AAD binding tenant and document IDs.
    PostgreSQL RLS WITH CHECK ensures tenant_id matches the active transaction context.
    """
    client_ip = request.client.host if request.client else None

    # Audit log any client spoofing attempts
    if (x_tenant_id and str(x_tenant_id) != str(current_user.tenant_id)) or (
        tenant_id_query and str(tenant_id_query) != str(current_user.tenant_id)
    ):
        await log_security_event(
            event_type="TENANT_SPOOFING_ATTEMPT",
            severity="WARNING",
            details={
                "endpoint": "/documents",
                "method": "POST",
                "spoofed_header": x_tenant_id,
                "spoofed_query": tenant_id_query,
            },
            ip_address=client_ip,
            tenant_id=current_user.tenant_id,
            user_id=current_user.user_id,
        )

    doc_id = uuid.uuid4()
    key_version, dek = await CryptoService.get_or_create_active_dek(db, current_user.tenant_id)
    doc_nonce, ciphertext = CryptoService.encrypt_document(
        dek=dek,
        plaintext=doc.content,
        tenant_id=current_user.tenant_id,
        document_id=doc_id,
    )

    result = await db.execute(
        text(
            "INSERT INTO documents (id, tenant_id, owner_id, title, key_version, nonce, ciphertext) "
            "VALUES (:id, :tenant_id, :owner_id, :title, :key_version, :nonce, :ciphertext) "
            "RETURNING id, tenant_id, owner_id, title, created_at, updated_at"
        ),
        {
            "id": str(doc_id),
            "tenant_id": str(current_user.tenant_id),
            "owner_id": str(current_user.user_id),
            "title": doc.title,
            "key_version": key_version,
            "nonce": doc_nonce,
            "ciphertext": ciphertext,
        },
    )
    row = result.fetchone()
    return DocumentResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        owner_id=row.owner_id,
        title=row.title,
        content=doc.content,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


@router.get(
    "",
    response_model=List[DocumentResponse],
    summary="List Tenant Documents",
    description="Returns confidential workspace documents belonging strictly to the authenticated tenant.",
)
async def list_documents(
    request: Request,
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID", description="Ignored by authorization"),
    tenant_id_query: Optional[str] = Query(None, alias="tenant_id", description="Ignored by authorization"),
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_tenant_db),
) -> List[DocumentResponse]:
    """
    Lists documents for the authenticated tenant.
    Combines application-level tenant filter with PostgreSQL Row-Level Security.
    Decrypts each authorized document using its recorded key version and deterministic AAD.
    """
    client_ip = request.client.host if request.client else None

    # Audit log spoofing attempts
    if (x_tenant_id and str(x_tenant_id) != str(current_user.tenant_id)) or (
        tenant_id_query and str(tenant_id_query) != str(current_user.tenant_id)
    ):
        await log_security_event(
            event_type="TENANT_SPOOFING_ATTEMPT",
            severity="WARNING",
            details={
                "endpoint": "/documents",
                "method": "GET",
                "spoofed_header": x_tenant_id,
                "spoofed_query": tenant_id_query,
            },
            ip_address=client_ip,
            tenant_id=current_user.tenant_id,
            user_id=current_user.user_id,
        )

    # Layer C: query-level tenant filter (disabled only in lab mode experiments)
    use_query_filter = settings.ENABLE_QUERY_TENANT_FILTER
    if not use_query_filter and settings.APP_ENV.lower() != "lab":
        use_query_filter = True  # fail-safe outside lab

    if use_query_filter:
        result = await db.execute(
            text(
                "SELECT id, tenant_id, owner_id, title, key_version, nonce, ciphertext, created_at, updated_at "
                "FROM documents WHERE tenant_id = :tenant_id ORDER BY created_at ASC"
            ),
            {"tenant_id": str(current_user.tenant_id)},
        )
    else:
        result = await db.execute(
            text(
                "SELECT id, tenant_id, owner_id, title, key_version, nonce, ciphertext, created_at, updated_at "
                "FROM documents ORDER BY created_at ASC"
            )
        )
    rows = result.fetchall()

    visible_docs = []
    for row in rows:
        try:
            check_document_ownership(row.tenant_id, current_user.tenant_id, row.id)

            # Decrypt ciphertext
            if row.ciphertext is not None and row.nonce is not None:
                try:
                    dek = await CryptoService.get_dek_for_version(db, current_user.tenant_id, row.key_version or 1)
                    content = CryptoService.decrypt_document(
                        dek=dek,
                        ciphertext=row.ciphertext,
                        nonce=row.nonce,
                        tenant_id=current_user.tenant_id,
                        document_id=row.id,
                    )
                except (CryptoShreddedError, CryptoKeyNotFoundError, CryptoAuthenticationError):
                    # Shredded or invalid document; omit safely from active listing without crashing
                    continue
            else:
                content = ""

            visible_docs.append(
                DocumentResponse(
                    id=row.id,
                    tenant_id=row.tenant_id,
                    owner_id=row.owner_id,
                    title=row.title,
                    content=content,
                    created_at=row.created_at,
                    updated_at=row.updated_at,
                )
            )
        except HTTPException:
            # Layer A filtered cross-tenant row
            await log_security_event(
                event_type="UNAUTHORIZED_ACCESS_DENIED",
                severity="WARNING",
                details={
                    "endpoint": "/documents",
                    "operation": "list",
                    "target_document_id": str(row.id),
                    "reason": "cross_tenant_ownership_violation",
                },
                ip_address=client_ip,
                tenant_id=current_user.tenant_id,
                user_id=current_user.user_id,
            )

    return visible_docs


@router.get(
    "/{document_id}",
    response_model=DocumentResponse,
    summary="Get Tenant Document",
    description="Retrieves a single document belonging to the authenticated tenant.",
)
async def get_document(
    document_id: UUID,
    request: Request,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_tenant_db),
) -> DocumentResponse:
    """
    Retrieves one document. Enforces Layer A (check_document_ownership), Layer B (PostgreSQL RLS),
    and decrypts content using the document's key version and deterministic AAD.
    """
    client_ip = request.client.host if request.client else None

    result = await db.execute(
        text(
            "SELECT id, tenant_id, owner_id, title, key_version, nonce, ciphertext, created_at, updated_at "
            "FROM documents WHERE id = :document_id"
        ),
        {"document_id": str(document_id)},
    )
    row = result.fetchone()

    if row is None:
        # Blocked by RLS (0 rows returned) or document does not exist
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )

    # Layer A Check
    try:
        check_document_ownership(row.tenant_id, current_user.tenant_id, row.id)
    except HTTPException:
        await log_security_event(
            event_type="UNAUTHORIZED_ACCESS_DENIED",
            severity="WARNING",
            details={
                "endpoint": f"/documents/{document_id}",
                "operation": "get",
                "target_document_id": str(document_id),
                "reason": "cross_tenant_ownership_violation",
            },
            ip_address=client_ip,
            tenant_id=current_user.tenant_id,
            user_id=current_user.user_id,
        )
        raise

    # Decrypt document content
    if row.ciphertext is not None and row.nonce is not None:
        try:
            dek = await CryptoService.get_dek_for_version(db, current_user.tenant_id, row.key_version or 1)
            content = CryptoService.decrypt_document(
                dek=dek,
                ciphertext=row.ciphertext,
                nonce=row.nonce,
                tenant_id=current_user.tenant_id,
                document_id=row.id,
            )
        except (CryptoShreddedError, CryptoKeyNotFoundError, CryptoAuthenticationError) as exc:
            # Key shredded or authentication failed -> fail safely without revealing cryptographic internals
            await log_security_event(
                event_type="DOCUMENT_DECRYPTION_FAILED",
                severity="WARNING",
                details={
                    "endpoint": f"/documents/{document_id}",
                    "operation": "get",
                    "target_document_id": str(document_id),
                    "reason": exc.__class__.__name__,
                },
                ip_address=client_ip,
                tenant_id=current_user.tenant_id,
                user_id=current_user.user_id,
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Document not found",
            )
    else:
        content = ""

    return DocumentResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        owner_id=row.owner_id,
        title=row.title,
        content=content,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


@router.put(
    "/{document_id}",
    response_model=DocumentResponse,
    summary="Update Tenant Document",
    description="Updates title or content of an existing document belonging to the authenticated tenant.",
)
async def update_document(
    document_id: UUID,
    doc_update: DocumentUpdate,
    request: Request,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_tenant_db),
) -> DocumentResponse:
    """
    Updates an existing document. Enforces Layer A and Layer B before applying mutations.
    If content is modified, encrypts with tenant's active DEK and deterministic AAD.
    """
    client_ip = request.client.host if request.client else None

    # 1. Fetch document to verify ownership
    result = await db.execute(
        text(
            "SELECT id, tenant_id, owner_id, title, key_version, nonce, ciphertext, created_at, updated_at "
            "FROM documents WHERE id = :document_id"
        ),
        {"document_id": str(document_id)},
    )
    row = result.fetchone()

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )

    # 2. Layer A Check
    try:
        check_document_ownership(row.tenant_id, current_user.tenant_id, row.id)
    except HTTPException:
        await log_security_event(
            event_type="UNAUTHORIZED_ACCESS_DENIED",
            severity="WARNING",
            details={
                "endpoint": f"/documents/{document_id}",
                "operation": "update",
                "target_document_id": str(document_id),
                "reason": "cross_tenant_ownership_violation",
            },
            ip_address=client_ip,
            tenant_id=current_user.tenant_id,
            user_id=current_user.user_id,
        )
        raise

    # 3. Apply updates
    new_title = doc_update.title if doc_update.title is not None else row.title

    if doc_update.content is not None:
        key_version, dek = await CryptoService.get_or_create_active_dek(db, current_user.tenant_id)
        doc_nonce, ciphertext = CryptoService.encrypt_document(
            dek=dek,
            plaintext=doc_update.content,
            tenant_id=current_user.tenant_id,
            document_id=document_id,
        )
        decrypted_content = doc_update.content
    else:
        key_version = row.key_version
        doc_nonce = row.nonce
        ciphertext = row.ciphertext
        if ciphertext is not None and doc_nonce is not None:
            try:
                dek = await CryptoService.get_dek_for_version(db, current_user.tenant_id, key_version or 1)
                decrypted_content = CryptoService.decrypt_document(
                    dek=dek,
                    ciphertext=ciphertext,
                    nonce=doc_nonce,
                    tenant_id=current_user.tenant_id,
                    document_id=document_id,
                )
            except Exception:
                decrypted_content = ""
        else:
            decrypted_content = ""

    update_result = await db.execute(
        text(
            "UPDATE documents "
            "SET title = :title, key_version = :key_version, nonce = :nonce, ciphertext = :ciphertext, updated_at = CURRENT_TIMESTAMP "
            "WHERE id = :document_id AND tenant_id = :tenant_id "
            "RETURNING id, tenant_id, owner_id, title, created_at, updated_at"
        ),
        {
            "document_id": str(document_id),
            "tenant_id": str(current_user.tenant_id),
            "title": new_title,
            "key_version": key_version,
            "nonce": doc_nonce,
            "ciphertext": ciphertext,
        },
    )
    updated_row = update_result.fetchone()
    if updated_row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )
    return DocumentResponse(
        id=updated_row.id,
        tenant_id=updated_row.tenant_id,
        owner_id=updated_row.owner_id,
        title=updated_row.title,
        content=decrypted_content,
        created_at=updated_row.created_at,
        updated_at=updated_row.updated_at,
    )


@router.delete(
    "/{document_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete Tenant Document",
    description="Deletes an existing document belonging to the authenticated tenant.",
)
async def delete_document(
    document_id: UUID,
    request: Request,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_tenant_db),
) -> Response:
    """
    Deletes an existing document. Enforces Layer A and Layer B before deleting.
    """
    client_ip = request.client.host if request.client else None

    # 1. Fetch document to verify ownership
    result = await db.execute(
        text("SELECT id, tenant_id FROM documents WHERE id = :document_id"),
        {"document_id": str(document_id)},
    )
    row = result.fetchone()

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )

    # 2. Layer A Check
    try:
        check_document_ownership(row.tenant_id, current_user.tenant_id, row.id)
    except HTTPException:
        await log_security_event(
            event_type="UNAUTHORIZED_ACCESS_DENIED",
            severity="WARNING",
            details={
                "endpoint": f"/documents/{document_id}",
                "operation": "delete",
                "target_document_id": str(document_id),
                "reason": "cross_tenant_ownership_violation",
            },
            ip_address=client_ip,
            tenant_id=current_user.tenant_id,
            user_id=current_user.user_id,
        )
        raise

    # 3. Delete document
    del_res = await db.execute(
        text("DELETE FROM documents WHERE id = :document_id AND tenant_id = :tenant_id"),
        {
            "document_id": str(document_id),
            "tenant_id": str(current_user.tenant_id),
        },
    )
    if del_res.rowcount == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
