"""
TenantShield - Document Workspace Endpoints
===========================================
Protected multi-tenant document endpoints demonstrating trusted tenant context
enforcement via get_tenant_db and PostgreSQL Row-Level Security.
"""

from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_tenant_db
from app.schemas.auth import AuthenticatedUser

router = APIRouter(prefix="/documents", tags=["Documents"])


class DocumentResponse(BaseModel):
    id: UUID
    tenant_id: UUID
    title: str
    content: str


class DocumentCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=255)
    content: str = Field(...)


@router.get(
    "",
    response_model=List[DocumentResponse],
    summary="List Tenant Documents",
    description="Returns confidential workspace documents belonging strictly to the authenticated tenant.",
)
async def list_documents(
    # Client may attempt to supply spoofed tenant IDs; they are strictly ignored
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID", description="Ignored by server"),
    tenant_id_query: Optional[str] = Query(None, alias="tenant_id", description="Ignored by server"),
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_tenant_db),
) -> List[DocumentResponse]:
    """
    Executes under restricted role tenantshield_app with transaction-scoped
    'app.current_tenant_id' set exclusively from current_user.tenant_id.
    Combines application-level tenant filter with PostgreSQL Row-Level Security.
    """
    result = await db.execute(
        text(
            "SELECT id, tenant_id, title, content FROM documents "
            "WHERE tenant_id = :tenant_id ORDER BY created_at ASC"
        ),
        {"tenant_id": str(current_user.tenant_id)},
    )
    rows = result.fetchall()
    return [
        DocumentResponse(
            id=row.id,
            tenant_id=row.tenant_id,
            title=row.title,
            content=row.content,
        )
        for row in rows
    ]


@router.post(
    "",
    response_model=DocumentResponse,
    status_code=201,
    summary="Create Tenant Document",
    description="Creates a new document stamped strictly with the authenticated user's tenant ID.",
)
async def create_document(
    doc: DocumentCreate,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_tenant_db),
) -> DocumentResponse:
    """
    Creates a new document. Tenant ID is injected from current_user.tenant_id.
    PostgreSQL RLS WITH CHECK ensures tenant_id matches the active transaction context.
    """
    result = await db.execute(
        text(
            "INSERT INTO documents (tenant_id, owner_id, title, content) "
            "VALUES (:tenant_id, :owner_id, :title, :content) "
            "RETURNING id, tenant_id, title, content"
        ),
        {
            "tenant_id": str(current_user.tenant_id),
            "owner_id": str(current_user.user_id),
            "title": doc.title,
            "content": doc.content,
        },
    )
    row = result.fetchone()
    return DocumentResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        title=row.title,
        content=row.content,
    )


@router.get(
    "/{document_id}",
    response_model=DocumentResponse,
    summary="Get Tenant Document",
    description="Retrieves a single document belonging to the authenticated tenant.",
)
async def get_document(
    document_id: UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_tenant_db),
) -> DocumentResponse:
    """
    Demonstrates defense-in-depth: combines application-level tenant check
    (WHERE id = :id AND tenant_id = :tenant_id) with database-level PostgreSQL Row-Level Security.
    """
    result = await db.execute(
        text(
            "SELECT id, tenant_id, title, content FROM documents "
            "WHERE id = :document_id AND tenant_id = :tenant_id"
        ),
        {
            "document_id": str(document_id),
            "tenant_id": str(current_user.tenant_id),
        },
    )
    row = result.fetchone()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )
    return DocumentResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        title=row.title,
        content=row.content,
    )
