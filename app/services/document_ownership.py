"""
TenantShield - Document Ownership Service (Layer A Defense)
==========================================================
Provides explicit application-layer tenant ownership verification for documents.
Enforces that authenticated tenants can only access, modify, or delete their
own documents. Controlled in lab environments via ENABLE_APP_OWNERSHIP_CHECK.
"""

import logging
from uuid import UUID
from fastapi import HTTPException, status
from app.core.config import settings

logger = logging.getLogger(__name__)


def check_document_ownership(
    document_tenant_id: UUID | str,
    user_tenant_id: UUID | str,
    document_id: UUID | str | None = None,
) -> bool:
    """
    Layer A Defense: Compares document tenant ID with the authenticated user's trusted tenant ID.

    Security Rules:
    - When ENABLE_APP_OWNERSHIP_CHECK is True:
        If document_tenant_id != user_tenant_id, raises HTTP 404 (Document not found)
        to prevent resource enumeration and cross-tenant data leakage.
    - When ENABLE_APP_OWNERSHIP_CHECK is False (permissible ONLY when APP_ENV='lab'):
        Bypasses the application-level check, allowing experimental evaluation of
        database-level Row-Level Security (Layer B) in isolation.
    - If ENABLE_APP_OWNERSHIP_CHECK is False outside APP_ENV='lab', the check is
        strictly re-enforced as a fail-safe defense.
    """
    is_check_enabled = settings.ENABLE_APP_OWNERSHIP_CHECK

    # Fail-safe: Never allow bypass outside lab environment
    if not is_check_enabled and settings.APP_ENV.lower() != "lab":
        is_check_enabled = True

    if not is_check_enabled:
        logger.warning(
            f"[LAB MODE EXPERIMENT] Layer A Application Ownership Check is DISABLED. "
            f"Relying solely on Layer B (Database RLS). Target document: {document_id}"
        )
        return True

    doc_tid_str = str(document_tenant_id).strip()
    user_tid_str = str(user_tenant_id).strip()

    if doc_tid_str != user_tid_str:
        logger.warning(
            f"[SECURITY ALERT] Layer A blocked cross-tenant access attempt. "
            f"User Tenant: {user_tid_str} tried to access Document Tenant: {doc_tid_str} (Doc: {document_id})"
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )

    return True
