"""
TenantShield - Platform Admin Key Lifecycle Endpoints
=====================================================
Protected administrative endpoints for:
- Rotating tenant Data Encryption Keys (DEKs).
- Crypto-shredding tenant keys (permanent cryptographic offboarding).
Only accessible to users with the 'platform_admin' role.
"""

from typing import Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.api.deps import get_current_user
from app.api.documents import log_security_event
from app.core.database import tenant_session
from app.schemas.auth import AuthenticatedUser
from app.services.crypto import CryptoService

router = APIRouter(prefix="/admin/keys", tags=["Admin Key Lifecycle"])


@router.post(
    "/{tenant_id}/rotate",
    status_code=status.HTTP_200_OK,
    summary="Rotate Tenant DEK",
    description="Retires the active DEK for a tenant and provisions version N+1. Requires platform_admin role.",
)
async def rotate_tenant_key(
    tenant_id: UUID,
    request: Request,
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    client_ip = request.client.host if request.client else None

    if current_user.role != "platform_admin":
        await log_security_event(
            event_type="UNAUTHORIZED_ADMIN_ACCESS",
            severity="WARNING",
            details={"endpoint": f"/admin/keys/{tenant_id}/rotate", "role": current_user.role},
            ip_address=client_ip,
            tenant_id=current_user.tenant_id,
            user_id=current_user.user_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Platform administrator privileges required.",
        )

    # Set transaction-scoped tenant context to the target tenant to satisfy RLS on tenant_keys
    async with tenant_session(tenant_id) as session:
        new_version = await CryptoService.rotate_tenant_dek(session, tenant_id)

    await log_security_event(
        event_type="KEY_ROTATION_COMPLETED",
        severity="INFO",
        details={"tenant_id": str(tenant_id), "new_key_version": new_version},
        ip_address=client_ip,
        tenant_id=tenant_id,
        user_id=current_user.user_id,
    )

    return {
        "status": "rotated",
        "tenant_id": str(tenant_id),
        "new_key_version": new_version,
    }


@router.post(
    "/{tenant_id}/shred",
    status_code=status.HTTP_200_OK,
    summary="Crypto-Shred Tenant Key",
    description="Permanently nullifies wrapped key material for a tenant. Requires platform_admin role.",
)
async def shred_tenant_key(
    tenant_id: UUID,
    request: Request,
    key_version: Optional[int] = Query(None, description="Specific key version to destroy; if omitted, destroys all keys for tenant"),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    client_ip = request.client.host if request.client else None

    if current_user.role != "platform_admin":
        await log_security_event(
            event_type="UNAUTHORIZED_ADMIN_ACCESS",
            severity="WARNING",
            details={"endpoint": f"/admin/keys/{tenant_id}/shred", "role": current_user.role},
            ip_address=client_ip,
            tenant_id=current_user.tenant_id,
            user_id=current_user.user_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Platform administrator privileges required.",
        )

    # Set transaction-scoped tenant context to the target tenant to satisfy RLS on tenant_keys
    async with tenant_session(tenant_id) as session:
        shredded_count = await CryptoService.crypto_shred_tenant_dek(session, tenant_id, key_version)

    await log_security_event(
        event_type="CRYPTO_SHRED_COMPLETED",
        severity="CRITICAL",
        details={
            "tenant_id": str(tenant_id),
            "key_version": key_version,
            "keys_destroyed": shredded_count,
        },
        ip_address=client_ip,
        tenant_id=tenant_id,
        user_id=current_user.user_id,
    )

    return {
        "status": "destroyed",
        "tenant_id": str(tenant_id),
        "key_version": key_version,
        "keys_destroyed": shredded_count,
    }
