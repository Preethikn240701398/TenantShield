"""
TenantShield - Platform Admin Endpoints
=======================================
Protected administrative endpoints for:
1. Rotating tenant Data Encryption Keys (DEKs).
2. Crypto-shredding tenant keys (permanent cryptographic offboarding).
3. Querying per-tenant operational and telemetry metrics (request count, errors, latency).

All endpoints strictly require the 'platform_admin' role.
"""

from typing import Any, Dict, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.api.deps import get_current_user
from app.api.documents import log_security_event
from app.core.database import tenant_session
from app.schemas.auth import AuthenticatedUser
from app.services.crypto import CryptoService
from app.services.metrics import MetricsService, MetricsUnavailableError

router = APIRouter(prefix="/admin", tags=["Platform Admin"])


@router.post(
    "/keys/{tenant_id}/rotate",
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
    "/keys/{tenant_id}/shred",
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


@router.get(
    "/metrics",
    status_code=status.HTTP_200_OK,
    summary="Get Multi-Tenant Metrics",
    description=(
        "Retrieves aggregated operational metrics (requests, errors, latency) per tenant "
        "across a specified time window. Accessible only to platform administrators."
    ),
)
async def get_system_metrics(
    request: Request,
    window_minutes: int = Query(60, description="Reporting interval in minutes (1 to 1440)"),
    limit: int = Query(100, description="Maximum number of tenants to return (1 to 1000)"),
    tenant_id: Optional[UUID] = Query(None, description="Optional tenant ID filter"),
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> Dict[str, Any]:
    client_ip = request.client.host if request.client else None

    # Strict authorization: Only platform_admin permitted
    if current_user.role != "platform_admin":
        await log_security_event(
            event_type="UNAUTHORIZED_ADMIN_ACCESS",
            severity="WARNING",
            details={"endpoint": "/admin/metrics", "role": current_user.role},
            ip_address=client_ip,
            tenant_id=current_user.tenant_id,
            user_id=current_user.user_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Platform administrator privileges required.",
        )

    # Validate window and limit bounds
    if window_minutes < 1 or window_minutes > 1440:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid reporting window: window_minutes must be between 1 and 1440 minutes.",
        )
    if limit < 1 or limit > 1000:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid limit: limit must be between 1 and 1000.",
        )

    try:
        metrics_data = await MetricsService.get_aggregated_metrics(
            window_minutes=window_minutes,
            tenant_id=tenant_id,
            limit=limit,
        )
        return metrics_data
    except MetricsUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service unavailable: Redis metrics service is currently unreachable.",
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


@router.post(
    "/limiter/strategy",
    status_code=status.HTTP_200_OK,
    summary="Configure Limiter Strategy",
    description="Switches the active limiter strategy on the running server.",
)
async def set_limiter_strategy(
    payload: Dict[str, Any],
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    if current_user.role != "platform_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Platform administrator privileges required.",
        )
    strategy_name = payload.get("strategy", "request_count")
    from app.limiter.service import LimiterService
    LimiterService.set_strategy(strategy_name)
    await LimiterService.reset_all_limits()
    return {
        "status": "success",
        "active_strategy": LimiterService.get_strategy().strategy_name,
        "statement_timeout_ms": LimiterService.get_active_statement_timeout_ms(),
        "effective_config": LimiterService.get_effective_config(),
    }


@router.post(
    "/limiter/reset",
    status_code=status.HTTP_200_OK,
    summary="Reset Limiter State",
    description="Flushes all limiter and concurrency keys in Redis.",
)
async def reset_limiter_state(
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    if current_user.role != "platform_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Platform administrator privileges required.",
        )
    from app.limiter.service import LimiterService
    await LimiterService.reset_all_limits()
    return {"status": "success", "message": "All limiter keys cleared."}

