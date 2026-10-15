"""
TenantShield - FastAPI Dependencies
===================================
Provides verified user authentication (get_current_user) and trusted,
transaction-scoped tenant database sessions (get_tenant_db).
"""

from typing import AsyncGenerator
from uuid import UUID
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import AsyncSessionLocal, set_tenant_context
from app.schemas.auth import AuthenticatedUser
from app.services.auth import AuthService

# Bearer security scheme for Authorization header
bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> AuthenticatedUser:
    """
    Dependency extracting Bearer JWT from Authorization header, verifying claims
    and cryptographic signature, and validating the active status against the
    database users table.
    """
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 1. Verify token claims and signature
    token = credentials.credentials
    payload = AuthService.verify_token(token)

    try:
        user_id = UUID(payload["user_id"])
        tenant_id = UUID(payload["tenant_id"])
        role = payload["role"]
        email = payload.get("email", "")
    except (KeyError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload structure",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 2. Validate user identity and active status against database record
    # Uses restricted application role (tenantshield_app)
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            text(
                "SELECT id, tenant_id, email, role, is_active "
                "FROM users WHERE id = :user_id AND tenant_id = :tenant_id"
            ),
            {"user_id": str(user_id), "tenant_id": str(tenant_id)},
        )
        user_row = result.fetchone()

        if user_row is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account does not exist or has been removed",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not user_row.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account is inactive or disabled",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return AuthenticatedUser(
            user_id=user_row.id,
            tenant_id=user_row.tenant_id,
            email=user_row.email,
            role=user_row.role,
        )


async def get_tenant_db(
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency yielding an AsyncSession bound to a transaction-local
    tenant context strictly derived from current_user.tenant_id.

    Security guarantees:
    - Runs under restricted role 'tenantshield_app' (NOSUPERUSER, NOBYPASSRLS).
    - Sets 'app.current_tenant_id' with is_local=true within an explicit transaction.
    - Completely ignores any client-supplied tenant ID (headers, query params, body).
    - Automatically rolls back on error and commits on clean completion.
    - Transaction-local scope guarantees zero context leakage across connection pools.
    """
    async with AsyncSessionLocal() as session:
        async with session.begin():
            # Layer B: Database Row-Level Security (RLS) enforcement
            is_rls_enabled = settings.ENABLE_DB_RLS
            # Fail-safe: Never allow RLS disable outside lab environment
            if not is_rls_enabled and settings.APP_ENV.lower() != "lab":
                is_rls_enabled = True

            if is_rls_enabled:
                await set_tenant_context(session, current_user.tenant_id)

            try:
                yield session
            except Exception:
                await session.rollback()
                raise
