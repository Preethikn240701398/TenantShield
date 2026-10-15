"""
TenantShield - Authentication Endpoints
=======================================
Handles password-based authentication (POST /auth/login) and identity inspection (GET /auth/me).
"""

import json
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.database import AsyncSessionLocal
from app.schemas.auth import AuthenticatedUser, LoginRequest, TokenResponse
from app.services.auth import AuthService

router = APIRouter(prefix="/auth", tags=["Authentication"])


async def log_security_event(
    event_type: str,
    severity: str,
    details: dict,
    ip_address: str | None = None,
    tenant_id: str | None = None,
    user_id: str | None = None,
) -> None:
    """Safely logs an authentication audit event to the security_events table."""
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
        # Prevent audit logging failure from breaking core auth flow
        pass


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Password-Based Login",
    description="Authenticates tenant user or platform admin credentials and returns a signed JWT.",
)
async def login(credentials: LoginRequest, request: Request) -> TokenResponse:
    """
    Validates user credentials against stored Argon2id hashes.
    Returns HTTP 401 with generic message on any mismatch to prevent user enumeration.
    Logs audit events for success and failure to security_events.
    """
    client_ip = request.client.host if request.client else None
    sanitized_email = credentials.email.lower().strip()

    # 1. Query user record by email using restricted application role
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            text(
                "SELECT id, tenant_id, email, hashed_password, role, is_active "
                "FROM users WHERE email = :email"
            ),
            {"email": sanitized_email},
        )
        user_row = result.fetchone()

    # 2. Constant-time / generic failure handling
    if user_row is None:
        # Dummy verify to mitigate timing attacks
        AuthService.verify_password("dummy_password", "$argon2id$v=19$m=65536,t=3,p=4$dummy$dummy")
        await log_security_event(
            event_type="LOGIN_FAILURE",
            severity="WARNING",
            details={"email": sanitized_email, "reason": "user_not_found"},
            ip_address=client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 3. Verify Argon2id password hash
    is_valid = AuthService.verify_password(credentials.password, user_row.hashed_password)
    if not is_valid or not user_row.is_active:
        await log_security_event(
            event_type="LOGIN_FAILURE",
            severity="WARNING",
            details={
                "email": sanitized_email,
                "reason": "invalid_credentials" if not is_valid else "account_disabled",
            },
            ip_address=client_ip,
            tenant_id=user_row.tenant_id,
            user_id=user_row.id,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 4. Generate signed JWT token embedding verified claims
    token, expires_in = AuthService.create_access_token(
        user_id=user_row.id,
        tenant_id=user_row.tenant_id,
        role=user_row.role,
        email=user_row.email,
    )

    # 5. Log successful authentication event
    await log_security_event(
        event_type="LOGIN_SUCCESS",
        severity="INFO",
        details={"email": user_row.email, "role": user_row.role},
        ip_address=client_ip,
        tenant_id=user_row.tenant_id,
        user_id=user_row.id,
    )

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=expires_in,
    )


@router.get(
    "/me",
    response_model=AuthenticatedUser,
    summary="Current User Identity",
    description="Returns the verified identity of the authenticated user.",
)
async def get_me(current_user: AuthenticatedUser = Depends(get_current_user)) -> AuthenticatedUser:
    """Returns validated server-side identity for current request token."""
    return current_user
