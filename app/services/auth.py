"""
TenantShield - Authentication Service (Stub)
============================================
FUTURE IMPLEMENTATION:
This module will handle multi-tenant authentication, including:
1. Tenant-scoped JWT token creation and verification.
2. Tenant context extraction from Authorization headers or API keys.
3. User password hashing and credential verification using argon2 or bcrypt.
4. Setting PostgreSQL session variables ('app.current_tenant_id') for RLS.

NOTE: This feature is planned for future implementation and is not yet active.
"""

from dataclasses import dataclass
from typing import Optional
from uuid import UUID


@dataclass
class TenantContext:
    """Represents the validated tenant identity extracted from the request token."""
    tenant_id: UUID
    user_id: UUID
    role: str
    email: str


class AuthService:
    """Authentication and tenant identity resolution service."""

    @classmethod
    async def create_access_token(cls, tenant_id: UUID, user_id: UUID, role: str) -> str:
        """
        Create a cryptographically signed JWT token embedding tenant_id and user_id.
        Planned for upcoming iteration.
        """
        raise NotImplementedError("AuthService.create_access_token is not yet implemented.")

    @classmethod
    async def verify_token(cls, token: str) -> TenantContext:
        """
        Verify incoming JWT signature, validate tenant status, and return TenantContext.
        Planned for upcoming iteration.
        """
        raise NotImplementedError("AuthService.verify_token is not yet implemented.")

    @classmethod
    async def hash_password(cls, plain_password: str) -> str:
        """
        Securely hash user credentials.
        Planned for upcoming iteration.
        """
        raise NotImplementedError("AuthService.hash_password is not yet implemented.")
