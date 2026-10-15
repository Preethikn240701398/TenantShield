"""
TenantShield - Authentication Schemas
=====================================
Pydantic models for authentication requests, responses, and validated identities.
"""

from uuid import UUID
from pydantic import BaseModel, EmailStr, Field


class LoginRequest(BaseModel):
    """Credentials required for password-based login."""
    email: str = Field(
        ...,
        min_length=3,
        max_length=255,
        description="User's registered email address",
        examples=["acme_user@acme.test"],
    )
    password: str = Field(
        ...,
        min_length=1,
        description="Plaintext password to authenticate",
        examples=["AcmeSecretPassword123!"],
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "email": "acme_user@acme.test",
                    "password": "AcmeSecretPassword123!",
                }
            ]
        }
    }


class TokenResponse(BaseModel):
    """Signed JWT token response model."""
    access_token: str = Field(..., description="Signed JSON Web Token")
    token_type: str = Field(default="bearer", description="Token scheme")
    expires_in: int = Field(..., description="Lifetime of token in seconds")


class AuthenticatedUser(BaseModel):
    """Trusted server-side user identity derived from verified token and database record."""
    user_id: UUID
    tenant_id: UUID
    email: str
    role: str
