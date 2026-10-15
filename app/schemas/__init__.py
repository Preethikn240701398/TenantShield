"""
TenantShield Pydantic Schemas
"""

from app.schemas.auth import LoginRequest, TokenResponse, AuthenticatedUser
from app.schemas.document import DocumentCreate, DocumentUpdate, DocumentResponse

__all__ = [
    "LoginRequest",
    "TokenResponse",
    "AuthenticatedUser",
    "DocumentCreate",
    "DocumentUpdate",
    "DocumentResponse",
]
