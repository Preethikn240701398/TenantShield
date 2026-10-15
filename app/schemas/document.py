"""
TenantShield - Document Schemas
===============================
Pydantic validation schemas for document workspace requests and responses.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID
from pydantic import BaseModel, Field


class DocumentCreate(BaseModel):
    """Payload for creating a new document within authenticated tenant context."""
    title: str = Field(..., min_length=1, max_length=255, description="Document title")
    content: str = Field(..., min_length=1, description="Document body content")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "title": "Quarterly Security Architecture",
                    "content": "Confidential security review and architectural controls.",
                }
            ]
        }
    }


class DocumentUpdate(BaseModel):
    """Payload for updating an existing document."""
    title: Optional[str] = Field(None, min_length=1, max_length=255, description="Updated document title")
    content: Optional[str] = Field(None, min_length=1, description="Updated document content")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "title": "Quarterly Security Architecture (Revised)",
                    "content": "Updated security review with verified RLS enforcement.",
                }
            ]
        }
    }


class DocumentResponse(BaseModel):
    """Document representation model returned to clients."""
    id: UUID
    tenant_id: UUID
    owner_id: Optional[UUID] = None
    title: str
    content: str
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
