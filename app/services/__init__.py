"""
TenantShield Services Package
=============================
Security and business logic services:
- auth: Multi-tenant token authentication and tenant context resolution
- document_ownership: Layer A explicit application-level tenant ownership checks
- crypto: Tenant-scoped envelope encryption for sensitive documents
- rate_limiter: Tenant-aware Redis sliding window rate limiting
- metrics: Tenant isolation and operational telemetry
- security_auditor: Automated cross-tenant attack simulation and penetration testing
"""

from app.services.auth import AuthService
from app.services.document_ownership import check_document_ownership

__all__ = ["AuthService", "check_document_ownership"]
