"""
TenantShield - Base API Endpoints
=================================
Contains baseline route handlers including GET / and GET /health.
Decoupled from direct database driver details via app.core.database.
"""

from datetime import datetime, timezone
from fastapi import APIRouter
from app.core.config import settings
from app.core.database import check_db_health

router = APIRouter()


@router.get(
    "/",
    summary="Root Endpoint",
    description="Returns general metadata about the TenantShield workspace API.",
    tags=["System"],
)
async def root() -> dict:
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "online",
        "docs_url": "/docs",
        "message": "TenantShield Secure Multi-Tenant SaaS Workspace API is operational.",
    }


@router.get(
    "/health",
    summary="Health Check",
    description="Reports the service operational health and database connectivity state.",
    tags=["System"],
)
async def health_check() -> dict:
    db_status = await check_db_health()
    db_healthy = db_status["status"] == "connected"

    return {
        "status": "healthy" if db_healthy else "degraded",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "environment": settings.ENVIRONMENT,
        "version": settings.APP_VERSION,
        "components": {
            "api": "healthy",
            "database": db_status,
        },
    }
