"""
TenantShield - FastAPI Application Entrypoint
=============================================
Configures the ASGI application, lifespan management, middleware, and
route registration.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router as system_router
from app.core.config import settings
from app.core.database import engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager. Handles startup and graceful shutdown
    of shared resources like connection pools.
    """
    # Startup: Resources are prepared on demand
    yield
    # Shutdown: Cleanly dispose of SQLAlchemy connection pool
    await engine.dispose()


def create_application() -> FastAPI:
    """
    Application factory initializing FastAPI with settings and routes.
    """
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description=(
            "TenantShield is a secure multi-tenant SaaS workspace API built with "
            "Python, FastAPI, and PostgreSQL 16 with Row-Level Security (RLS)."
        ),
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # Cross-Origin Resource Sharing (CORS) Middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"] if settings.DEBUG else ["https://yourdomain.com"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register System Endpoints (/, /health)
    app.include_router(system_router)

    return app


app = create_application()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
    )
