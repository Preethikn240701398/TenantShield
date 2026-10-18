"""
TenantShield - FastAPI Application Entrypoint
=============================================
Configures the ASGI application, lifespan management, middleware, and
route registration.
"""

from contextlib import asynccontextmanager
import logging
import time
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from app.api.admin import router as admin_router
from app.api.auth import router as auth_router
from app.api.dashboard import router as dashboard_router
from app.api.documents import router as documents_router
from app.api.routes import router as system_router
from app.api.runs import router as runs_router
from app.api.demo import router as demo_router
from app.api.traffic_demo import router as traffic_demo_router
from app.api.attack_demo import router as attack_demo_router
from app.api.config_check import router as config_check_router
from app.api.benchmark_demo import router as benchmark_demo_router
from app.vulnerable.documents_flawed import router as vulnerable_router
from app.core.config import settings
from app.core.database import engine
from app.services.metrics import MetricsService
from app.services.rate_limiter import RateLimiterService

app_logger = logging.getLogger("tenantshield.main")


class TenantMetricsMiddleware(BaseHTTPMiddleware):
    """
    Measures request latency and logs operational metrics per tenant into Redis.
    Guarantees:
    - Associates latency and status code strictly with the verified tenant identity.
    - Captures HTTP 4xx and 5xx errors without double-counting.
    - Fails safely: metric logging exceptions never mask application errors.
    """

    async def dispatch(self, request: Request, call_next):
        start_time = time.perf_counter()
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            response.headers["X-Process-Time-Ms"] = f"{duration_ms:.2f}"
            return response
        except Exception:
            status_code = 500
            raise
        finally:
            # Release concurrency slot if held by this request (even on error/failure)
            if getattr(request.state, "concurrency_slot_held", False):
                slot_tenant_id = getattr(request.state, "concurrency_tenant_id", None)
                if slot_tenant_id:
                    try:
                        from app.limiter.service import LimiterService
                        await LimiterService.release_concurrency(slot_tenant_id)
                    except Exception:
                        pass

            duration_ms = (time.perf_counter() - start_time) * 1000.0
            tenant_id = getattr(request.state, "tenant_id", None)
            if tenant_id is not None:
                try:
                    await MetricsService.record_request(
                        tenant_id=tenant_id,
                        status_code=status_code,
                        duration_ms=duration_ms,
                    )
                except Exception:
                    pass



@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager. Handles startup and graceful shutdown
    of shared resources like connection pools.
    """
    # Startup: Resources are prepared on demand
    from app.limiter.service import LimiterService
    app_logger.info(
        "Server startup: Active limiter strategy=%s, effective_limits=%s",
        LimiterService.get_strategy().strategy_name,
        LimiterService.get_effective_config(),
    )
    yield
    # Shutdown: Cleanly dispose of Redis and SQLAlchemy connection pools
    await RateLimiterService.close()
    await engine.dispose()


def create_application() -> FastAPI:
    """
    Application factory initializing FastAPI with settings, middleware, and routes.
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

    # Per-tenant operational metrics and latency tracking middleware
    app.add_middleware(TenantMetricsMiddleware)

    @app.middleware("http")
    async def ui_security_headers(request: Request, call_next):
        response = await call_next(request)
        if request.url.path.startswith("/ui"):
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none';"
            )
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
        return response

    # Register Endpoints
    app.include_router(system_router)
    app.include_router(auth_router)
    app.include_router(documents_router)
    app.include_router(admin_router)
    app.include_router(dashboard_router)
    app.include_router(runs_router)
    app.include_router(demo_router)
    app.include_router(traffic_demo_router)
    app.include_router(attack_demo_router)
    app.include_router(config_check_router)
    app.include_router(benchmark_demo_router)
    app.include_router(vulnerable_router)

    # Mount UI static files
    from pathlib import Path
    from fastapi.staticfiles import StaticFiles
    ui_dir = Path(__file__).resolve().parent.parent / "ui"
    if ui_dir.exists():
        app.mount("/ui", StaticFiles(directory=str(ui_dir), html=True), name="ui")

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
