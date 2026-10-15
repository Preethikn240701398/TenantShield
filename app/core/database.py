"""
TenantShield - Database Connection & Session Management
======================================================
Decouples database engine initialization, connection pooling, session lifecycle,
and PostgreSQL Row-Level Security (RLS) tenant context setting from API routes.
"""

import uuid
from contextlib import asynccontextmanager
from typing import AsyncGenerator
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from sqlalchemy.pool import NullPool

from app.core.config import settings

# Asynchronous SQLAlchemy Engine using the restricted application role
engine_kwargs = {
    "echo": settings.DEBUG,
    "pool_pre_ping": True,
}
if settings.ENVIRONMENT == "testing":
    engine_kwargs["poolclass"] = NullPool
else:
    engine_kwargs["pool_size"] = settings.DB_POOL_SIZE
    engine_kwargs["max_overflow"] = settings.DB_MAX_OVERFLOW
    engine_kwargs["pool_timeout"] = settings.DB_POOL_TIMEOUT

engine = create_async_engine(settings.DATABASE_URL, **engine_kwargs)

# Async session factory
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency yielding an async database session.
    Ensures sessions are cleanly closed when requests complete.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


async def set_tenant_context(session: AsyncSession, tenant_id: str | uuid.UUID) -> None:
    """
    Enforces PostgreSQL Row-Level Security (RLS) by setting the session variable
    'app.current_tenant_id' within the current transaction block.

    Uses `is_local = true` so the setting resets when the transaction commits or aborts,
    preventing tenant context leakage in pooled database connections.
    """
    await session.execute(
        text("SELECT set_config('app.current_tenant_id', :tenant_id, true)"),
        {"tenant_id": str(tenant_id)},
    )


@asynccontextmanager
async def tenant_session(tenant_id: str | uuid.UUID) -> AsyncGenerator[AsyncSession, None]:
    """
    Context manager providing an AsyncSession strictly bound to a transaction-local
    tenant context for Row-Level Security (RLS) enforcement.

    Ensures:
    1. An explicit transaction block is opened (`async with session.begin()`).
    2. `app.current_tenant_id` is set locally (`is_local = true`).
    3. The setting automatically terminates when the transaction commits or aborts.
    """
    async with AsyncSessionLocal() as session:
        async with session.begin():
            await set_tenant_context(session, tenant_id)
            yield session


async def check_db_health() -> dict[str, str]:
    """
    Performs a lightweight query to verify PostgreSQL connectivity.
    Gracefully catches connection errors so health check endpoints can report
    component-level status without crashing.
    """
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return {"status": "connected", "details": "PostgreSQL is reachable"}
    except Exception as exc:
        return {"status": "disconnected", "error": str(exc)}
