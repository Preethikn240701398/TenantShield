"""
Pytest Fixtures for TenantShield
================================
Provides a configured TestClient and Redis test client for testing.
"""

import os
import pytest
from fastapi.testclient import TestClient
import fakeredis.aioredis

# Ensure environment is set to testing before settings load
os.environ["ENVIRONMENT"] = "testing"
os.environ["DEBUG"] = "false"

from app.main import app
from app.services.metrics import MetricsService
from app.services.rate_limiter import RateLimiterService


@pytest.fixture(scope="session", autouse=True)
def test_redis_client():
    """
    Session-wide Redis client for integration and regression testing.
    Uses in-memory async FakeRedis to guarantee instantaneous, deterministic
    execution of atomic pipelines without requiring external server daemons.
    """
    fake_client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    RateLimiterService.set_redis_client(fake_client)
    MetricsService.set_redis_client(fake_client)

    yield fake_client

    RateLimiterService.set_redis_client(None)
    MetricsService.set_redis_client(None)


@pytest.fixture(scope="session")
def client() -> TestClient:
    """
    Returns a synchronous TestClient bound to the FastAPI application.
    """
    with TestClient(app) as test_client:
        yield test_client
