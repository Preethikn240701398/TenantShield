"""
TenantShield - Limiter Strategies Unit Tests
============================================
Tests the core limiter strategies:
1. Slot released on failure (concurrency limiter).
2. Clean database statement timeout error (HTTP 504).
3. HTTP 429 returned for the right tenant (strict tenant isolation).
4. Cost budget limiter enforcement (Strategy D).
5. No-limit baseline behavior.
"""

import asyncio
from uuid import UUID
from fastapi.testclient import TestClient
import pytest

from app.core.config import settings
from app.limiter.service import LimiterService
from app.limiter.strategies import (
    CombinedLimiter,
    ConcurrencyLimiter,
    CostBudgetLimiter,
    NoLimitLimiter,
    RequestCountLimiter,
    StatementTimeoutLimiter,
)
from app.services.rate_limiter import RateLimiterService


@pytest.fixture(autouse=True)
async def reset_limiter_state():
    """Reset limiter strategy and Redis state before and after each test."""
    await LimiterService.reset_all_limits()
    orig_strategy = LimiterService._active_strategy
    yield
    await LimiterService.reset_all_limits()
    LimiterService.set_strategy("request_count")


@pytest.mark.asyncio
async def test_01_slot_released_on_request_failure(client: TestClient, acme_auth):
    """
    Validates that the per-tenant concurrency slot in Redis is released even if
    the HTTP request fails (HTTP 4xx/5xx or unhandled exception).
    """
    conc_limiter = ConcurrencyLimiter(max_concurrency=1)
    LimiterService.set_strategy(conc_limiter)
    tenant_id = UUID(acme_auth["user"]["tenant_id"])
    headers = acme_auth["headers"]

    await LimiterService.reset_all_limits(tenant_id)

    # 1. Issue an intentionally failing request (invalid document UUID -> 404/422)
    fail_resp = client.get("/documents/00000000-0000-0000-0000-000000000000", headers=headers)
    assert fail_resp.status_code in (404, 422)

    # 2. Verify that the concurrency slot was released: in-flight count in Redis must be 0
    client_redis = LimiterService.get_redis_client()
    key = f"tenantshield:concurrency:{tenant_id}"
    active_in_flight = await client_redis.get(key)
    assert active_in_flight is None or int(active_in_flight) == 0, f"Expected 0 active slots, got {active_in_flight}"

    # 3. Next legitimate request must succeed (not blocked by a leaked concurrency slot)
    success_resp = client.get("/documents", headers=headers)
    assert success_resp.status_code == 200


@pytest.mark.asyncio
async def test_02_clean_statement_timeout_error(client: TestClient, acme_auth):
    """
    Validates that per-tenant statement_timeout (SET LOCAL) returns a clean HTTP 504
    Gateway Timeout and counts as an error for the offending tenant without crashing.
    """
    # Configure a fast statement timeout (100ms) that heavy report will exceed
    stmt_limiter = StatementTimeoutLimiter(timeout_ms=100)
    LimiterService.set_strategy(stmt_limiter)
    headers = acme_auth["headers"]

    # Request the heavy report endpoint (takes ~350-450ms)
    resp = client.get("/documents/analytics/heavy-report", headers=headers)
    assert resp.status_code == 504, f"Expected HTTP 504, got {resp.status_code}: {resp.text}"
    assert "statement timeout" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_03_429_for_the_right_tenant(client: TestClient, acme_auth, beta_auth):
    """
    Validates that when Tenant Acme exhausts its limiter quota (HTTP 429),
    Tenant Beta is completely unaffected and continues to receive HTTP 200.
    """
    req_limiter = RequestCountLimiter(requests_limit=2, window_seconds=60)
    LimiterService.set_strategy(req_limiter)

    acme_id = UUID(acme_auth["user"]["tenant_id"])
    beta_id = UUID(beta_auth["user"]["tenant_id"])
    await LimiterService.reset_all_limits()

    acme_headers = acme_auth["headers"]
    beta_headers = beta_auth["headers"]

    # Acme sends 2 allowed requests, 3rd gets 429
    assert client.get("/documents", headers=acme_headers).status_code == 200
    assert client.get("/documents", headers=acme_headers).status_code == 200
    acme_blocked = client.get("/documents", headers=acme_headers)
    assert acme_blocked.status_code == 429

    # Tenant Beta sends a request: MUST succeed (200 OK)
    beta_resp = client.get("/documents", headers=beta_headers)
    assert beta_resp.status_code == 200


@pytest.mark.asyncio
async def test_04_concurrency_limiter_exceeded_blocks_excess(acme_auth):
    """
    Validates concurrency acquisition and rejection when max_concurrency is reached.
    """
    conc = ConcurrencyLimiter(max_concurrency=2)
    tenant_id = UUID(acme_auth["user"]["tenant_id"])
    await conc.reset_tenant_limit(tenant_id)

    # 1. Acquire slot 1 -> success
    ok1, rem1, _ = await conc.acquire_slot(tenant_id)
    assert ok1 is True
    assert rem1 == 1

    # 2. Acquire slot 2 -> success
    ok2, rem2, _ = await conc.acquire_slot(tenant_id)
    assert ok2 is True
    assert rem2 == 0

    # 3. Acquire slot 3 -> blocked
    ok3, rem3, retry3 = await conc.acquire_slot(tenant_id)
    assert ok3 is False
    assert rem3 == 0
    assert retry3 >= 1

    # 4. Release slot 1 -> now slot 3 can succeed
    await conc.release_slot(tenant_id)
    ok4, rem4, _ = await conc.acquire_slot(tenant_id)
    assert ok4 is True

    # Cleanup
    await conc.release_slot(tenant_id)
    await conc.release_slot(tenant_id)


@pytest.mark.asyncio
async def test_05_cost_budget_limiter_enforces_weighted_costs(acme_auth):
    """
    Validates CostBudgetLimiter: endpoints consume cost from the tenant's windowed budget.
    """
    cost_limiter = CostBudgetLimiter(budget_per_window=15, window_seconds=10)
    tenant_id = UUID(acme_auth["user"]["tenant_id"])
    await cost_limiter.reset_tenant_limit(tenant_id)

    # Normal request (cost=1): 1/15 consumed
    ok1, rem1, _ = await cost_limiter.check_rate_limit(tenant_id, cost=1)
    assert ok1 is True
    assert rem1 == 14

    # Heavy request (cost=10): 11/15 consumed
    ok2, rem2, _ = await cost_limiter.check_rate_limit(tenant_id, cost=10)
    assert ok2 is True
    assert rem2 == 4

    # Another heavy request (cost=10): 21/15 -> exceeds budget!
    ok3, rem3, _ = await cost_limiter.check_rate_limit(tenant_id, cost=10)
    assert ok3 is False
    assert rem3 == 0


@pytest.mark.asyncio
async def test_06_no_limit_baseline_never_blocks(acme_auth):
    """
    Validates that NoLimitLimiter permits all requests without restriction.
    """
    limiter = NoLimitLimiter()
    tenant_id = UUID(acme_auth["user"]["tenant_id"])
    for _ in range(100):
        ok, rem, retry = await limiter.check_rate_limit(tenant_id, cost=10)
        assert ok is True
        assert rem == 999999
        assert retry == 0
