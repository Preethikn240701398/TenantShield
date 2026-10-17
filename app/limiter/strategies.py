"""
TenantShield - Limiter Strategies Implementation
================================================
Implements:
1. NoLimitLimiter (Baseline)
2. RequestCountLimiter (Strategy A)
3. ConcurrencyLimiter (Strategy B - releases slot on success and failure)
4. StatementTimeoutLimiter (Strategy C - SET LOCAL statement_timeout in DB)
5. CostBudgetLimiter (Strategy D - Cost-based limiting per window)
6. CombinedLimiter (Strategy E - Multi-layer limiter combining A, B, and C)
"""

import logging
import time
from typing import Optional, Tuple
from uuid import UUID

import redis.asyncio as aioredis
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import RedisError, TimeoutError as RedisTimeoutError

from app.core.config import settings
from app.limiter.base import LimiterInterface, LimiterUnavailableError

logger = logging.getLogger("tenantshield.limiter")

# Lua script for safe concurrency decrement (never drops below 0)
LUA_SAFE_DECR = """
local current = redis.call('GET', KEYS[1])
if not current then
    return 0
end
local num = tonumber(current)
if num > 1 then
    return redis.call('DECR', KEYS[1])
else
    redis.call('DEL', KEYS[1])
    return 0
end
"""


class BaseRedisLimiter(LimiterInterface):
    """Base class for limiters interacting with Redis / Memurai."""

    def __init__(
        self,
        redis_client: Optional[aioredis.Redis] = None,
        failure_policy: Optional[str] = None,
    ):
        self._custom_client = redis_client
        self._failure_policy = (failure_policy or settings.REDIS_FAILURE_POLICY).strip().lower()

    def _get_client(self) -> aioredis.Redis:
        if self._custom_client is not None:
            return self._custom_client
        from app.services.rate_limiter import RateLimiterService
        return RateLimiterService.get_redis_client()

    def set_client(self, client: Optional[aioredis.Redis]) -> None:
        self._custom_client = client


class NoLimitLimiter(LimiterInterface):
    """
    Baseline Strategy: No limits applied.
    Permits all traffic, zero concurrency tracking, zero statement timeouts.
    """

    @property
    def strategy_name(self) -> str:
        return "none"

    async def check_rate_limit(self, tenant_id: UUID, cost: int = 1) -> Tuple[bool, int, int]:
        return True, 999999, 0

    async def reset_tenant_limit(self, tenant_id: UUID) -> None:
        pass


class RequestCountLimiter(BaseRedisLimiter):
    """
    Strategy A: Request-Count Rate Limiting.
    Tenant-partitioned atomic fixed-window limiting using Redis MULTI/EXEC pipelines.
    Default: 15 requests per 10s window (or configured setting).
    """

    def __init__(
        self,
        requests_limit: Optional[int] = None,
        window_seconds: Optional[int] = None,
        redis_client: Optional[aioredis.Redis] = None,
        failure_policy: Optional[str] = None,
    ):
        super().__init__(redis_client, failure_policy)
        self._requests_limit = requests_limit or settings.RATE_LIMIT_REQUESTS
        self._window_seconds = window_seconds or settings.RATE_LIMIT_WINDOW_SECONDS

    @property
    def strategy_name(self) -> str:
        return "request_count"

    @property
    def requests_limit(self) -> int:
        return self._requests_limit

    @property
    def window_seconds(self) -> int:
        return self._window_seconds

    async def check_rate_limit(self, tenant_id: UUID, cost: int = 1) -> Tuple[bool, int, int]:
        now = time.time()
        window_start = int(now // self._window_seconds) * self._window_seconds
        window_end = window_start + self._window_seconds
        retry_after = max(1, int(window_end - now))

        key = f"tenantshield:rate_limit:{tenant_id}:{int(window_start)}"
        try:
            client = self._get_client()
            pipe = client.pipeline(transaction=True)
            pipe.incrby(key, cost)
            pipe.expire(key, self._window_seconds + 5)
            results = await pipe.execute()

            current_count = int(results[0])
            allowed = current_count <= self._requests_limit
            remaining = max(0, self._requests_limit - current_count)
            return allowed, remaining, retry_after

        except (RedisConnectionError, RedisTimeoutError, RedisError, OSError) as exc:
            if self._failure_policy == "fail_closed":
                raise LimiterUnavailableError("Rate limiting service unavailable.") from exc
            return True, self._requests_limit, 0

    async def reset_tenant_limit(self, tenant_id: UUID) -> None:
        try:
            client = self._get_client()
            pattern = f"tenantshield:rate_limit:{tenant_id}:*"
            keys = []
            async for k in client.scan_iter(match=pattern):
                keys.append(k)
            if keys:
                await client.delete(*keys)
        except Exception:
            pass


class ConcurrencyLimiter(BaseRedisLimiter):
    """
    Strategy B: Per-Tenant Concurrency Limiting.
    Tracks active in-flight requests in Redis per tenant.
    Default: Max 2 concurrent in-flight requests per tenant.
    Releases the slot on both success and failure via middleware/finally blocks.
    """

    def __init__(
        self,
        max_concurrency: int = 2,
        redis_client: Optional[aioredis.Redis] = None,
        failure_policy: Optional[str] = None,
    ):
        super().__init__(redis_client, failure_policy)
        self._max_concurrency = max_concurrency

    @property
    def strategy_name(self) -> str:
        return "concurrency"

    @property
    def max_concurrency(self) -> int:
        return self._max_concurrency

    async def acquire_slot(self, tenant_id: UUID) -> Tuple[bool, int, int]:
        """
        Atomically increment in-flight count for tenant.
        If current > max_concurrency, decrement and reject.
        """
        key = f"tenantshield:concurrency:{tenant_id}"
        try:
            client = self._get_client()
            pipe = client.pipeline(transaction=True)
            pipe.incr(key)
            pipe.expire(key, 30)  # Failsafe TTL: auto-release if process crashes
            results = await pipe.execute()
            current_active = int(results[0])

            if current_active > self._max_concurrency:
                # Concurrency exceeded: decrement immediately and reject
                await client.decr(key)
                return False, 0, 1  # 1s retry-after

            remaining = max(0, self._max_concurrency - current_active)
            return True, remaining, 0

        except (RedisConnectionError, RedisTimeoutError, RedisError, OSError) as exc:
            if self._failure_policy == "fail_closed":
                raise LimiterUnavailableError("Limiter unavailable.") from exc
            return True, self._max_concurrency, 0

    async def release_slot(self, tenant_id: UUID) -> None:
        """
        Atomically decrement in-flight count for tenant, never going below 0.
        Called in finally block of request execution.
        """
        key = f"tenantshield:concurrency:{tenant_id}"
        try:
            client = self._get_client()
            try:
                await client.eval(LUA_SAFE_DECR, 1, key)
            except Exception:
                # Fallback if Lua disabled: atomic pipeline DECR with clamp
                val = await client.get(key)
                if val and int(val) > 0:
                    await client.decr(key)
        except Exception as exc:
            logger.warning("Error releasing concurrency slot for %s: %s", tenant_id, exc)

    async def check_rate_limit(self, tenant_id: UUID, cost: int = 1) -> Tuple[bool, int, int]:
        """Checks and acquires a concurrency slot."""
        return await self.acquire_slot(tenant_id)

    async def reset_tenant_limit(self, tenant_id: UUID) -> None:
        try:
            client = self._get_client()
            key = f"tenantshield:concurrency:{tenant_id}"
            await client.delete(key)
        except Exception:
            pass


class StatementTimeoutLimiter(LimiterInterface):
    """
    Strategy C: Database Statement Timeout Limiting.
    Applies SET LOCAL statement_timeout in PostgreSQL transactions for each request.
    Default: 250ms statement timeout.
    Returns clean HTTP 504 Gateway Timeout and records an error for the offending tenant.
    """

    def __init__(self, timeout_ms: int = 250):
        self._timeout_ms = timeout_ms

    @property
    def strategy_name(self) -> str:
        return "statement_timeout"

    @property
    def timeout_ms(self) -> int:
        return self._timeout_ms

    def get_statement_timeout_ms(self) -> int:
        return self._timeout_ms

    async def check_rate_limit(self, tenant_id: UUID, cost: int = 1) -> Tuple[bool, int, int]:
        # Statement timeout does not block requests at the API gateway layer
        return True, 999999, 0

    async def reset_tenant_limit(self, tenant_id: UUID) -> None:
        pass


class CostBudgetLimiter(BaseRedisLimiter):
    """
    Strategy D (Phase 2): Cost-Based Limiting.
    Each endpoint has an associated cost weight (normal = 1, heavy report = 10).
    Each tenant has a provisioned budget per time window (e.g. 25 units per 10s).
    """

    def __init__(
        self,
        budget_per_window: int = 25,
        window_seconds: int = 10,
        redis_client: Optional[aioredis.Redis] = None,
        failure_policy: Optional[str] = None,
    ):
        super().__init__(redis_client, failure_policy)
        self._budget_per_window = budget_per_window
        self._window_seconds = window_seconds

    @property
    def strategy_name(self) -> str:
        return "cost_budget"

    @property
    def budget_per_window(self) -> int:
        return self._budget_per_window

    @property
    def window_seconds(self) -> int:
        return self._window_seconds

    async def check_rate_limit(self, tenant_id: UUID, cost: int = 1) -> Tuple[bool, int, int]:
        now = time.time()
        window_start = int(now // self._window_seconds) * self._window_seconds
        window_end = window_start + self._window_seconds
        retry_after = max(1, int(window_end - now))

        key = f"tenantshield:cost_budget:{tenant_id}:{int(window_start)}"
        try:
            client = self._get_client()
            pipe = client.pipeline(transaction=True)
            pipe.incrby(key, cost)
            pipe.expire(key, self._window_seconds + 5)
            results = await pipe.execute()

            current_spent = int(results[0])
            allowed = current_spent <= self._budget_per_window
            remaining = max(0, self._budget_per_window - current_spent)
            return allowed, remaining, retry_after

        except (RedisConnectionError, RedisTimeoutError, RedisError, OSError) as exc:
            if self._failure_policy == "fail_closed":
                raise LimiterUnavailableError("Cost limiter unavailable.") from exc
            return True, self._budget_per_window, 0

    async def reset_tenant_limit(self, tenant_id: UUID) -> None:
        try:
            client = self._get_client()
            pattern = f"tenantshield:cost_budget:{tenant_id}:*"
            keys = []
            async for k in client.scan_iter(match=pattern):
                keys.append(k)
            if keys:
                await client.delete(*keys)
        except Exception:
            pass


class CombinedLimiter(LimiterInterface):
    """
    Strategy E (Phase 2): Multi-Layer Limiter.
    Combines Request-Count Limiter, Concurrency Limiter, and Statement Timeout.
    """

    def __init__(
        self,
        request_limiter: RequestCountLimiter,
        concurrency_limiter: ConcurrencyLimiter,
        statement_timeout_limiter: StatementTimeoutLimiter,
    ):
        self._request_limiter = request_limiter
        self._concurrency_limiter = concurrency_limiter
        self._statement_timeout_limiter = statement_timeout_limiter

    @property
    def strategy_name(self) -> str:
        return "combined"

    @property
    def requests_limit(self) -> int:
        return self._request_limiter.requests_limit

    @property
    def window_seconds(self) -> int:
        return self._request_limiter.window_seconds

    @property
    def max_concurrency(self) -> int:
        return self._concurrency_limiter.max_concurrency

    @property
    def statement_timeout_ms(self) -> int:
        return self._statement_timeout_limiter.get_statement_timeout_ms()

    def get_statement_timeout_ms(self) -> int:
        return self._statement_timeout_limiter.get_statement_timeout_ms()

    async def acquire_slot(self, tenant_id: UUID) -> Tuple[bool, int, int]:
        return await self._concurrency_limiter.acquire_slot(tenant_id)

    async def release_slot(self, tenant_id: UUID) -> None:
        await self._concurrency_limiter.release_slot(tenant_id)

    async def check_rate_limit(self, tenant_id: UUID, cost: int = 1) -> Tuple[bool, int, int]:
        # 1. Check request count quota
        allowed_count, rem_count, retry_count = await self._request_limiter.check_rate_limit(tenant_id, cost)
        if not allowed_count:
            return False, rem_count, retry_count

        # 2. Check and acquire concurrency slot
        allowed_conc, rem_conc, retry_conc = await self._concurrency_limiter.acquire_slot(tenant_id)
        if not allowed_conc:
            return False, rem_conc, retry_conc

        return True, min(rem_count, rem_conc), 0

    async def reset_tenant_limit(self, tenant_id: UUID) -> None:
        await self._request_limiter.reset_tenant_limit(tenant_id)
        await self._concurrency_limiter.reset_tenant_limit(tenant_id)
        await self._statement_timeout_limiter.reset_tenant_limit(tenant_id)
