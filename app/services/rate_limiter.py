"""
TenantShield - Tenant-Aware Rate Limiting Service
=================================================
Provides tenant-aware, distributed request rate limiting backed by Redis/Memurai:
1. Prevents "noisy neighbor" resource starvation across tenants.
2. Tenant-partitioned atomic fixed-window limiting using standard Redis commands
   (pipeline MULTI/EXEC transaction) without requiring Lua scripts.
3. Strict tenant isolation: limits are keyed exclusively by trusted tenant UUIDs.
4. Configurable failure policies: 'fail_open' vs 'fail_closed' with finite timeouts.
"""

from abc import ABC, abstractmethod
import logging
import time
from typing import Optional, Tuple
from uuid import UUID

import redis.asyncio as aioredis
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import RedisError, TimeoutError as RedisTimeoutError

from app.core.config import settings

logger = logging.getLogger("tenantshield.rate_limiter")


class RateLimiterError(Exception):
    """Base exception for rate limiting errors."""
    pass


class RateLimiterUnavailableError(RateLimiterError):
    """Raised when Redis is unreachable and failure policy is fail_closed."""
    pass


class RateLimiterInterface(ABC):
    """Abstract interface defining the rate limiter contract for future strategies."""

    @abstractmethod
    async def check_rate_limit(self, tenant_id: UUID) -> Tuple[bool, int, int]:
        """
        Check if the requesting tenant has exceeded their provisioned request quota.
        Returns:
            (allowed: bool, remaining_quota: int, retry_after_seconds: int)
        """
        pass

    @abstractmethod
    async def reset_tenant_limit(self, tenant_id: UUID) -> None:
        """Reset or clear rate limit counters for a tenant (useful for tests/admin)."""
        pass


class RedisFixedWindowRateLimiter(RateLimiterInterface):
    """
    Atomic fixed-window rate limiter using Redis MULTI/EXEC pipelines.
    Compatible with Memurai Developer and native Redis without Lua scripts.
    """

    def __init__(
        self,
        requests_limit: Optional[int] = None,
        window_seconds: Optional[int] = None,
        failure_policy: Optional[str] = None,
        redis_client: Optional[aioredis.Redis] = None,
    ):
        self._requests_limit = requests_limit or settings.RATE_LIMIT_REQUESTS
        self._window_seconds = window_seconds or settings.RATE_LIMIT_WINDOW_SECONDS
        self._failure_policy = (failure_policy or settings.REDIS_FAILURE_POLICY).strip().lower()
        self._custom_client = redis_client

    def _get_client(self) -> aioredis.Redis:
        """Returns the active Redis client or shared singleton."""
        if self._custom_client is not None:
            return self._custom_client
        return RateLimiterService.get_redis_client()

    def set_client(self, client: Optional[aioredis.Redis]) -> None:
        """Override or mock the Redis client."""
        self._custom_client = client

    @property
    def requests_limit(self) -> int:
        return self._requests_limit

    @property
    def window_seconds(self) -> int:
        return self._window_seconds

    @property
    def failure_policy(self) -> str:
        return self._failure_policy

    async def check_rate_limit(self, tenant_id: UUID) -> Tuple[bool, int, int]:
        """
        Enforce rate limit for a specific tenant in an atomic window.

        Redis key schema:
            tenantshield:rate_limit:{tenant_id}:{window_timestamp}

        Returns:
            (allowed, remaining, retry_after)
        """
        now = time.time()
        window_start = int(now // self._window_seconds) * self._window_seconds
        window_end = window_start + self._window_seconds
        retry_after = max(1, int(window_end - now))

        key = f"tenantshield:rate_limit:{tenant_id}:{int(window_start)}"
        try:
            client = self._get_client()
            # Atomic pipeline without Lua: INCR + EXPIRE in a single MULTI/EXEC transaction
            pipe = client.pipeline(transaction=True)
            pipe.incr(key)
            pipe.expire(key, self._window_seconds + 5)
            results = await pipe.execute()

            current_count = int(results[0])
            allowed = current_count <= self._requests_limit
            remaining = max(0, self._requests_limit - current_count)

            return allowed, remaining, retry_after

        except (RedisConnectionError, RedisTimeoutError, RedisError, OSError) as exc:
            # Handle Redis unavailability based on configured failure policy
            if self._failure_policy == "fail_closed":
                logger.error(
                    "Redis rate limiter unavailable (fail_closed policy active). "
                    "Rejecting request for tenant %s. Error: %s",
                    tenant_id,
                    type(exc).__name__,
                )
                raise RateLimiterUnavailableError(
                    "Rate limiting service is currently unavailable."
                ) from exc
            else:
                # fail_open default: log operational warning and permit traffic
                logger.warning(
                    "Redis rate limiter unavailable (fail_open policy active). "
                    "Permitting request for tenant %s. Error: %s",
                    tenant_id,
                    type(exc).__name__,
                )
                return True, self._requests_limit, 0

    async def reset_tenant_limit(self, tenant_id: UUID) -> None:
        """Clears active rate-limit keys for a tenant."""
        try:
            client = self._get_client()
            pattern = f"tenantshield:rate_limit:{tenant_id}:*"
            keys = []
            async for k in client.scan_iter(match=pattern):
                keys.append(k)
            if keys:
                await client.delete(*keys)
        except Exception as exc:
            logger.warning("Could not reset tenant rate limit keys: %s", type(exc).__name__)


class RateLimiterService:
    """Singleton manager for Redis connection pool and rate limiter instance."""

    _redis_client: Optional[aioredis.Redis] = None
    _limiter_instance: Optional[RedisFixedWindowRateLimiter] = None

    @classmethod
    def get_redis_client(cls) -> aioredis.Redis:
        """Returns or creates a shared async Redis client with finite timeouts."""
        if cls._redis_client is None:
            cls._redis_client = aioredis.from_url(
                settings.REDIS_URL,
                socket_connect_timeout=settings.REDIS_CONNECT_TIMEOUT,
                socket_timeout=settings.REDIS_SOCKET_TIMEOUT,
                decode_responses=True,
                max_connections=50,
            )
        return cls._redis_client

    @classmethod
    def set_redis_client(cls, client: Optional[aioredis.Redis]) -> None:
        """Allows injecting a mock or test client (such as fakeredis)."""
        cls._redis_client = client
        if cls._limiter_instance is not None:
            cls._limiter_instance.set_client(client)

    @classmethod
    def get_limiter(cls) -> RedisFixedWindowRateLimiter:
        """Returns the default configured rate limiter."""
        if cls._limiter_instance is None:
            cls._limiter_instance = RedisFixedWindowRateLimiter(
                requests_limit=settings.RATE_LIMIT_REQUESTS,
                window_seconds=settings.RATE_LIMIT_WINDOW_SECONDS,
                failure_policy=settings.REDIS_FAILURE_POLICY,
                redis_client=cls._redis_client,
            )
        return cls._limiter_instance

    @classmethod
    async def check_rate_limit(cls, tenant_id: UUID) -> Tuple[bool, int, int]:
        """Convenience delegation to active limiter."""
        return await cls.get_limiter().check_rate_limit(tenant_id)

    @classmethod
    async def close(cls) -> None:
        """Gracefully closes Redis connection pool on application shutdown."""
        if cls._redis_client is not None:
            try:
                await cls._redis_client.aclose()
            except Exception:
                pass
            cls._redis_client = None
            cls._limiter_instance = None
