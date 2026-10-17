"""
TenantShield - Limiter Service Manager
======================================
Singleton manager to select, configure, and execute limiter strategies dynamically.
Provides backward-compatible delegation for Level 6 RateLimiterService.
"""

import logging
from typing import Optional, Tuple
from uuid import UUID

import redis.asyncio as aioredis

from app.core.config import settings
from app.limiter.base import LimiterInterface
from app.limiter.strategies import (
    CombinedLimiter,
    ConcurrencyLimiter,
    CostBudgetLimiter,
    NoLimitLimiter,
    RequestCountLimiter,
    StatementTimeoutLimiter,
)

logger = logging.getLogger("tenantshield.limiter_service")


class LimiterService:
    """Central singleton managing the active limiter strategy."""

    _active_strategy: Optional[LimiterInterface] = None
    _redis_client: Optional[aioredis.Redis] = None

    @classmethod
    def get_redis_client(cls) -> aioredis.Redis:
        from app.services.rate_limiter import RateLimiterService
        return RateLimiterService.get_redis_client()

    @classmethod
    def set_redis_client(cls, client: Optional[aioredis.Redis]) -> None:
        cls._redis_client = client
        if cls._active_strategy and hasattr(cls._active_strategy, "set_client"):
            cls._active_strategy.set_client(client)

    @classmethod
    def create_strategy_by_name(cls, name: str) -> LimiterInterface:
        """Factory method to instantiate a strategy by its configured name."""
        name = name.strip().lower()
        if name in ("none", "baseline", "no_limit"):
            return NoLimitLimiter()

        elif name in ("request_count", "rate_limit"):
            return RequestCountLimiter(
                requests_limit=getattr(settings, "LIMITER_REQUESTS_LIMIT", 15),
                window_seconds=getattr(settings, "LIMITER_WINDOW_SECONDS", 10),
                redis_client=cls._redis_client,
                failure_policy=settings.REDIS_FAILURE_POLICY,
            )

        elif name == "concurrency":
            return ConcurrencyLimiter(
                max_concurrency=getattr(settings, "LIMITER_CONCURRENCY_LIMIT", 2),
                redis_client=cls._redis_client,
                failure_policy=settings.REDIS_FAILURE_POLICY,
            )

        elif name == "statement_timeout":
            return StatementTimeoutLimiter(
                timeout_ms=getattr(settings, "LIMITER_STATEMENT_TIMEOUT_MS", 250),
            )

        elif name == "cost_budget":
            return CostBudgetLimiter(
                budget_per_window=getattr(settings, "LIMITER_COST_BUDGET", 25),
                window_seconds=getattr(settings, "LIMITER_COST_WINDOW_SECONDS", 10),
                redis_client=cls._redis_client,
                failure_policy=settings.REDIS_FAILURE_POLICY,
            )

        elif name == "combined":
            req_limiter = RequestCountLimiter(
                requests_limit=getattr(settings, "LIMITER_REQUESTS_LIMIT", 15),
                window_seconds=getattr(settings, "LIMITER_WINDOW_SECONDS", 10),
                redis_client=cls._redis_client,
                failure_policy=settings.REDIS_FAILURE_POLICY,
            )
            conc_limiter = ConcurrencyLimiter(
                max_concurrency=getattr(settings, "LIMITER_CONCURRENCY_LIMIT", 2),
                redis_client=cls._redis_client,
                failure_policy=settings.REDIS_FAILURE_POLICY,
            )
            stmt_limiter = StatementTimeoutLimiter(
                timeout_ms=getattr(settings, "LIMITER_STATEMENT_TIMEOUT_MS", 250),
            )
            return CombinedLimiter(req_limiter, conc_limiter, stmt_limiter)

        else:
            logger.warning("Unknown limiter strategy '%s'. Defaulting to request_count.", name)
            return RequestCountLimiter(
                requests_limit=getattr(settings, "LIMITER_REQUESTS_LIMIT", 15),
                window_seconds=getattr(settings, "LIMITER_WINDOW_SECONDS", 10),
                redis_client=cls._redis_client,
                failure_policy=settings.REDIS_FAILURE_POLICY,
            )

    @classmethod
    def get_strategy(cls) -> LimiterInterface:
        """Returns the active strategy instance, creating it if needed."""
        if cls._active_strategy is None:
            strategy_name = getattr(settings, "LIMITER_STRATEGY", "request_count")
            cls._active_strategy = cls.create_strategy_by_name(strategy_name)
        return cls._active_strategy

    @classmethod
    def set_strategy(cls, strategy: LimiterInterface | str) -> None:
        """Overrides the active strategy instance."""
        if isinstance(strategy, str):
            cls._active_strategy = cls.create_strategy_by_name(strategy)
        else:
            cls._active_strategy = strategy
        from app.services.rate_limiter import RateLimiterService
        RateLimiterService.set_limiter(cls._active_strategy)

    @classmethod
    async def check_rate_limit(cls, tenant_id: UUID, cost: int = 1) -> Tuple[bool, int, int]:
        """Delegates rate check to the active strategy."""
        return await cls.get_strategy().check_rate_limit(tenant_id, cost=cost)

    @classmethod
    async def release_concurrency(cls, tenant_id: UUID) -> None:
        """Releases concurrency slot if the active strategy tracks concurrency."""
        strategy = cls.get_strategy()
        await strategy.release_slot(tenant_id)

    @classmethod
    def get_active_statement_timeout_ms(cls) -> int:
        """Returns active statement timeout in ms, or 0 if inactive."""
        return cls.get_strategy().get_statement_timeout_ms()

    @classmethod
    def get_effective_config(cls) -> dict:
        """Returns the dictionary of effective limits for the active strategy."""
        strat = cls.get_strategy()
        name = strat.strategy_name
        cfg: dict = {"strategy": name}
        if name == "request_count":
            cfg["requests_limit"] = getattr(strat, "requests_limit", None)
            cfg["window_seconds"] = getattr(strat, "window_seconds", None)
        elif name == "concurrency":
            cfg["max_concurrency"] = getattr(strat, "max_concurrency", None)
        elif name == "statement_timeout":
            cfg["timeout_ms"] = getattr(strat, "timeout_ms", None)
        elif name == "cost_budget":
            cfg["budget_per_window"] = getattr(strat, "budget_per_window", None)
            cfg["window_seconds"] = getattr(strat, "window_seconds", None)
        elif name == "combined":
            cfg["requests_limit"] = getattr(strat, "requests_limit", None)
            cfg["window_seconds"] = getattr(strat, "window_seconds", None)
            cfg["max_concurrency"] = getattr(strat, "max_concurrency", None)
            cfg["timeout_ms"] = getattr(strat, "statement_timeout_ms", None)
        elif name == "none":
            cfg["limits"] = "none"
        return cfg


    @classmethod
    async def reset_all_limits(cls, tenant_id: Optional[UUID] = None) -> None:
        """Flushes rate limit, concurrency, and cost budget keys in Redis."""
        try:
            client = cls.get_redis_client()
            if tenant_id:
                patterns = [
                    f"tenantshield:rate_limit:{tenant_id}:*",
                    f"tenantshield:concurrency:{tenant_id}",
                    f"tenantshield:cost_budget:{tenant_id}:*",
                ]
            else:
                patterns = [
                    "tenantshield:rate_limit:*",
                    "tenantshield:concurrency:*",
                    "tenantshield:cost_budget:*",
                ]

            for pat in patterns:
                try:
                    keys = await client.keys(pat)
                    if keys:
                        await client.delete(*keys)
                except Exception:
                    pass
        except Exception as exc:
            logger.warning("Error resetting limiter keys: %s", exc)

    @classmethod
    async def close(cls) -> None:
        """Closes Redis connections."""
        if cls._redis_client is not None:
            try:
                await cls._redis_client.aclose()
            except Exception:
                pass
            cls._redis_client = None
        cls._active_strategy = None
