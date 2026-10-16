"""
TenantShield - Multi-Tenant Telemetry & Metrics Service
======================================================
Provides per-tenant operational and security observability backed by Redis/Memurai:
1. Per-tenant operational metrics: request count, error count (HTTP 4xx/5xx),
   and latency (in milliseconds).
2. Time-bucketed hash schema (1-minute buckets) with automated TTL retention.
3. Aggregation across configurable reporting windows for platform administrators.
4. Non-blocking error handling: metric recording failures never crash API endpoints.
"""

from datetime import datetime, timezone
import logging
import time
from typing import Any, Dict, List, Optional
from uuid import UUID

import redis.asyncio as aioredis
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import RedisError, TimeoutError as RedisTimeoutError

from app.core.config import settings
from app.services.rate_limiter import RateLimiterService

logger = logging.getLogger("tenantshield.metrics")


class MetricsError(Exception):
    """Base exception for metrics service."""
    pass


class MetricsUnavailableError(MetricsError):
    """Raised when Redis is unreachable when querying metrics."""
    pass


class MetricsService:
    """
    Multi-tenant telemetry and observability service.
    Aggregates operational request counts, error counts, and latencies.
    """

    _custom_client: Optional[aioredis.Redis] = None

    @classmethod
    def set_redis_client(cls, client: Optional[aioredis.Redis]) -> None:
        """Inject a test or mock Redis client."""
        cls._custom_client = client

    @classmethod
    def _get_client(cls) -> aioredis.Redis:
        """Returns the active Redis client."""
        if cls._custom_client is not None:
            return cls._custom_client
        return RateLimiterService.get_redis_client()

    @classmethod
    async def record_request(
        cls,
        tenant_id: UUID,
        status_code: int,
        duration_ms: float,
    ) -> None:
        """
        Record an incoming HTTP request tagged by trusted tenant identifier.

        Time-bucket schema:
            Key: tenantshield:metrics:{tenant_id}:{bucket_timestamp}
            Fields:
                requests: total requests count
                errors: count of HTTP 4xx / 5xx responses
                total_latency_ms: cumulative duration in milliseconds

        Fails safely without raising exceptions to ensure metric collection
        never breaks or masks application endpoints.
        """
        try:
            client = cls._get_client()
            now = time.time()
            bucket_ts = int(now // 60) * 60  # 1-minute bucket
            key = f"tenantshield:metrics:{tenant_id}:{bucket_ts}"
            tenants_set_key = "tenantshield:metrics:tenants"

            is_error = 1 if status_code >= 400 else 0
            rounded_duration = round(max(0.0, float(duration_ms)), 2)

            pipe = client.pipeline(transaction=True)
            pipe.hincrby(key, "requests", 1)
            if is_error:
                pipe.hincrby(key, "errors", 1)
            pipe.hincrbyfloat(key, "total_latency_ms", rounded_duration)
            pipe.expire(key, settings.METRICS_RETENTION_SECONDS)

            # Track active tenant in set for quick tenant lookup without KEYS *
            pipe.sadd(tenants_set_key, str(tenant_id))
            pipe.expire(tenants_set_key, settings.METRICS_RETENTION_SECONDS * 2)

            await pipe.execute()

        except (RedisConnectionError, RedisTimeoutError, RedisError, OSError) as exc:
            logger.warning(
                "Failed to record metric in Redis for tenant %s: %s",
                tenant_id,
                type(exc).__name__,
            )
        except Exception as exc:
            logger.error("Unexpected error in MetricsService.record_request: %s", exc)

    @classmethod
    async def get_aggregated_metrics(
        cls,
        window_minutes: int = 60,
        tenant_id: Optional[UUID] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """
        Retrieve aggregated metrics across active tenants for the specified time window.

        Args:
            window_minutes: reporting interval in minutes (1 to 1440)
            tenant_id: optional filter for a single tenant
            limit: maximum number of tenants to return (1 to 1000)

        Returns:
            Dictionary containing window bounds and per-tenant metrics list.
        """
        if window_minutes < 1 or window_minutes > 1440:
            raise ValueError("window_minutes must be between 1 and 1440 (24 hours)")
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")

        now = time.time()
        start_ts = now - (window_minutes * 60)
        start_bucket = int(start_ts // 60) * 60
        end_bucket = int(now // 60) * 60

        # Construct list of all 1-minute bucket timestamps in window
        buckets = [b for b in range(start_bucket, end_bucket + 60, 60)]

        try:
            client = cls._get_client()

            # Identify target tenants
            if tenant_id is not None:
                tenants = [str(tenant_id)]
            else:
                tenants_set_key = "tenantshield:metrics:tenants"
                raw_tenants = await client.smembers(tenants_set_key)
                # Decode if needed
                tenants = sorted([
                    t.decode("utf-8") if isinstance(t, bytes) else str(t)
                    for t in raw_tenants
                ])[:limit]

            tenant_aggregates: List[Dict[str, Any]] = []

            for t_id in tenants:
                pipe = client.pipeline(transaction=False)
                for b_ts in buckets:
                    pipe.hgetall(f"tenantshield:metrics:{t_id}:{b_ts}")
                bucket_results = await pipe.execute()

                total_requests = 0
                total_errors = 0
                total_latency = 0.0

                for b_data in bucket_results:
                    if not b_data:
                        continue
                    # Normalize string/bytes keys and values
                    data = {
                        (k.decode() if isinstance(k, bytes) else k): (
                            v.decode() if isinstance(v, bytes) else v
                        )
                        for k, v in b_data.items()
                    }
                    total_requests += int(data.get("requests", 0))
                    total_errors += int(data.get("errors", 0))
                    total_latency += float(data.get("total_latency_ms", 0.0))

                if total_requests > 0 or tenant_id is not None:
                    avg_latency = (
                        round(total_latency / total_requests, 2)
                        if total_requests > 0
                        else 0.0
                    )
                    tenant_aggregates.append({
                        "tenant_id": t_id,
                        "request_count": total_requests,
                        "error_count": total_errors,
                        "avg_latency_ms": avg_latency,
                    })

            # Format ISO timestamps
            start_iso = datetime.fromtimestamp(start_ts, tz=timezone.utc).isoformat()
            end_iso = datetime.fromtimestamp(now, tz=timezone.utc).isoformat()

            return {
                "reporting_window_minutes": window_minutes,
                "start_time": start_iso,
                "end_time": end_iso,
                "tenant_count": len(tenant_aggregates),
                "tenants": tenant_aggregates,
            }

        except (RedisConnectionError, RedisTimeoutError, RedisError, OSError) as exc:
            logger.error("Redis metrics query failed: %s", type(exc).__name__)
            raise MetricsUnavailableError(
                "Redis metrics service is currently unavailable."
            ) from exc

    @classmethod
    async def clear_metrics(cls) -> None:
        """Clears all metrics keys (useful for test isolation)."""
        try:
            client = cls._get_client()
            tenants_set_key = "tenantshield:metrics:tenants"
            tenants = await client.smembers(tenants_set_key)
            all_keys = [tenants_set_key]
            for t in tenants:
                t_str = t.decode() if isinstance(t, bytes) else str(t)
                pattern = f"tenantshield:metrics:{t_str}:*"
                async for k in client.scan_iter(match=pattern):
                    all_keys.append(k)
            if all_keys:
                await client.delete(*all_keys)
        except Exception as exc:
            logger.warning("Could not clear metrics keys: %s", type(exc).__name__)
