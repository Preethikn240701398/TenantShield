"""
TenantShield - Noisy Neighbour HTTP Load Generator
==================================================
Asynchronous HTTP load generator using httpx to send paced requests
over real HTTP connections to the standalone application server.
Supports concurrent task dispatch to ensure accurate target rates.
"""

import asyncio
from dataclasses import dataclass
import time
from typing import List, Optional
import httpx


@dataclass
class RequestRecord:
    tenant: str
    endpoint: str
    status_code: int
    duration_ms: float
    timestamp: float
    is_warmup: bool
    server_duration_ms: Optional[float] = None
    error_detail: Optional[str] = None


class HTTPWorkloadGenerator:
    """
    Executes controlled tenant workloads against the live HTTP API server.
    Uses asynchronous task dispatch to decouple request generation from completion latency.
    """

    def __init__(
        self,
        base_url: str,
        acme_token: str,
        beta_token: str,
    ):
        self.base_url = base_url.rstrip("/")
        self.acme_token = acme_token
        self.beta_token = beta_token

    async def _send_single_request(
        self,
        client: httpx.AsyncClient,
        tenant_name: str,
        token: str,
        endpoint: str,
        is_warmup: bool,
    ) -> RequestRecord:
        url = f"{self.base_url}{endpoint}"
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        t0 = time.perf_counter()
        status_code = 500
        server_duration_ms = None
        error_detail = None
        try:
            resp = await client.get(url, headers=headers)
            status_code = resp.status_code
            val = resp.headers.get("x-process-time-ms")
            if val:
                try:
                    server_duration_ms = float(val)
                except ValueError:
                    pass
            if status_code >= 400:
                try:
                    error_detail = resp.json().get("detail", "")
                except Exception:
                    error_detail = resp.text[:100]
        except httpx.TimeoutException:
            status_code = 504
            error_detail = "Client timeout"
        except Exception as e:
            status_code = 500
            error_detail = str(e)[:100]
        duration_ms = (time.perf_counter() - t0) * 1000.0

        return RequestRecord(
            tenant=tenant_name,
            endpoint=endpoint,
            status_code=status_code,
            duration_ms=duration_ms,
            timestamp=time.time(),
            is_warmup=is_warmup,
            server_duration_ms=server_duration_ms,
            error_detail=error_detail,
        )

    async def _dispatch_single_request(
        self,
        client: httpx.AsyncClient,
        tenant_name: str,
        token: str,
        endpoint: str,
        is_warmup: bool,
        records: List[RequestRecord],
    ) -> None:
        rec = await self._send_single_request(client, tenant_name, token, endpoint, is_warmup)
        records.append(rec)

    async def _run_tenant_worker(
        self,
        client: httpx.AsyncClient,
        tenant_name: str,
        token: str,
        endpoint: str,
        rate_rps: float,
        warmup_seconds: float,
        duration_seconds: float,
        records: List[RequestRecord],
        burst_size: int = 1,
    ) -> None:
        """Sends requests at a fixed target rate (RPS) for (warmup + duration)."""
        interval = (1.0 / rate_rps * burst_size) if rate_rps > 0 else 1.0
        start_time = time.time()
        end_time = start_time + warmup_seconds + duration_seconds
        warmup_end = start_time + warmup_seconds

        in_flight: set[asyncio.Task] = set()
        next_tick = start_time

        try:
            while True:
                now = time.time()
                if now >= end_time:
                    break

                is_warmup = now < warmup_end
                for _ in range(burst_size):
                    task = asyncio.create_task(
                        self._dispatch_single_request(
                            client, tenant_name, token, endpoint, is_warmup, records
                        )
                    )
                    in_flight.add(task)
                    task.add_done_callback(in_flight.discard)

                next_tick += interval
                sleep_time = next_tick - time.time()
                if sleep_time > 0:
                    await asyncio.sleep(sleep_time)
                else:
                    await asyncio.sleep(0.001)
        finally:
            if in_flight:
                await asyncio.gather(*in_flight, return_exceptions=True)

    async def execute_experiment_run(
        self,
        load_type: str,
        warmup_seconds: float = 2.0,
        run_seconds: float = 30.0,
    ) -> List[RequestRecord]:
        """
        Executes concurrent workloads for Tenant Beta and Tenant Acme:
        - 'quiet_baseline': Beta steady 2 RPS on GET /documents, Acme 0 traffic
        - 'harness_overhead': Beta steady 2 RPS on GET /health, Acme 0 traffic
        - 'high_volume': Beta steady 2 RPS on GET /documents, Acme 20 RPS on GET /documents
        - 'expensive': Beta steady 2 RPS on GET /documents, Acme bursts of 2 concurrent requests
                       every 5.0s on GET /documents/analytics/heavy-report (stays under 15/10s limit)
        """
        records: List[RequestRecord] = []
        limits = httpx.Limits(max_keepalive_connections=100, max_connections=200)
        timeout = httpx.Timeout(15.0, connect=5.0)

        async with httpx.AsyncClient(limits=limits, timeout=timeout) as client:
            tasks = []

            if load_type == "harness_overhead":
                # Beta requests to /health without auth
                tasks.append(
                    asyncio.create_task(
                        self._run_tenant_worker(
                            client=client,
                            tenant_name="beta",
                            token="",
                            endpoint="/health",
                            rate_rps=2.0,
                            warmup_seconds=warmup_seconds,
                            duration_seconds=run_seconds,
                            records=records,
                            burst_size=1,
                        )
                    )
                )
            else:
                # 1. Tenant Beta Worker (steady 2.0 req/s on normal documents endpoint)
                tasks.append(
                    asyncio.create_task(
                        self._run_tenant_worker(
                            client=client,
                            tenant_name="beta",
                            token=self.beta_token,
                            endpoint="/documents",
                            rate_rps=2.0,
                            warmup_seconds=warmup_seconds,
                            duration_seconds=run_seconds,
                            records=records,
                            burst_size=1,
                        )
                    )
                )

                # 2. Tenant Acme Worker (based on load_type)
                if load_type == "quiet_baseline":
                    # Acme sends 0 requests
                    pass
                elif load_type == "high_volume":
                    tasks.append(
                        asyncio.create_task(
                            self._run_tenant_worker(
                                client=client,
                                tenant_name="acme",
                                token=self.acme_token,
                                endpoint="/documents",
                                rate_rps=20.0,
                                warmup_seconds=warmup_seconds,
                                duration_seconds=run_seconds,
                                records=records,
                                burst_size=1,
                            )
                        )
                    )
                elif load_type == "expensive":
                    # Bursts of 2 concurrent expensive requests every 5.0s
                    # Over 30s: 6 bursts * 2 = 12 requests (4 req / 10s window < 15/10s limit)
                    tasks.append(
                        asyncio.create_task(
                            self._run_tenant_worker(
                                client=client,
                                tenant_name="acme",
                                token=self.acme_token,
                                endpoint="/documents/analytics/heavy-report",
                                rate_rps=0.4,  # 2 req every 5s = 0.4 rps with burst_size=2
                                warmup_seconds=warmup_seconds,
                                duration_seconds=run_seconds,
                                records=records,
                                burst_size=2,
                            )
                        )
                    )

            await asyncio.gather(*tasks)

        return records
