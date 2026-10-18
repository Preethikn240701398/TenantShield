"""
TenantShield - Live Dynamic Noisy Neighbour Benchmark
======================================================
Executes real-time HTTP load generation across selected noisy and victim tenants,
measuring actual p50/p95 latency, error rates, 429 rate limit responses,
and server timeouts.
"""

import argparse
import asyncio
import json
import os
import sys
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Set
import httpx

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

TENANT_CREDENTIALS = {
    "acme": {
        "email": os.getenv("DEV_ACME_USER_EMAIL", "acme_user@acme.test"),
        "password": os.getenv("DEV_ACME_USER_PASSWORD", "AcmeSecretPassword123!"),
        "label": "Acme Corp",
    },
    "beta": {
        "email": os.getenv("DEV_BETA_USER_EMAIL", "beta_user@beta.test"),
        "password": os.getenv("DEV_BETA_USER_PASSWORD", "BetaSecretPassword123!"),
        "label": "Beta Industries",
    },
    "demo": {
        "email": os.getenv("DEMO_COMPANY_EMAIL", "demo_user@democo.test").lower().strip(),
        "password": os.getenv("DEMO_COMPANY_PASSWORD", "DemoCompanySecurePass123!"),
        "label": "Demo Co",
    },
}

STRATEGY_LABELS = {
    "none": "Baseline (No Limit)",
    "request_count": "Request Count (Token Bucket)",
    "concurrency": "Concurrency Limiter",
    "statement_timeout": "Statement Timeout",
    "cost_budget": "Cost Budget Limiter",
    "combined": "Combined Defense",
}


def percentile(values: List[float], pct: float) -> float:
    if not values:
        return 0.0
    sorted_vals = sorted(values)
    k = (len(sorted_vals) - 1) * (pct / 100.0)
    f = int(k)
    c = f + 1
    if c < len(sorted_vals):
        d0 = sorted_vals[f] * (c - k)
        d1 = sorted_vals[c] * (k - f)
        return round(d0 + d1, 2)
    return round(sorted_vals[f], 2)


async def authenticate(client: httpx.AsyncClient, email: str, password: str) -> str:
    res = await client.post("/auth/login", json={"email": email, "password": password})
    if res.status_code != 200:
        raise RuntimeError(f"Login failed for {email}: HTTP {res.status_code}")
    data = res.json()
    token = data.get("access_token")
    if not token:
        raise RuntimeError(f"No access token for {email}")
    return token


async def apply_strategy(client: httpx.AsyncClient, strategy: str) -> str:
    admin_email = os.getenv("DEV_ADMIN_EMAIL", "admin@tenantshield.test")
    admin_pass = os.getenv("DEV_ADMIN_PASSWORD", "PlatformAdminPassword123!")
    token = await authenticate(client, admin_email, admin_pass)
    res = await client.post(
        "/admin/limiter/strategy",
        headers={"Authorization": f"Bearer {token}"},
        json={"strategy": strategy},
    )
    if res.status_code == 200:
        return res.json().get("active_strategy", strategy)
    return strategy


async def send_single_request(
    client: httpx.AsyncClient,
    token: str,
    endpoint: str,
    records_list: List[Dict[str, Any]],
) -> None:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    t0 = time.perf_counter()
    status_code = 500
    server_duration_ms = None
    try:
        resp = await client.get(endpoint, headers=headers)
        status_code = resp.status_code
        val = resp.headers.get("x-process-time-ms")
        if val:
            try:
                server_duration_ms = float(val)
            except ValueError:
                pass
    except httpx.TimeoutException:
        status_code = 504
    except Exception:
        status_code = 500
    duration_ms = (time.perf_counter() - t0) * 1000.0

    records_list.append({
        "status_code": status_code,
        "duration_ms": duration_ms,
        "server_duration_ms": server_duration_ms,
        "timestamp": time.time(),
    })


async def run_tenant_pacer(
    client: httpx.AsyncClient,
    token: str,
    endpoint: str,
    rate_rps: float,
    burst_size: int,
    end_time: float,
    records_list: List[Dict[str, Any]],
    in_flight: Set[asyncio.Task],
) -> None:
    interval = (1.0 / rate_rps * burst_size) if rate_rps > 0 else 1.0
    next_tick = time.time()

    while time.time() < end_time:
        for _ in range(burst_size):
            task = asyncio.create_task(send_single_request(client, token, endpoint, records_list))
            in_flight.add(task)
            task.add_done_callback(in_flight.discard)

        next_tick += interval
        sleep_time = next_tick - time.time()
        if sleep_time > 0:
            await asyncio.sleep(sleep_time)
        else:
            await asyncio.sleep(0.005)


async def run_benchmark(
    noisy_key: str,
    victim_key: str,
    load_type: str,
    duration: float,
    strategy: Optional[str],
    target_url: str,
    progress_file_path: str,
):
    # Safety: localhost only
    parsed = urllib.parse.urlparse(target_url)
    hostname = (parsed.hostname or "").lower()
    if hostname not in ("127.0.0.1", "localhost"):
        print(f"[ERROR] Target host '{hostname}' must be 127.0.0.1 or localhost.", file=sys.stderr)
        sys.exit(1)

    noisy_info = TENANT_CREDENTIALS.get(noisy_key, TENANT_CREDENTIALS["acme"])
    victim_info = TENANT_CREDENTIALS.get(victim_key, TENANT_CREDENTIALS["beta"])

    limits = httpx.Limits(max_keepalive_connections=150, max_connections=300)
    timeout = httpx.Timeout(10.0, connect=3.0)

    progress_file = open(progress_file_path, "w", encoding="utf-8", buffering=1)

    async with httpx.AsyncClient(base_url=target_url, limits=limits, timeout=timeout) as client:
        active_strat = "request_count"
        if strategy:
            try:
                active_strat = await apply_strategy(client, strategy)
            except Exception as e:
                print(f"[WARN] Failed to apply strategy {strategy}: {e}", file=sys.stderr)

        # Authenticate
        noisy_token = await authenticate(client, noisy_info["email"], noisy_info["password"])
        victim_token = await authenticate(client, victim_info["email"], victim_info["password"])

        victim_records: List[Dict[str, Any]] = []
        noisy_records: List[Dict[str, Any]] = []
        in_flight: Set[asyncio.Task] = set()

        start_time = time.time()
        end_time = start_time + duration

        # Pacer parameters
        # Victim: steady 2 requests / sec on normal /documents
        # Noisy:
        #   high_volume: 12 RPS (with burst 3) on /documents -> quickly exceeds 15/10s rate limit
        #   expensive: 0.5 RPS (with burst 2) on /documents/analytics/heavy-report
        victim_pacer = asyncio.create_task(
            run_tenant_pacer(
                client=client,
                token=victim_token,
                endpoint="/documents",
                rate_rps=2.0,
                burst_size=1,
                end_time=end_time,
                records_list=victim_records,
                in_flight=in_flight,
            )
        )

        noisy_endpoint = "/documents/analytics/heavy-report" if load_type == "expensive" else "/documents"
        noisy_rps = 0.5 if load_type == "expensive" else 4.0
        noisy_burst = 2 if load_type == "expensive" else 2

        noisy_pacer = asyncio.create_task(
            run_tenant_pacer(
                client=client,
                token=noisy_token,
                endpoint=noisy_endpoint,
                rate_rps=noisy_rps,
                burst_size=noisy_burst,
                end_time=end_time,
                records_list=noisy_records,
                in_flight=in_flight,
            )
        )

        # Periodic progress reporter
        while time.time() < end_time:
            await asyncio.sleep(0.5)
            elapsed = round(time.time() - start_time, 1)
            v_count = len(victim_records)
            n_count = len(noisy_records)
            n_429 = sum(1 for r in noisy_records if r["status_code"] == 429)
            n_timeouts = sum(1 for r in noisy_records if r["status_code"] == 504)
            line = json.dumps({
                "type": "progress",
                "elapsed": elapsed,
                "duration": duration,
                "victim_reqs": v_count,
                "noisy_reqs": n_count,
                "noisy_429s": n_429,
                "noisy_timeouts": n_timeouts,
            })
            progress_file.write(line + "\n")
            progress_file.flush()

        # Await pacers
        await asyncio.gather(victim_pacer, noisy_pacer, return_exceptions=True)

        # Await remaining in-flight tasks up to 5s
        if in_flight:
            await asyncio.wait(in_flight, timeout=5.0)

        # Compute summary
        v_lats = [
            (r["server_duration_ms"] if r["server_duration_ms"] is not None else r["duration_ms"])
            for r in victim_records
            if r["status_code"] < 500
        ]
        v_errs = sum(1 for r in victim_records if r["status_code"] >= 500)
        v_total = len(victim_records) or 1
        v_p50 = percentile(v_lats, 50.0) if v_lats else 0.0
        v_p95 = percentile(v_lats, 95.0) if v_lats else 0.0
        v_err_rate = round((v_errs / v_total) * 100.0, 2)

        n_429 = sum(1 for r in noisy_records if r["status_code"] == 429)
        n_timeouts = sum(1 for r in noisy_records if r["status_code"] == 504)
        n_200 = sum(1 for r in noisy_records if r["status_code"] == 200)
        n_total = len(noisy_records)

        strat_label = STRATEGY_LABELS.get(active_strat, active_strat.replace("_", " ").title())

        summary = {
            "type": "summary",
            "status": "completed",
            "strategy": active_strat,
            "strategy_label": strat_label,
            "load_type": load_type,
            "noisy_tenant": noisy_info["label"],
            "victim_tenant": victim_info["label"],
            "duration_seconds": duration,
            "victim_p50_ms": v_p50,
            "victim_p95_ms": v_p95,
            "victim_error_rate": v_err_rate,
            "noisy_429": n_429,
            "noisy_timeouts": n_timeouts,
            "noisy_200": n_200,
            "noisy_total": n_total,
            "victim_total": len(victim_records),
            "timestamp": time.time(),
        }

        progress_file.write(json.dumps(summary) + "\n")
        progress_file.flush()
        progress_file.close()


def main():
    parser = argparse.ArgumentParser(description="Live Noisy Neighbour Dynamic Benchmark")
    parser.add_argument("--noisy-tenant", default="acme", choices=["acme", "beta", "demo"])
    parser.add_argument("--victim-tenant", default="beta", choices=["acme", "beta", "demo"])
    parser.add_argument("--load-type", default="high_volume", choices=["high_volume", "expensive"])
    parser.add_argument("--duration", type=float, default=10.0)
    parser.add_argument("--strategy", default=None)
    parser.add_argument("--target-url", default="http://127.0.0.1:8000")
    parser.add_argument("--progress-file", required=True)
    args = parser.parse_args()

    noisy = args.noisy_tenant.lower()
    victim = args.victim_tenant.lower()
    if noisy == victim:
        victim = "beta" if noisy != "beta" else "acme"

    asyncio.run(
        run_benchmark(
            noisy_key=noisy,
            victim_key=victim,
            load_type=args.load_type,
            duration=args.duration,
            strategy=args.strategy,
            target_url=args.target_url,
            progress_file_path=args.progress_file,
        )
    )


if __name__ == "__main__":
    main()
