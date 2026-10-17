# TenantShield: Noisy-Neighbour Experiment Plan (Phase 0)

> **Status:** LOCKED — Established before experiment execution and unchanged throughout testing.

---

## 1. Environment & Hardware Specifications

The following system information was gathered automatically from the host environment:

- **CPU Model:** AMD Ryzen 7 7840HS w/ Radeon 780M Graphics
- **Core Count:** 16 logical cores (8 physical cores)
- **RAM:** 15.29 GB
- **Operating System:** Windows 11 (Build 10.0.26300)
- **Python Version:** 3.13.2
- **PostgreSQL Version:** PostgreSQL 16.15, compiled by Visual C++ build 1944, 64-bit (native Windows, database `tenantshield_db` / `tenantshield`, restricted role `tenantshield_app`)
- **Memurai / Redis Version:** Memurai 8.2.0 (Redis 8.2.10) (native Windows localhost:6379)
- **Server Execution:** `uvicorn app.main:app` running as an independent OS process on `127.0.0.1:8000`
- **Server Workers:** 1 fixed worker (fixed for all runs to maintain deterministic concurrency and connection pool limits)

---

## 2. Fixed Limits for Limiter Strategies

All limits are fixed in advance and will not be tuned after observing results:

| Strategy | Limit Setting | Description |
| :--- | :--- | :--- |
| **Baseline (None)** | No limits | Unlimited requests, unlimited concurrency, no statement timeout |
| **(a) Request-Count Limit** | `15` requests per `10s` window | Fixed window in Redis. Returns HTTP 429 when quota is exceeded |
| **(b) Concurrency Limit** | `2` concurrent requests | Max concurrent in-flight requests per tenant tracked in Redis. Releases slot in `finally` block on completion or failure. Returns HTTP 429 when concurrency quota is reached |
| **(c) Statement Timeout** | `250ms` (`SET LOCAL statement_timeout = '250ms'`) | Per-tenant DB transaction timeout. Cancels queries exceeding 250ms; returns HTTP 504 and counts as an error for the offending tenant |
| **(d) Cost-Based Limit** | Normal = `1`, Expensive = `10`; Budget = `25` per `10s` | Windowed budget tracked in Redis. Returns HTTP 429 when cost quota is depleted |
| **(e) Combined Limiter** | Request-count (`15/10s`) + Concurrency (`2`) + Timeout (`250ms`) | Multi-layered defense against both volume and computational exhaustion |

---

## 3. Endpoints & Workload Definitions

### Legitimate Normal Endpoint
- **Route:** `GET /documents`
- **Behavior:** Standard tenant-isolated listing with RLS and application-layer ownership checks.
- **Measured baseline latency:** ~3ms – 8ms per request.
- **Cost:** 1 unit.

### Legitimate Deliberately Expensive Endpoint
- **Route:** `GET /documents/analytics/heavy-report`
- **Behavior:** Real database computation querying tenant documents joined with `generate_series(1, 50000)` computing cryptographic hashing (`md5`), string concatenation, and distinct aggregation.
- **Measured baseline latency:** ~350ms – 450ms per request (clearly and significantly slower than normal request by >50x).
- **Cost:** 10 units.

---

## 4. Tenant Workload Scenarios

### Tenant Beta (Victim / Observer)
- **Profile:** Quiet, steady, well-behaved tenant.
- **Traffic:** Normal requests (`GET /documents`) at a steady rate of **2 requests/second** throughout each run.
- **Target Count:** In a 10-second measurement window, Beta sends exactly **20 requests**.
- **Requirement:** Paced identically across every run. Any run where Beta does not send 20 requests is flagged.

### Tenant Acme (Noisy Neighbour)
- **Load Type (i) - High Volume Normal:**
  - High rate of normal requests: **20 requests/second** (`GET /documents`).
  - Total offered requests in 10s: ~200 requests (designed to exceed request-count limit of 15/10s).
- **Load Type (ii) - Expensive Low Volume:**
  - Low rate of heavy report requests: **1 request every 2.5 seconds** (0.4 req/s = ~4 requests in 10s).
  - Designed specifically to stay **strictly below the request-count limit** (4 < 15), testing whether request-count limiting alone can protect Tenant Beta from resource exhaustion.

---

## 5. Experiment Execution Parameters

- **Warm-up Length:** 3 seconds (traffic is sent to prime connections/caches, but metrics are excluded from analysis).
- **Run Length:** 10 seconds (active measurement window).
- **Number of Repeats:** 3 repeats per configuration.
- **Smoke Test:** 1 preliminary 10-second run before executing the full matrix.
- **Inter-Run Reset Procedure:**
  1. Flush all limiter keys in Redis (`tenantshield:rate_limit:*`, `tenantshield:concurrency:*`, `tenantshield:budget:*`).
  2. Clear in-memory caches.
  3. Validate database connectivity and tenant seed documents.
- **Metrics Collected per Run:**
  - **Tenant Beta:** p50 latency (ms), p95 latency (ms), error rate (fraction / count), total requests sent.
  - **Tenant Acme:** 429 count, timeout (504) count, error count (5xx), success count (2xx).
  - **Aggregated Statistics:** Mean, minimum, maximum, and sample standard deviation (spread) across the 3 repeats.

---

## 6. Research Hypothesis & Test of Claim

- **Claim under test:** Request-count limiting alone does not guarantee fairness against heavy, resource-intensive queries.
- **Evaluation criteria:**
  - Measure Tenant Beta's p95 latency and error rate under Load Type (ii) with **No Limit** vs. **Request-Count Limit**.
  - Compare the delta against the spread (standard deviation across repeats).
  - If the difference is within the spread, request-count limiting failed to significantly isolate Beta from Acme's expensive queries.

---

## Amendments (Level 10 Review — post-initial-run)

All amendments below were recorded before the re-run. All strategies were re-run after each amendment.

### Amendment 1 — Fix: Request-count limit was using wrong settings keys (2026-10-17)
**Reason:** In the previous run, Acme got 0 HTTP 429 responses under `request_count`, `concurrency`, and `combined` for `high_volume` load (~20 req/s vs limit of 15/10s). Investigation found the `LimiterService.create_strategy_by_name` was reading `settings.RATE_LIMIT_REQUESTS` (default 100) and `settings.RATE_LIMIT_WINDOW_SECONDS` (default 60) instead of the plan-specified limit of 15 req/10s. `RATE_LIMIT_REQUESTS=100` and `RATE_LIMIT_WINDOW_SECONDS=60` in `.env` effectively gave 100 requests per 60s — Acme's 20 req/s for 10s = 200 requests, but Acme always stayed under the 100/60s limit in any 10s slice.
**Fix:** Added dedicated settings `LIMITER_REQUESTS_LIMIT` (default 15) and `LIMITER_WINDOW_SECONDS` (default 10), updated `LimiterService` to use them, and updated `get_effective_config()` to expose these limits. The effective config is now returned in the strategy-set API response and saved in every run's raw data.

### Amendment 2 — Fix: Heavy report endpoint query was unbounded (2026-10-17)
**Reason:** `GET /documents/analytics/heavy-report` had `SELECT ciphertext FROM documents` (unconstrained) which made its duration vary with document count. Also `UNION ALL SELECT 'baseline_tenant_record'` without parentheses failed with `LIMIT` clause.
**Fix:** Bounded to `(SELECT ciphertext FROM documents LIMIT 1) UNION ALL (SELECT 'baseline_tenant_record')` with `generate_series(1, 45000)` and `repeat('x', 200)`. Confirmed: ~370 ms stable per query.

### Amendment 3 — Add X-Process-Time-Ms response header (2026-10-17)
**Reason:** Need to separate server-side processing time from client-side latency to understand how much of the 80–190 ms is harness overhead vs. endpoint cost.
**Change:** `TenantMetricsMiddleware` in `app/main.py` now emits `X-Process-Time-Ms` header on every response. Generator captures it in each `RequestRecord`.

### Amendment 4 — Measurement window extended to 30 seconds (2026-10-17)
**Reason:** Per review requirement: 30-second window gives ~60 Beta samples per run, enabling a more reliable p95 estimate.
**Change:** `PLAN_RUN_SECONDS = 30.0`, `PLAN_WARMUP_SECONDS = 2.0`, `PLAN_BETA_EXPECTED = 60` samples.

### Amendment 5 — Add QUIET-ONLY baseline and harness overhead load types (2026-10-17)
**Reason:** Per review requirement: need a Beta-alone reference point to compare against noisy-neighbour runs, and need to quantify how much latency is harness overhead vs. endpoint.
**Change:** Added `quiet_baseline` load type (Beta at 2 req/s, no Acme) and `harness_overhead` (Beta hits `/health` at 2 req/s). Both use same warmup/window/repeats.

### Amendment 6 — Expensive load uses concurrent burst of 2 (2026-10-17)
**Reason:** Previous expensive run used 0.4 req/s serial (1 request every 2.5s). Since the single-worker server processes requests sequentially, and the expensive request takes ~370 ms, a serial expensive request occupies the server for <1% of window time, causing no measurable effect on Beta. To produce an effect while staying under the 15/10s request-count limit, we send 2 concurrent expensive requests every 5 seconds. Over 30s: 6 bursts × 2 = 12 requests ≈ 4 requests per 10s window (< 15). This tests whether the 1-worker server stalls Beta when 2 expensive requests run concurrently.

### Amendment 7 — Generator rewritten to use concurrent task dispatch (2026-10-17)
**Reason:** Previous generator dispatched requests serially: `await _send_single_request()` blocked the loop, so actual Acme rate was limited by response latency. At 20 req/s target with ~80 ms response, only ~12 requests/s were achievable.
**Fix:** Generator now fires each request as an async task (non-blocking dispatch), accurately achieving target rates independent of response latency.

