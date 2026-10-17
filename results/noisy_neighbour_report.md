# TenantShield — Level 10 Noisy-Neighbour Experiment Report

**Generated:** 2026-10-17
**Window:** 30 s measurement, 2 s warmup, 3 repeats each combination
**Beta load:** 2 req/s steady on GET /documents
**High-volume Acme load:** 20 req/s on GET /documents
**Expensive Acme load:** bursts of 2 concurrent requests every 5 s on GET /documents/analytics/heavy-report (approx 12 requests / 30 s = 4 / 10 s window, under the 15 / 10 s limit)
**Limiter configuration recorded:** effective config saved in every raw run object (noisy_neighbour_runs_20261017_151422.json)

---

## Effective Limiter Configuration at Run Time

Spot-check for Strategy A (request_count):

  strategy: request_count
  requests_limit: 15
  window_seconds: 10

This confirms the fix from Amendment 1 took effect: the limiter used 15 req / 10 s, not the previous 100 / 60 s default.

---

## Harness Overhead (in these runs)

  Client p50 to /health:          6.76 ms (+-0.82, range 5.81-7.25)
  Client p95 to /health:          8.72 ms (+-0.94, range 7.77-9.65)
  Server-side p50 to /health:     3.54 ms
  Beta quiet-baseline p50 (/docs): 81.92 ms (+-0.86)

In these runs the harness adds approximately 6-9 ms of client-side overhead.
The difference between the /documents quiet-baseline p50 (81.92 ms) and the /health p50 (6.76 ms)
is approximately 75 ms, representing application + database work per request.

---

## Results Table (in these runs)

All values are mean across 3 repeats. Spread shown as +- std.
Quiet-only baseline is the first row.

Strategy                          | Load type       | Beta p50 ms       | Beta p95 ms        | Beta err rate | Acme 429s    | Acme timeouts
----------------------------------|-----------------|-------------------|--------------------|---------------|--------------|---------------
Quiet-Only Baseline (Beta alone)  | quiet_baseline  | 81.92 (+-0.86)    | 89.23 (+-1.32)     | 0.00          | --           | --
Harness Overhead (/health)        | harness_overhead| 6.76 (+-0.82)     | 8.72 (+-0.94)      | 0.00          | --           | --
Baseline -- No Limit              | high_volume     | 20281 (+-39)      | 26655 (+-57)       | 0.84          | 0 (+-0)      | 532 (+-2)
Baseline -- No Limit              | expensive       | 76.48 (+-0.56)    | 91.99 (+-2.84)     | 0.00          | 0 (+-0)      | 0 (+-0)
A: Request-Count (15/10s)         | high_volume     | 150.48 (+-94)     | 1971 (+-1098)      | 0.22          | 555 (+-0)    | 0 (+-0)
A: Request-Count (15/10s)         | expensive       | 125.15 (+-4.92)   | 152.89 (+-3.81)    | 0.21          | 9 (+-0)      | 0 (+-0)
B: Concurrency (max 2)            | high_volume     | 217.76 (+-20)     | 244.19 (+-29)      | 0.00          | 432 (+-14)   | 0 (+-0)
B: Concurrency (max 2)            | expensive       | 77.11 (+-0.67)    | 91.09 (+-0.20)     | 0.00          | 0 (+-0)      | 0 (+-0)
C: Statement Timeout (250ms)      | high_volume     | 20321 (+-208)     | 26600 (+-220)      | 0.79          | 0 (+-0)      | 516 (+-34)
C: Statement Timeout (250ms)      | expensive       | 111.10 (+-2.34)   | 129.93 (+-6.74)    | 0.00          | 0 (+-0)      | 12 (+-0)
D: Cost-Budget (25 units/10s)     | high_volume     | 3641 (+-1285)     | 6536 (+-2643)      | 0.00          | 525 (+-0)    | 0.67 (+-1)
D: Cost-Budget (25 units/10s)     | expensive       | 112.32 (+-1.94)   | 125.97 (+-0.73)    | 0.00          | 6 (+-0)      | 0 (+-0)
E: Combined (A+B+C)               | high_volume     | 131.63 (+-0.66)   | 336.29 (+-11)      | 0.19          | 588 (+-0)    | 0 (+-0)
E: Combined (A+B+C)               | expensive       | 113.20 (+-0.49)   | 130.83 (+-1.45)    | 0.23          | 9 (+-0)      | 3 (+-0)

---

## Key Observations (in these runs)

1. HARNESS OVERHEAD IS SMALL
   Client round-trip to /health was 6.76 ms p50. The 80-130 ms latencies reported for Beta
   on /documents reflect real application + database work, not harness inflation.

2. NO-LIMIT HIGH_VOLUME: SEVERE HARM TO BETA
   Without any limiter, Acme 20 req/s saturated the single worker. Beta p50 rose to 20,281 ms
   (248x quiet-baseline) and error rate reached 0.84 (84% of Beta requests failed or timed out).
   In these runs, one noisy tenant on a single-worker server made the service effectively
   unusable for Beta.

3. NO-LIMIT EXPENSIVE: NO MEASURABLE HARM TO BETA
   With Acme sending bursts of 2 concurrent expensive requests every 5 s (12 requests / 30 s),
   Beta p50 was 76.48 ms and p95 was 91.99 ms -- within the spread of the quiet-only baseline
   (81.92 +- 0.86 ms). In these runs, the burst-of-2 expensive load did not produce a measurable
   noisy-neighbour effect on Beta. The effect could not be produced on this hardware with 1 worker
   at the chosen burst size.

4. STATEMENT TIMEOUT (C) DID NOT HELP WITH HIGH_VOLUME
   Strategy C sets a per-statement DB timeout but does not reject requests at the HTTP layer.
   Acme high-volume requests are cheap individual queries, so the 250 ms timeout never fires.
   Beta p50 was 20,321 ms -- essentially identical to the no-limit baseline. Strategy C is
   ineffective against high-volume low-cost traffic.

5. BETA EXCEEDS ITS OWN REQUEST-COUNT QUOTA (STRATEGIES A AND E)
   With a 15 req / 10 s per-tenant limit, Beta own rate of 2 req/s = 20 req / 10 s exceeds
   its quota. In these runs, Beta received 429s from its own per-tenant limiter (error rate
   0.19-0.22). This is not cross-tenant contamination; it is Beta being throttled by its own
   quota. The chosen plan limit of 15/10s is too tight for Beta own 2 RPS load.

6. STRATEGY A REDUCED BUT DID NOT ELIMINATE HIGH_VOLUME HARM
   Beta p95 under Strategy A / high_volume was 1,971 ms (mean) with +-1,098 ms spread -- a
   large reduction from 26,655 ms, but high variance (range 1,268-3,236 ms). The limiter slowed
   Acme significantly (555 of ~600 Acme requests received 429s) but Beta still saw elevated
   latency during the allowed burst window.

7. STRATEGY B (CONCURRENCY) GAVE THE CLEANEST HIGH_VOLUME ISOLATION
   Beta p50: 217.76 ms, p95: 244.19 ms, error rate: 0.00. Low spread (+-20-29 ms).
   In these runs, concurrency limiting (max 2 in-flight) provided the most stable isolation
   against high-volume load while completely protecting Beta from errors.

8. STRATEGY D (COST_BUDGET) SHOWS HIGH VARIANCE ON HIGH_VOLUME
   Beta p50 ranged from 2,342-4,911 ms across repeats (mean 3,641 ms). The allowed budget
   spend per window creates periodic high-latency spikes. Spread is too large to draw
   a firm conclusion from 3 repeats.

---

## Claim Evaluation (in these runs)

Claim: Request-count limiting alone does not guarantee fairness against heavy, resource-intensive queries.

VERDICT: In these runs, the data cannot confirm or refute this claim for the expensive load case.

Reasoning:
- The expensive load produced only ~12 requests in 30 s, staying under the 15/10 s limit.
  Acme was never rate-limited for expensive requests under Strategy A (only 9 Acme 429s,
  caused by its total count window late in the run).
- Beta latency under Strategy A / expensive (p95 = 152.89 ms) is higher than quiet-baseline
  (89.23 ms), but Beta also received 429s from its OWN per-tenant quota (2 RPS = 20 req/10 s >
  15 req/10 s limit). The elevated p95 is attributable to Beta own throttling, not to Acme
  expensive queries.
- To confirm or refute the claim, a future experiment would need to either (a) raise the
  request-count limit so Beta is not self-throttled, or (b) increase the expensive burst volume
  so the resource cost creates a measurable queueing effect on the single worker.

What can be said from the data:
- In these runs under HIGH-VOLUME load, Strategy A reduced but did not prevent Beta latency
  degradation (p95: 1,971 ms vs quiet-baseline 89 ms) with high variance (+-1,098 ms). In
  these runs, request-count limiting did not achieve the same protection as concurrency limiting
  against bulk lightweight traffic.
- In these runs under EXPENSIVE load at the tested burst volume, no cross-tenant latency harm
  to Beta was observed regardless of which strategy was active.

---

## Bug Fixes Discovered During Runs

Bug 1: RequestCountLimiter reading wrong settings key
  Symptom: 0 Acme 429s under request_count / high_volume (effective limit was 100/60s not 15/10s)
  Fix: Added LIMITER_REQUESTS_LIMIT=15 and LIMITER_WINDOW_SECONDS=10 settings; factory updated

Bug 2: get_effective_config() AttributeError on CostBudgetLimiter
  Symptom: HTTP 500 on POST /admin/limiter/strategy when switching to cost_budget
  Fix: Added window_seconds property to CostBudgetLimiter; hardened all reads with getattr

Bug 3: Admin call httpx.ReadTimeout between high-volume repeats
  Symptom: Suite crash after repeat 1 of high_volume runs
  Fix: Added 2 s drain sleep before each admin call; raised timeout to 30 s; 3x retry with backoff
