# TenantShield — Results Summary

> All numbers below are read directly from the newest result files in `results/` and are reproduced exactly as they appear in those files (no rounding beyond file precision). The source file is named for each number.
>
> **These results describe specific experiment runs only. They do not prove or disprove system security.**

---

## 1. Verification Attack Suite

**Source file:** `results/verification_attack_report_20261017_172102.json`  
**Generated at UTC:** `2026-10-17T17:21:02.193902+00:00`

### Summary

| Field | Value |
|-------|-------|
| `total_attacks_run` | 7 |
| `blocked_attacks` | 5 |
| `leaked_attacks` | 3 |
| `inconclusive_attacks` | 0 |
| `control_verification` | PASSED |
| `tenant_b_canary_integrity` | COMPROMISED |
| `list_leak_check` | PASSED |
| `cross_tenant_leak` | yes |
| `owner_access_lost` | no |
| `overall_verdict` | LEAK_DETECTED |

### Per-Attack Outcomes

| Attack | Method | Path | Status | Outcome |
|--------|---------|------|--------|---------|
| Cross-Tenant Create Injection (Body Reference) | POST | `/documents` | 201 | BLOCKED (`TOKEN_TENANT_CONTEXT`) |
| Cross-Tenant Read | GET | `/documents/{document_id}` | 404 | BLOCKED |
| Cross-Tenant Update | PUT | `/documents/{document_id}` | 200 | LEAKED |
| Cross-Tenant Delete | DELETE | `/documents/{document_id}` | 204 | LEAKED |
| Cross-Tenant Action (rotate) | POST | `/admin/keys/{tenant_id}/rotate` | 403 | BLOCKED (`ROLE_CHECK`) |
| Cross-Tenant Action (shred) | POST | `/admin/keys/{tenant_id}/shred` | 403 | BLOCKED (`ROLE_CHECK`) |
| Cross-Tenant Create Injection (limiter/strategy) | POST | `/admin/limiter/strategy` | 403 | BLOCKED (`ROLE_CHECK`) |

**Interpretation (from file):** The update and delete attacks succeeded because the application lacked per-operation ownership checks for those HTTP methods when the query-filter layer was absent. The canary document row (`1caf588e-...`) does not exist in the database after the run (`admin_verification.exists: false`). The list endpoint (`GET /documents`) did not expose cross-tenant documents (`list_leak_check: PASSED`).

---

## 2. Layer-Kill Matrix

**Source file:** `results/layer_kill_matrix_20261017_172102.json`  
**Generated at UTC:** `2026-10-17T17:21:02.197697+00:00`  
**Target database:** `tenantshield_lab`  
**Overall verdict:** `LEAK_DETECTED`  
**Configurations evaluated:** 5

| Config | Layer A (App Check) | Layer B (DB RLS) | Layer C (Query Filter) | Total Leaks | Verdict |
|--------|---------------------|------------------|------------------------|-------------|---------|
| (a) All Controls ON | ON | ON | ON | 0 | NO_LEAK_DETECTED |
| (b) App Ownership OFF | OFF | ON | ON | 0 | NO_LEAK_DETECTED |
| (c) Database RLS OFF | ON | OFF | ON | 0 | NO_LEAK_DETECTED |
| (d) Both A+B OFF | OFF | OFF | ON | 0 | NO_LEAK_DETECTED |
| (e) All Controls OFF | OFF | OFF | OFF | 2 | LEAK_DETECTED |

**Leak breakdown for (e) All Controls OFF** (from `layer_note`):  
`read=0, write=0, update=1, delete=1`

**Active protections always on:** Envelope encryption (`DECRYPT_FAILED`) is always active and is listed as a protection in all configurations including (e).

**Interpretation:** In these runs, Layer C (application query filter) alone was sufficient to prevent leaks even with Layers A and B disabled. Two leaks (update, delete) appeared only when all three layers were off, because the envelope encryption AAD check catches cross-tenant reads but not cross-tenant writes or deletes.

---

## 3. Isolation Mutation Testing

**Source file:** `results/mutation_report_20261017_171820.json`  
**Run ID:** `mut_run_20261017_171820`  
**Timestamp:** `2026-10-17T17:18:20.722283+00:00`  
**Target database:** `tenantshield_lab` (environment: `lab`)  
**Redis:** Memurai Developer (localhost:6379)

### Score

| Metric | Value |
|--------|-------|
| `total_injected` | 5 |
| `total_caught` | 5 |
| `attack_suite_caught` | 4 |
| `dedicated_probe_caught` | 1 |
| `missed_mutations` | [] (none) |
| `isolation_mutation_score` | "4 caught by the attack suite and 1 caught by a dedicated probe, out of 5" |

**Baseline run verdict:** `NO_LEAK_DETECTED` (`leaks: 0`, `cross_tenant_leak: "no"`, `owner_access_lost: "no"`)

### Per-Mutation Details

| Mutation | Mutated Layer | Detection | Isolated: cross_tenant_leak | Isolated: owner_access_lost | Masked: cross_tenant_leak | Masked: owner_access_lost |
|----------|--------------|-----------|-----------------------------|-----------------------------|---------------------------|---------------------------|
| Mut 1: Query missing tenant filter | Layer C (App Query Filter) | ATTACK_SUITE | no | no | no | no |
| Mut 2: RLS policy condition flipped | Layer B (DB RLS Policy) | ATTACK_SUITE | no | yes | no | yes |
| Mut 3: RLS not enabled on table | Layer B (DB RLS Table) | ATTACK_SUITE | no | no | no | no |
| Mut 4: App connecting as BYPASSRLS role | Layer B Bypass (Role) | ATTACK_SUITE | no | no | no | no |
| Mut 5: Connection pool context leakage | Session / Pool | DEDICATED_PROBE | yes | no | no | no |

**Notes on Mutation 1 isolated run** (from file): `total_leaks: 3`, `overall_verdict: LEAK_DETECTED`, `canary_integrity: COMPROMISED`. Masked run: `masked_by_other_layers: true`, `canary_integrity: INTACT`.

**Notes on Mutation 2 isolated run** (from file): `total_leaks: 3`, `overall_verdict: LEAK_DETECTED`, `canary_integrity: COMPROMISED`. Masked run: `masked_by_other_layers: true`, `canary_integrity: OWNER_ACCESS_LOST`, `owner_access_lost: "yes"`. The flipped RLS condition (`tenant_id != current_setting(...)`) locked out the owning tenant but other layers prevented cross-tenant data exposure.

**Notes on Mutation 5** (from file): `uncontextualized_test.context_leaked: true`, `rows_returned_count: 1`. The dedicated probe confirmed context leaked through the connection pool; the attack suite reported 0 leaks from its HTTP-level checks (`cross_tenant_leak: "yes"` is set at the mutation level based on the probe result).

---

## 4. Noisy-Neighbour Experiment

**Source files:**  
- `results/noisy_neighbour_summary_20261017_151422.json` (aggregated numbers)  
- `results/noisy_neighbour_report.md` (narrative with table and claim evaluation)

**Generated at UTC:** `2026-10-17T15:14:22.805538+00:00`

### Environment (from file)

| Field | Value |
|-------|-------|
| `cpu_model` | AMD Ryzen 7 7840HS w/ Radeon 780M Graphics |
| `core_count` | 16 |
| `ram_gb` | 15.29 |
| `windows_version` | Windows 11 (Build 10.0.26300) |
| `python_version` | 3.13.2 |
| `postgres_version` | PostgreSQL 16.15, compiled by Visual C++ build 1944, 64-bit |
| `memurai_version` | Memurai 8.2.0 (Redis 8.2.10) |
| `server_workers` | 1 |

### Plan (from file)

| Field | Value |
|-------|-------|
| `warmup_seconds` | 2.0 |
| `run_seconds` | 30.0 |
| `num_repeats` | 3 |
| `beta_rps` | 2.0 |
| `beta_expected_requests_per_run` | 60 |

### Results Table (all values are mean across 3 repeats — from `noisy_neighbour_report.md`)

| Strategy | Load type | Beta p50 ms | Beta p95 ms | Beta err rate | Acme 429s | Acme timeouts |
|----------|-----------|-------------|-------------|---------------|-----------|---------------|
| Quiet-Only Baseline (Beta alone) | quiet_baseline | 81.92 (±0.86) | 89.23 (±1.32) | 0.00 | — | — |
| Harness Overhead (/health) | harness_overhead | 6.76 (±0.82) | 8.72 (±0.94) | 0.00 | — | — |
| Baseline (No Limit) | high_volume | 20,281 (±39) | 26,655 (±57) | 0.84 | 0 (±0) | 532 (±2) |
| Baseline (No Limit) | expensive | 76.48 (±0.56) | 91.99 (±2.84) | 0.00 | 0 (±0) | 0 (±0) |
| A: Request-Count (15/10s) | high_volume | 150.48 (±94) | 1,971 (±1,098) | 0.22 | 555 (±0) | 0 (±0) |
| A: Request-Count (15/10s) | expensive | 125.15 (±4.92) | 152.89 (±3.81) | 0.21 | 9 (±0) | 0 (±0) |
| B: Concurrency (max 2) | high_volume | 217.76 (±20) | 244.19 (±29) | 0.00 | 432 (±14) | 0 (±0) |
| B: Concurrency (max 2) | expensive | 77.11 (±0.67) | 91.09 (±0.20) | 0.00 | 0 (±0) | 0 (±0) |
| C: Statement Timeout (250ms) | high_volume | 20,321 (±208) | 26,600 (±220) | 0.79 | 0 (±0) | 516 (±34) |
| C: Statement Timeout (250ms) | expensive | 111.10 (±2.34) | 129.93 (±6.74) | 0.00 | 0 (±0) | 12 (±0) |
| D: Cost-Budget (25 units/10s) | high_volume | 3,641 (±1,285) | 6,536 (±2,643) | 0.00 | 525 (±0) | 0.67 (±1) |
| D: Cost-Budget (25 units/10s) | expensive | 112.32 (±1.94) | 125.97 (±0.73) | 0.00 | 6 (±0) | 0 (±0) |
| E: Combined (A+B+C) | high_volume | 131.63 (±0.66) | 336.29 (±11) | 0.19 | 588 (±0) | 0 (±0) |
| E: Combined (A+B+C) | expensive | 113.20 (±0.49) | 130.83 (±1.45) | 0.23 | 9 (±0) | 3 (±0) |

**Limiter effective config for Strategy A** (from file `effective_config_sample`): `requests_limit: 15`, `window_seconds: 10`.

### Key Observations (from `noisy_neighbour_report.md`, section "Key Observations")

- **No-limit high_volume:** Beta p50 rose to 20,281 ms (248× quiet-baseline) and error rate reached 0.84. In these runs, one noisy tenant on a single-worker server made the service effectively unusable for Beta.
- **Strategy B (Concurrency) gave the cleanest high-volume isolation:** Beta p50: 217.76 ms, p95: 244.19 ms, error rate: 0.00.
- **Strategy C (Statement Timeout) did not help with high_volume:** Beta p50 was 20,321 ms — essentially identical to the no-limit baseline.
- **Beta self-throttled under Strategy A and E:** With a 15/10s limit, Beta's own 2 req/s = 20 req/10s exceeded the quota, causing Beta to receive 429s from its own limiter (error rate 0.19–0.22). This is not cross-tenant contamination.
- **Claim (request-count limiting vs expensive queries):** `VERDICT: In these runs, the data cannot confirm or refute this claim for the expensive load case.` (from `noisy_neighbour_report.md`, Claim Evaluation section)

### Bugs Discovered During Runs (from `noisy_neighbour_report.md`)

1. **Bug 1:** `RequestCountLimiter` reading wrong settings key — effective limit was 100/60s not 15/10s. Fix: added `LIMITER_REQUESTS_LIMIT=15` and `LIMITER_WINDOW_SECONDS=10`.
2. **Bug 2:** `get_effective_config()` AttributeError on `CostBudgetLimiter` — HTTP 500 on strategy switch. Fix: added `window_seconds` property.
3. **Bug 3:** Admin call `httpx.ReadTimeout` between high-volume repeats. Fix: 2s drain sleep, 30s timeout, 3× retry with backoff.
