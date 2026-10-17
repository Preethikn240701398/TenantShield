"""
TenantShield - Noisy-Neighbour Experiment Orchestrator
======================================================
Manages standalone uvicorn server lifecycle, runs paced HTTP workloads,
measures per-tenant performance metrics, performs state resets between runs,
and exports traceable raw and aggregated results to results/.
"""

import asyncio
from datetime import datetime, timezone
import json
import logging
import math
import os
from pathlib import Path
import statistics
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional
import httpx

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(WORKSPACE_ROOT))

from app.core.config import settings
from loadtests.generator import HTTPWorkloadGenerator, RequestRecord
from scripts.system_info import get_cpu_info, get_ram_gb, get_services_info

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("tenantshield.noisy_neighbour_runner")

RESULTS_DIR = WORKSPACE_ROOT / "results"
RESULTS_DIR.mkdir(exist_ok=True)

# Plan: 30-second measurement window, 2-second warmup, 3 repeats
PLAN_WARMUP_SECONDS = 2.0
PLAN_RUN_SECONDS = 30.0
PLAN_NUM_REPEATS = 3
PLAN_BETA_RPS = 2.0
PLAN_BETA_EXPECTED = int(PLAN_BETA_RPS * PLAN_RUN_SECONDS)  # 60 samples


def calc_percentile(data: List[float], p: float) -> float:
    if not data:
        return 0.0
    sorted_data = sorted(data)
    k = (len(sorted_data) - 1) * (p / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return float(sorted_data[int(k)])
    d0 = sorted_data[int(f)] * (c - k)
    d1 = sorted_data[int(c)] * (k - f)
    return float(d0 + d1)


def calc_stats(values: List[float]) -> Dict[str, float]:
    if not values:
        return {"mean": 0.0, "min": 0.0, "max": 0.0, "std": 0.0}
    mean_val = statistics.mean(values)
    min_val = min(values)
    max_val = max(values)
    std_val = statistics.stdev(values) if len(values) > 1 else 0.0
    return {
        "mean": round(float(mean_val), 2),
        "min": round(float(min_val), 2),
        "max": round(float(max_val), 2),
        "std": round(float(std_val), 2),
    }


class ServerProcessManager:
    """Manages the standalone uvicorn server process."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8000, workers: int = 1):
        self.host = host
        self.port = port
        self.workers = workers
        self.base_url = f"http://{host}:{port}"
        self.process: Optional[subprocess.Popen] = None

    def start(self) -> None:
        """Launches the real uvicorn server as an independent OS process."""
        python_exe = sys.executable
        cmd = [
            python_exe,
            "-m",
            "uvicorn",
            "app.main:app",
            "--host",
            self.host,
            "--port",
            str(self.port),
            "--workers",
            str(self.workers),
        ]
        logger.info("Starting uvicorn server: %s", " ".join(cmd))
        env = os.environ.copy()
        env["PYTHONPATH"] = str(WORKSPACE_ROOT)
        env["APP_ENV"] = "development"
        env["ENABLE_APP_OWNERSHIP_CHECK"] = "true"
        env["ENABLE_DB_RLS"] = "true"
        env["ENABLE_QUERY_TENANT_FILTER"] = "true"

        self.log_file = open(WORKSPACE_ROOT / "loadtests_server.log", "w", encoding="utf-8")
        self.process = subprocess.Popen(
            cmd,
            cwd=str(WORKSPACE_ROOT),
            env=env,
            stdout=self.log_file,
            stderr=self.log_file,
        )

    def wait_until_ready(self, timeout_seconds: float = 15.0) -> bool:
        """Polls /health until the server responds with 200 OK."""
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            try:
                resp = httpx.get(f"{self.base_url}/health", timeout=1.0)
                if resp.status_code == 200:
                    logger.info("Server is ready and responding at %s", self.base_url)
                    return True
            except Exception:
                time.sleep(0.5)
        return False

    def stop(self) -> None:
        """Gracefully terminates the server process."""
        if self.process is not None:
            logger.info("Shutting down uvicorn server...")
            self.process.terminate()
            try:
                self.process.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                self.process.kill()
            self.process = None
        if hasattr(self, "log_file") and self.log_file:
            try:
                self.log_file.close()
            except Exception:
                pass


class NoisyNeighbourRunner:
    """Coordinates and executes the complete noisy-neighbour battery."""

    def __init__(self, server_url: str = "http://127.0.0.1:8000"):
        self.server_url = server_url
        self.admin_token = ""
        self.acme_token = ""
        self.beta_token = ""
        self.system_metadata: Dict[str, Any] = {}

    async def gather_system_metadata(self) -> None:
        """Gathers hardware and host environment information."""
        cpu = get_cpu_info()
        ram = get_ram_gb()
        services = await get_services_info()
        import platform
        self.system_metadata = {
            "cpu_model": cpu["model"],
            "core_count": cpu["logical_cores"],
            "ram_gb": ram,
            "windows_version": f"{platform.system()} {platform.release()} (Build {platform.version()})",
            "python_version": sys.version.split()[0],
            "postgres_version": services["postgres_version"],
            "memurai_version": services["memurai_version"],
            "server_workers": 1,
        }

    async def authenticate_tenants(self) -> None:
        """Logs in as admin, Acme, and Beta to retrieve JWT access tokens."""
        async with httpx.AsyncClient(base_url=self.server_url, timeout=10.0) as client:
            # 1. Admin login
            admin_resp = await client.post(
                "/auth/login",
                json={
                    "email": settings.DEV_ADMIN_USER_EMAIL,
                    "password": settings.DEV_ADMIN_USER_PASSWORD,
                },
            )
            assert admin_resp.status_code == 200, f"Admin login failed: {admin_resp.text}"
            self.admin_token = admin_resp.json()["access_token"]

            # 2. Acme login
            acme_resp = await client.post(
                "/auth/login",
                json={
                    "email": settings.DEV_ACME_USER_EMAIL,
                    "password": settings.DEV_ACME_USER_PASSWORD,
                },
            )
            assert acme_resp.status_code == 200, f"Acme login failed: {acme_resp.text}"
            self.acme_token = acme_resp.json()["access_token"]

            # 3. Beta login
            beta_resp = await client.post(
                "/auth/login",
                json={
                    "email": settings.DEV_BETA_USER_EMAIL,
                    "password": settings.DEV_BETA_USER_PASSWORD,
                },
            )
            assert beta_resp.status_code == 200, f"Beta login failed: {beta_resp.text}"
            self.beta_token = beta_resp.json()["access_token"]

        logger.info("Successfully authenticated Admin, Acme, and Beta tenants.")

    async def set_server_strategy(self, strategy_name: str) -> Dict[str, Any]:
        """Configures the limiter strategy on the live server via the admin API.
        Retries up to 3 times with a 3-second back-off to tolerate server saturation
        between high-volume runs. Returns the effective_config from the server response."""
        last_exc: Exception = RuntimeError("unreachable")
        for attempt in range(1, 4):
            try:
                async with httpx.AsyncClient(base_url=self.server_url, timeout=30.0) as client:
                    resp = await client.post(
                        "/admin/limiter/strategy",
                        headers={"Authorization": f"Bearer {self.admin_token}"},
                        json={"strategy": strategy_name},
                    )
                    assert resp.status_code == 200, f"Failed to set strategy: {resp.text}"
                    data = resp.json()
                    logger.info(
                        "Server limiter configured (attempt %d): strategy=%s effective_config=%s",
                        attempt, data.get("active_strategy"), data.get("effective_config"),
                    )
                    return data
            except Exception as exc:
                last_exc = exc
                logger.warning(
                    "set_server_strategy attempt %d failed (%s); retrying in 3s...", attempt, exc
                )
                await asyncio.sleep(3.0)
        raise RuntimeError(f"set_server_strategy failed after 3 attempts: {last_exc}") from last_exc

    async def reset_server_limits(self) -> None:
        """Resets limiter keys in Redis via the admin API."""
        async with httpx.AsyncClient(base_url=self.server_url, timeout=30.0) as client:
            resp = await client.post(
                "/admin/limiter/reset",
                headers={"Authorization": f"Bearer {self.admin_token}"},
            )
            assert resp.status_code == 200, f"Failed to reset limits: {resp.text}"

    def analyze_records(
        self,
        records: List[RequestRecord],
        expected_beta_requests: int = 60,
    ) -> Dict[str, Any]:
        """Analyzes measurement window records for Beta and Acme."""
        # Filter out warm-up records
        measured = [r for r in records if not r.is_warmup]

        beta_recs = [r for r in measured if r.tenant == "beta"]
        acme_recs = [r for r in measured if r.tenant == "acme"]

        # Beta client-side stats
        beta_count = len(beta_recs)
        beta_latencies = [r.duration_ms for r in beta_recs]
        beta_p50 = calc_percentile(beta_latencies, 50) if beta_latencies else 0.0
        beta_p95 = calc_percentile(beta_latencies, 95) if beta_latencies else 0.0
        beta_errors = sum(1 for r in beta_recs if r.status_code >= 400)
        beta_error_rate = (beta_errors / beta_count) if beta_count > 0 else 0.0

        # Beta server-side duration stats (from X-Process-Time-Ms header)
        beta_server_durs = [r.server_duration_ms for r in beta_recs if r.server_duration_ms is not None]
        beta_server_p50 = calc_percentile(beta_server_durs, 50) if beta_server_durs else None
        beta_server_p95 = calc_percentile(beta_server_durs, 95) if beta_server_durs else None

        # Check if Beta sent the expected number of requests
        count_flag = abs(beta_count - expected_beta_requests) > 2  # allow ±2 tolerance for 30s window

        # Acme stats
        acme_count = len(acme_recs)
        acme_429 = sum(1 for r in acme_recs if r.status_code == 429)
        acme_timeouts = sum(1 for r in acme_recs if r.status_code == 504)
        acme_errors = sum(1 for r in acme_recs if r.status_code >= 500 and r.status_code != 504)
        acme_200 = sum(1 for r in acme_recs if 200 <= r.status_code < 300)

        # Harness overhead stats (from /health requests)
        health_recs = [r for r in measured if r.endpoint == "/health"]
        health_latencies = [r.duration_ms for r in health_recs]
        health_p50 = calc_percentile(health_latencies, 50) if health_latencies else None
        health_server_durs = [r.server_duration_ms for r in health_recs if r.server_duration_ms is not None]
        health_server_p50 = calc_percentile(health_server_durs, 50) if health_server_durs else None

        return {
            "beta": {
                "request_count": beta_count,
                "expected_count": expected_beta_requests,
                "flagged": count_flag,
                "p50_ms": round(beta_p50, 2),
                "p95_ms": round(beta_p95, 2),
                "error_count": beta_errors,
                "error_rate": round(beta_error_rate, 4),
                "server_p50_ms": round(beta_server_p50, 2) if beta_server_p50 is not None else None,
                "server_p95_ms": round(beta_server_p95, 2) if beta_server_p95 is not None else None,
            },
            "acme": {
                "request_count": acme_count,
                "count_200": acme_200,
                "count_429": acme_429,
                "count_timeout": acme_timeouts,
                "count_errors": acme_errors,
            },
            "harness_overhead": {
                "health_client_p50_ms": round(health_p50, 2) if health_p50 is not None else None,
                "health_server_p50_ms": round(health_server_p50, 2) if health_server_p50 is not None else None,
                "health_count": len(health_recs),
            },
        }

    async def run_single_experiment(
        self,
        strategy_name: str,
        load_type: str,
        repeat_index: int,
        warmup_seconds: float = PLAN_WARMUP_SECONDS,
        run_seconds: float = PLAN_RUN_SECONDS,
    ) -> Dict[str, Any]:
        """Runs a single repeat of a (strategy, load_type) experiment."""
        logger.info(
            "--- Running Strategy='%s', LoadType='%s', Repeat=%d ---",
            strategy_name,
            load_type,
            repeat_index,
        )
        # Allow the single-worker server to drain any in-flight requests from the
        # previous run before issuing admin commands.
        await asyncio.sleep(2.0)
        strategy_response = await self.set_server_strategy(strategy_name)
        effective_config = strategy_response.get("effective_config", {})
        await self.reset_server_limits()

        generator = HTTPWorkloadGenerator(
            base_url=self.server_url,
            acme_token=self.acme_token,
            beta_token=self.beta_token,
        )

        records = await generator.execute_experiment_run(
            load_type=load_type,
            warmup_seconds=warmup_seconds,
            run_seconds=run_seconds,
        )

        expected_beta = int(PLAN_BETA_RPS * run_seconds)
        analysis = self.analyze_records(
            records=records,
            expected_beta_requests=expected_beta,
        )

        return {
            "strategy": strategy_name,
            "load_type": load_type,
            "repeat": repeat_index,
            "effective_config_at_run": effective_config,
            "metrics": analysis,
            "raw_records_count": len(records),
            "warmup_seconds": warmup_seconds,
            "run_seconds": run_seconds,
        }

    def aggregate_repeats(
        self,
        strategy_name: str,
        load_type: str,
        repeats: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Calculates mean, min, max, and std deviation across repeated runs."""
        beta_p50s = [r["metrics"]["beta"]["p50_ms"] for r in repeats]
        beta_p95s = [r["metrics"]["beta"]["p95_ms"] for r in repeats]
        beta_errs = [r["metrics"]["beta"]["error_rate"] for r in repeats]
        beta_counts = [r["metrics"]["beta"]["request_count"] for r in repeats]
        beta_flags = [r["metrics"]["beta"]["flagged"] for r in repeats]

        acme_429s = [r["metrics"]["acme"]["count_429"] for r in repeats]
        acme_timeouts = [r["metrics"]["acme"]["count_timeout"] for r in repeats]
        acme_errors = [r["metrics"]["acme"]["count_errors"] for r in repeats]
        acme_200s = [r["metrics"]["acme"]["count_200"] for r in repeats]

        # Server-side duration (if available)
        beta_server_p95s = [r["metrics"]["beta"]["server_p95_ms"] for r in repeats
                            if r["metrics"]["beta"]["server_p95_ms"] is not None]

        effective_configs = [r.get("effective_config_at_run", {}) for r in repeats]

        return {
            "strategy": strategy_name,
            "load_type": load_type,
            "repeats_count": len(repeats),
            "beta_request_counts": beta_counts,
            "beta_count_flagged": any(beta_flags),
            "beta_p50_ms": calc_stats(beta_p50s),
            "beta_p95_ms": calc_stats(beta_p95s),
            "beta_error_rate": calc_stats(beta_errs),
            "beta_server_p95_ms": calc_stats(beta_server_p95s) if beta_server_p95s else None,
            "acme_429": calc_stats(acme_429s),
            "acme_timeouts": calc_stats(acme_timeouts),
            "acme_errors": calc_stats(acme_errors),
            "acme_200": calc_stats(acme_200s),
            "effective_config_sample": effective_configs[0] if effective_configs else {},
        }

    async def execute_full_suite(
        self,
        smoke_test: bool = True,
        num_repeats: int = PLAN_NUM_REPEATS,
        warmup_seconds: float = PLAN_WARMUP_SECONDS,
        run_seconds: float = PLAN_RUN_SECONDS,
    ) -> Dict[str, Any]:
        """Executes Smoke Test, quiet_baseline, harness_overhead, and full strategy matrix."""
        await self.gather_system_metadata()
        await self.authenticate_tenants()

        # 1. Smoke Test
        if smoke_test:
            logger.info("=== Starting Smoke Test ===")
            smoke_res = await self.run_single_experiment(
                strategy_name="request_count",
                load_type="high_volume",
                repeat_index=0,
                warmup_seconds=2.0,
                run_seconds=10.0,
            )
            logger.info("Smoke Test completed: %s", smoke_res["metrics"])

        all_raw_runs: List[Dict[str, Any]] = []
        aggregated_summaries: List[Dict[str, Any]] = []

        # ----------------------------------------------------------------
        # 2. QUIET-ONLY baseline: Beta alone at 2 req/s, no Acme
        # ----------------------------------------------------------------
        logger.info("=== Running QUIET-ONLY Baseline ===")
        quiet_repeats = []
        for rep in range(1, num_repeats + 1):
            run_result = await self.run_single_experiment(
                strategy_name="none",
                load_type="quiet_baseline",
                repeat_index=rep,
                warmup_seconds=warmup_seconds,
                run_seconds=run_seconds,
            )
            run_result["strategy_label"] = "Quiet-Only Baseline (Beta alone)"
            quiet_repeats.append(run_result)
            all_raw_runs.append(run_result)

        quiet_summary = self.aggregate_repeats("none", "quiet_baseline", quiet_repeats)
        quiet_summary["strategy_label"] = "Quiet-Only Baseline (Beta alone)"
        aggregated_summaries.append(quiet_summary)

        # ----------------------------------------------------------------
        # 3. HARNESS OVERHEAD: Beta hitting /health at 2 req/s, no auth
        # ----------------------------------------------------------------
        logger.info("=== Measuring Harness Overhead (/health) ===")
        overhead_repeats = []
        for rep in range(1, num_repeats + 1):
            run_result = await self.run_single_experiment(
                strategy_name="none",
                load_type="harness_overhead",
                repeat_index=rep,
                warmup_seconds=warmup_seconds,
                run_seconds=run_seconds,
            )
            run_result["strategy_label"] = "Harness Overhead (/health)"
            overhead_repeats.append(run_result)
            all_raw_runs.append(run_result)

        overhead_summary = self.aggregate_repeats("none", "harness_overhead", overhead_repeats)
        overhead_summary["strategy_label"] = "Harness Overhead (/health)"
        aggregated_summaries.append(overhead_summary)

        # ----------------------------------------------------------------
        # 4. Full strategy matrix: high_volume + expensive
        # ----------------------------------------------------------------
        strategies_phase1 = [
            ("none", "Baseline (No Limit)"),
            ("request_count", "Strategy A: Request-Count Limit"),
            ("concurrency", "Strategy B: Concurrency Limit"),
            ("statement_timeout", "Strategy C: Statement Timeout"),
        ]
        strategies_phase2 = [
            ("cost_budget", "Strategy D: Cost-Based Limit"),
            ("combined", "Strategy E: Combined Multi-Layer"),
        ]
        all_strategies = strategies_phase1 + strategies_phase2
        load_types = ["high_volume", "expensive"]

        for strat_key, strat_label in all_strategies:
            for l_type in load_types:
                strat_repeats = []
                for rep in range(1, num_repeats + 1):
                    run_result = await self.run_single_experiment(
                        strategy_name=strat_key,
                        load_type=l_type,
                        repeat_index=rep,
                        warmup_seconds=warmup_seconds,
                        run_seconds=run_seconds,
                    )
                    run_result["strategy_label"] = strat_label
                    strat_repeats.append(run_result)
                    all_raw_runs.append(run_result)

                summary = self.aggregate_repeats(strat_key, l_type, strat_repeats)
                summary["strategy_label"] = strat_label
                aggregated_summaries.append(summary)

        # Persist results
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        raw_json_path = RESULTS_DIR / f"noisy_neighbour_runs_{timestamp}.json"
        summary_json_path = RESULTS_DIR / f"noisy_neighbour_summary_{timestamp}.json"
        summary_csv_path = RESULTS_DIR / f"noisy_neighbour_summary_{timestamp}.csv"

        payload_raw = {
            "title": "TenantShield Noisy-Neighbour Experiment Runs (Raw)",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "environment": self.system_metadata,
            "plan": {
                "warmup_seconds": warmup_seconds,
                "run_seconds": run_seconds,
                "num_repeats": num_repeats,
                "beta_rps": PLAN_BETA_RPS,
                "beta_expected_requests_per_run": int(PLAN_BETA_RPS * run_seconds),
                "measurement_window_note": f"{run_seconds}s window → ~{int(PLAN_BETA_RPS * run_seconds)} Beta samples per run",
            },
            "total_runs": len(all_raw_runs),
            "runs": all_raw_runs,
        }
        with open(raw_json_path, "w", encoding="utf-8") as f:
            json.dump(payload_raw, f, indent=2)

        payload_summary = {
            "title": "TenantShield Noisy-Neighbour Experiment Aggregated Summary",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "environment": self.system_metadata,
            "plan": payload_raw["plan"],
            "summaries": aggregated_summaries,
        }
        with open(summary_json_path, "w", encoding="utf-8") as f:
            json.dump(payload_summary, f, indent=2)

        # Write CSV
        import csv
        with open(summary_csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "strategy",
                "load_type",
                "strategy_label",
                "repeats",
                "beta_p50_mean",
                "beta_p50_spread",
                "beta_p95_mean",
                "beta_p95_spread",
                "beta_server_p95_mean",
                "beta_error_mean",
                "beta_error_spread",
                "beta_count_flagged",
                "acme_429_mean",
                "acme_429_spread",
                "acme_timeouts_mean",
                "acme_timeouts_spread",
                "acme_errors_mean",
                "effective_config",
            ])
            for s in aggregated_summaries:
                bp50 = s["beta_p50_ms"]
                bp95 = s["beta_p95_ms"]
                berr = s["beta_error_rate"]
                a429 = s["acme_429"]
                ato = s["acme_timeouts"]
                aerr = s["acme_errors"]
                srv_p95 = s.get("beta_server_p95_ms")
                writer.writerow([
                    s["strategy"],
                    s["load_type"],
                    s.get("strategy_label", ""),
                    s["repeats_count"],
                    bp50["mean"],
                    f"{bp50['min']}-{bp50['max']} (±{bp50['std']})",
                    bp95["mean"],
                    f"{bp95['min']}-{bp95['max']} (±{bp95['std']})",
                    srv_p95["mean"] if srv_p95 else "n/a",
                    berr["mean"],
                    f"{berr['min']}-{berr['max']} (±{berr['std']})",
                    s["beta_count_flagged"],
                    a429["mean"],
                    f"{a429['min']}-{a429['max']} (±{a429['std']})",
                    ato["mean"],
                    f"{ato['min']}-{ato['max']} (±{ato['std']})",
                    aerr["mean"],
                    json.dumps(s.get("effective_config_sample", {})),
                ])

        logger.info("Saved raw per-run results to %s", raw_json_path)
        logger.info("Saved aggregated summary to %s and %s", summary_json_path, summary_csv_path)

        return {
            "environment": self.system_metadata,
            "summaries": aggregated_summaries,
            "raw_json_file": str(raw_json_path),
            "summary_json_file": str(summary_json_path),
            "summary_csv_file": str(summary_csv_path),
        }


def print_comparison_table(summaries: List[Dict[str, Any]]) -> None:
    """Prints a clear terminal comparison table of the experiment results."""
    header = (
        f"{'Strategy':<24} | {'Load Type':<17} | {'Beta p50 ms':<19} | "
        f"{'Beta p95 ms':<19} | {'Err Rate':<12} | {'Acme 429s':<12} | {'Acme Timeouts':<14}"
    )
    sep = "-" * len(header)
    print("\n" + sep)
    print("NOISY-NEIGHBOUR ISOLATION EXPERIMENT RESULTS (OBSERVED DATA — 'in these runs')")
    print(sep)
    print(header)
    print(sep)
    for s in summaries:
        strat = s.get("strategy_label", s["strategy"])[:24]
        load = s["load_type"][:17]
        p50 = f"{s['beta_p50_ms']['mean']} (±{s['beta_p50_ms']['std']})"
        p95 = f"{s['beta_p95_ms']['mean']} (±{s['beta_p95_ms']['std']})"
        err = f"{s['beta_error_rate']['mean']}"
        a429 = f"{s['acme_429']['mean']} (±{s['acme_429']['std']})"
        ato = f"{s['acme_timeouts']['mean']} (±{s['acme_timeouts']['std']})"
        print(f"{strat:<24} | {load:<17} | {p50:<19} | {p95:<19} | {err:<12} | {a429:<12} | {ato:<14}")
    print(sep + "\n")


async def main():
    smoke_only = "--smoke-only" in sys.argv
    manager = ServerProcessManager(host="127.0.0.1", port=8000, workers=1)
    try:
        manager.start()
        if not manager.wait_until_ready(timeout_seconds=20.0):
            logger.error("Could not reach uvicorn server. Aborting.")
            sys.exit(1)

        runner = NoisyNeighbourRunner(server_url=manager.base_url)
        if smoke_only:
            logger.info("Executing smoke test only...")
            await runner.gather_system_metadata()
            await runner.authenticate_tenants()
            res = await runner.run_single_experiment(
                strategy_name="request_count",
                load_type="high_volume",
                repeat_index=1,
                warmup_seconds=2.0,
                run_seconds=10.0,
            )
            print("\nSMOKE TEST RESULT:")
            print(json.dumps(res, indent=2))
            return

        results = await runner.execute_full_suite(
            smoke_test=True,
            num_repeats=PLAN_NUM_REPEATS,
            warmup_seconds=PLAN_WARMUP_SECONDS,
            run_seconds=PLAN_RUN_SECONDS,
        )
        print_comparison_table(results["summaries"])
    finally:
        manager.stop()


if __name__ == "__main__":
    asyncio.run(main())
