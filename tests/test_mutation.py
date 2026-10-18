"""
TenantShield - Isolation Mutation Testing Suite (pytest)
=======================================================
Validates safety refusals, baseline validation, revert mechanisms,
uncontextualized connection pool leakage, and individual mutation catches.
"""

from pathlib import Path
import pytest

from app.core.config import settings
from verifier.mutation import (
    check_baseline_state,
    IsolationMutationRunner,
    MutationSafetyError,
    query_db_evidence,
    verify_mutation_safety,
)


def test_01_safety_refusal_when_app_env_not_lab():
    """
    Validates that the mutation engine refuses to run when APP_ENV is not 'lab'.
    """
    orig_env = settings.APP_ENV
    try:
        settings.APP_ENV = "production"
        with pytest.raises(MutationSafetyError) as exc_info:
            verify_mutation_safety()
        assert "APP_ENV='lab'" in str(exc_info.value)
    finally:
        settings.APP_ENV = orig_env


def test_02_safety_refusal_when_db_not_lab():
    """
    Validates that the mutation engine refuses to run when the database is not 'tenantshield_lab'.
    """
    orig_env = settings.APP_ENV
    orig_lab_url = settings.LAB_DATABASE_URL
    try:
        settings.APP_ENV = "lab"
        settings.LAB_DATABASE_URL = "postgresql+asyncpg://tenantshield_app:pass@localhost:5432/tenantshield_db"
        with pytest.raises(MutationSafetyError) as exc_info:
            verify_mutation_safety()
        assert "tenantshield_lab" in str(exc_info.value)
    finally:
        settings.APP_ENV = orig_env
        settings.LAB_DATABASE_URL = orig_lab_url


@pytest.fixture
def lab_env():
    orig_env = settings.APP_ENV
    orig_environment = settings.ENVIRONMENT
    settings.APP_ENV = "lab"
    settings.ENVIRONMENT = "lab"
    try:
        yield
    finally:
        settings.APP_ENV = orig_env
        settings.ENVIRONMENT = orig_environment


def test_03_baseline_check_and_revert_verification(lab_env):
    """
    Validates that clean baseline state is verified, a mutation alters the state,
    and exiting the mutation block cleanly restores baseline state.
    """
    runner = IsolationMutationRunner()
    runner._reset_lab()

    # 1. Clean baseline check
    base_state = check_baseline_state(runner.admin_url)
    assert base_state["is_baseline"] is True, f"Baseline state invalid: {base_state}"
    assert base_state["rls_ok"] is True
    assert base_state["policy_condition_ok"] is True
    assert base_state["app_role_ok"] is True

    # 2. Inject mutation 3 (disable RLS)
    with runner._mutate_3_rls_not_enabled():
        mutated_evidence = query_db_evidence(runner.admin_url)
        assert mutated_evidence["relrowsecurity"] is False, "RLS should be disabled during mutation 3"

    # 3. Verify baseline restored after revert
    restored_state = check_baseline_state(runner.admin_url)
    assert restored_state["is_baseline"] is True, "Baseline must be restored after exiting mutation block"
    assert restored_state["rls_ok"] is True


@pytest.mark.asyncio
async def test_04_quick_mutation_rls_not_enabled_caught(lab_env):
    """
    Quick mutation test: Executes Mutation 3 (RLS not enabled on documents).
    Asserts:
    1. Isolated run reports leaks -> CAUGHT
    2. Masked run reports no leaks -> MASKED
    3. Baseline state is restored afterwards.
    """
    runner = IsolationMutationRunner()
    result = await runner.run_single_mutation(
        mutation_id="mut_3_rls_not_enabled",
        mutation_name="Mutation 3: RLS not enabled on documents table",
        description="Documents table has ROW LEVEL SECURITY disabled.",
        mutated_layer="Layer B (Database RLS Table Enforcement)",
        mutation_cm_factory=runner._mutate_3_rls_not_enabled,
    )

    assert result["isolated_outcome"] == "CAUGHT", f"Expected CAUGHT, got {result['isolated_outcome']}"
    assert result["isolated_run"]["total_leaks"] > 0, "Expected at least 1 leak in isolated run"
    assert result["masked_run"]["leak_detected"] is False, "Other layers must mask the flaw in masked run"
    assert result["baseline_restored"] is True, "Baseline must be restored"


@pytest.mark.asyncio
async def test_05_mutation_5_connection_pool_uncontextualized_leak(lab_env):
    """
    Validates Mutation 5 connection pooling context leakage:
    1. Tenant B sets session-level context (is_local=false) with pool_size=1.
    2. A subsequent request that sets NO tenant context queries the documents table.
    3. Confirms Tenant B's rows are returned due to connection context leakage.
    """
    runner = IsolationMutationRunner()
    runner._reset_lab()

    with runner._mutate_5_connection_pool_leakage():
        leak_res = await runner.execute_uncontextualized_leak_test()

        assert leak_res["context_leaked"] is True, "Tenant context should leak to uncontextualized request"
        assert leak_res["rows_returned_count"] > 0, "Rows should be returned under leaked context"
        assert any(r["tenant_id"] == leak_res["target_tenant_id"] for r in leak_res["rows_returned"])


@pytest.mark.slow
@pytest.mark.asyncio
async def test_06_full_isolation_mutation_run(lab_env):
    """
    Full isolation mutation testing suite across all 5 mutations.
    Marked as 'slow' so standard pytest runs remain fast.
    """
    runner = IsolationMutationRunner()
    report = await runner.run_all_mutations()

    assert report["total_injected"] == 5
    assert report["total_caught"] >= 1
    assert "isolation_mutation_score" in report
    assert len(report["mutations"]) == 5

    # Check that each mutation has evidence and baseline_restored
    for m in report["mutations"]:
        assert m["baseline_restored"] is True, f"Baseline not restored for {m['mutation_id']}"
        assert m["evidence"] is not None

    # Verify report files written to results/
    results_dir = Path(__file__).resolve().parent.parent / "results"
    report_json = list(results_dir.glob("mutation_report_*.json"))
    report_csv = list(results_dir.glob("mutation_report_*.csv"))
    assert len(report_json) > 0, "Expected mutation report JSON in results/"
    assert len(report_csv) > 0, "Expected mutation report CSV in results/"


@pytest.mark.asyncio
async def test_07_mutation_2_flipped_rls_masked_reports_no_leak_owner_access_lost(lab_env):
    """
    Validates Mutation 2 (flipped RLS policy):
    - In isolated run: Tenant A can read Tenant B's doc -> cross_tenant_leak='yes', CAUGHT
    - In masked run: Layer A blocks Tenant A, owner Tenant B cannot read own doc (RLS flipped),
      target row is intact in DB -> cross_tenant_leak='no', owner_access_lost='yes', leak_detected=False
    - Baseline restored cleanly.
    """
    runner = IsolationMutationRunner()
    result = await runner.run_single_mutation(
        mutation_id="mut_2_flipped_rls_policy",
        mutation_name="Mutation 2: RLS policy with condition flipped",
        description="PostgreSQL RLS policy uses 'tenant_id != current_setting(...)' allowing cross-tenant rows.",
        mutated_layer="Layer B (Database RLS Policy)",
        mutation_cm_factory=runner._mutate_2_flipped_rls_policy,
    )

    assert result["isolated_outcome"] == "CAUGHT"
    assert result["isolated_run"]["cross_tenant_leak"] == "yes"
    assert result["masked_run"]["leak_detected"] is False
    assert result["masked_run"]["cross_tenant_leak"] == "no"
    assert result["masked_run"]["owner_access_lost"] == "yes"
    assert result["baseline_restored"] is True
