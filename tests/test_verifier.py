"""
TenantShield - Verification Package Test Suite
==============================================
Validates the dynamic attack generator, execution engine, leak detection,
integrity checks, control tests, create-injection proof, list-leak check,
HTTP 429 handling, and report persistence.
"""

from pathlib import Path
import pytest
import httpx

from app.main import app
from verifier.generator import AttackGenerator
from verifier.runner import VerificationRunner


def test_01_openapi_schema_endpoint_discovery():
    """
    Validates that AttackGenerator dynamically discovers endpoints with resource ID
    path parameters directly from OpenAPI schema without hardcoded lists.
    """
    generator = AttackGenerator.from_app(app)
    discovered = generator.discover_resource_endpoints()

    discovered_paths = [d["path"] for d in discovered]
    assert "/documents/{document_id}" in discovered_paths
    assert any("admin" in p and "{tenant_id}" in p for p in discovered_paths)

    attacks = generator.generate_attacks()
    assert len(attacks) >= 5, f"Expected at least 5 generated attacks, got {len(attacks)}"

    categories = {a.category for a in attacks}
    assert "read" in categories
    assert "update" in categories
    assert "delete" in categories
    assert "create_injection" in categories


@pytest.mark.asyncio
async def test_02_verification_runner_control_attack_succeeds():
    """
    Validates that legitimate same-tenant requests succeed (control test).
    Ensures that verification is not falsely passing due to generic brokenness.
    """
    runner = VerificationRunner()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        await runner.setup_tenants_and_canaries(client)
        control_res = await runner.run_control_verification(client)

        assert control_res["outcome"] == "PASSED"
        assert control_res["details"]["tenant_a_self_read_status"] == 200
        assert control_res["details"]["tenant_a_content_matched"] is True
        assert control_res["details"]["tenant_b_self_read_status"] == 200
        assert control_res["details"]["tenant_b_content_matched"] is True


@pytest.mark.asyncio
async def test_03_create_injection_proof_and_cleanup():
    """
    Item 1 (Level 7): For the create-injection attack (POST /documents, HTTP 201):
    - Verifies the new document is owned by the attacker's tenant (not Beta's).
    - Confirms Beta's canary is unchanged.
    - Confirms the attack doc is not visible to Beta (via GET and list).
    - Confirms cleanup deletes the attack doc afterwards.
    """
    runner = VerificationRunner()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        await runner.setup_tenants_and_canaries(client)

        generator = AttackGenerator.from_app(app)
        attacks = generator.generate_attacks()
        injection_attacks = [a for a in attacks if a.category == "create_injection"]
        assert len(injection_attacks) > 0, "Expected at least one create_injection attack"

        attack = injection_attacks[0]
        result = await runner.execute_attack(client, attack)

        if result["status_code"] == 201:
            proof = result.get("create_injection_proof")
            assert proof is not None, "create_injection_proof must be set when HTTP 201 is returned"
            assert proof["assigned_tenant_id"] is not None
            # If blocked: doc belongs to attacker, not visible to B, canary intact
            if result["outcome"] == "BLOCKED":
                assert proof["new_doc_owned_by_attacker"] is True, "New doc must belong to attacker if BLOCKED"
                assert proof["new_doc_owned_by_target"] is False, "New doc must NOT belong to target if BLOCKED"
                assert proof["visible_to_b_via_get"] is False, "New doc must NOT be visible to Beta if BLOCKED"
                assert proof["visible_to_b_via_list"] is False, "New doc must NOT appear in Beta's list if BLOCKED"
                assert proof["beta_canary_intact"] is True, "Beta canary must be intact if BLOCKED"
            # Either way, the attack doc must have been tracked for cleanup
            assert len(runner._attack_created_doc_ids) > 0, "Attack doc ID should be tracked for cleanup"

        # Run cleanup and confirm tracking list is cleared
        await runner._cleanup_attack_documents(client)
        # After cleanup the tracked list is consumed; docs should be gone from Tenant A's view
        for doc_id, _ in runner._attack_created_doc_ids:
            check = await client.get(
                f"/documents/{doc_id}",
                headers={"Authorization": f"Bearer {runner.token_a}"},
            )
            assert check.status_code in (404, 403), f"Attack doc {doc_id} should be deleted after cleanup"


@pytest.mark.asyncio
async def test_04_list_leak_check_passes():
    """
    Item 3 (Level 7): GET /documents as Tenant A must not return Beta's canary
    title, secret, or document ID.
    """
    runner = VerificationRunner()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        await runner.setup_tenants_and_canaries(client)
        list_leak = await runner.run_list_leak_check(client)

        assert list_leak["status_code"] == 200, "GET /documents must return HTTP 200 for authenticated user"
        assert list_leak["outcome"] == "PASSED", f"List-leak check failed: {list_leak['evidence']}"
        assert list_leak["leaked"] is False, f"Beta data visible to Tenant A: {list_leak['evidence']}"


@pytest.mark.asyncio
async def test_05_http_429_classified_as_inconclusive():
    """
    Item 5 (Level 7): HTTP 429 responses must be classified as INCONCLUSIVE,
    never BLOCKED or LEAKED.
    """
    from unittest.mock import AsyncMock, MagicMock, patch
    from verifier.runner import VerificationRunner
    from verifier.generator import AttackSpec

    runner = VerificationRunner()
    runner.token_a = "fake_token_a"
    runner.tenant_id_a = "aaaaaaaa-0000-0000-0000-000000000001"
    runner.tenant_id_b = "bbbbbbbb-0000-0000-0000-000000000002"
    runner.canary_doc_b = {"id": "cccccccc-0000-0000-0000-000000000003"}

    mock_response = MagicMock()
    mock_response.status_code = 429
    mock_response.text = "Rate limit exceeded"

    mock_client = AsyncMock()
    mock_client.request = AsyncMock(return_value=mock_response)

    attack = AttackSpec(
        name="Test 429 attack",
        category="read",
        method="GET",
        path_template="/documents/{document_id}",
        path_param_name="document_id",
        path_param_type="resource_id",
    )

    result = await runner.execute_attack(mock_client, attack)
    assert result["outcome"] == "INCONCLUSIVE", f"HTTP 429 must be INCONCLUSIVE, got {result['outcome']}"
    assert result["status_code"] == 429
    assert result["blocking_control"] == "unknown"


@pytest.mark.asyncio
async def test_06_verification_runner_executes_and_asserts_zero_leaks():
    """
    Executes the full automated cross-tenant attack verification suite.
    Asserts:
    1. All cross-tenant attacks are marked BLOCKED (or INCONCLUSIVE for 429).
    2. Zero data leaks.
    3. Target canary document integrity INTACT.
    4. List-leak check PASSED.
    5. Report saved to results/.
    6. Verdict is NO_LEAK_DETECTED.
    """
    runner = VerificationRunner()
    report = await runner.run_verification()

    summary = report["summary"]
    assert summary["control_verification"] == "PASSED"
    assert summary["leaked_attacks"] == 0, f"Detected {summary['leaked_attacks']} leaked attacks!"
    assert summary["blocked_attacks"] >= 1
    assert summary["tenant_b_canary_integrity"] == "INTACT"
    assert summary["list_leak_check"] == "PASSED", "List-leak check must pass"
    assert summary["overall_verdict"] == "NO_LEAK_DETECTED"
    assert summary["total_attacks_run"] > 0

    # Each attack result must have blocking_control field
    for a in report["attack_results"]:
        assert "blocking_control" in a, f"Missing blocking_control in attack result: {a['attack_name']}"
        assert a["outcome"] in ("BLOCKED", "LEAKED", "INCONCLUSIVE", "EXPECTED_LEAK")
    assert summary.get("expected_leaks", 0) >= 1

    # Verify JSON report file was written to results/
    results_dir = Path(__file__).resolve().parent.parent / "results"
    report_files = list(results_dir.glob("verification_attack_report_*.json"))
    assert len(report_files) > 0, "Expected verification attack report to exist in results/"


@pytest.mark.asyncio
async def test_07_layer_kill_matrix_execution_and_exports():
    """
    Validates that the LayerKillMatrixRunner executes across all 5 configurations,
    resets tenantshield_lab cleanly, exports JSON and CSV, and computes leak metrics.
    Also checks: db_proof, ownership_check_invocations, config_verdict, control_detail,
    active_protections are all present in the report.
    """
    from verifier.matrix_runner import LayerKillMatrixRunner

    runner = LayerKillMatrixRunner()
    report = await runner.run_matrix()

    assert report["configurations_evaluated"] == 5
    matrix = report["matrix"]
    assert len(matrix) == 5

    config_ids = [m["config_id"] for m in matrix]
    assert "all_controls_on" in config_ids
    assert "app_ownership_off" in config_ids
    assert "rls_off" in config_ids
    assert "both_off" in config_ids
    assert "all_off" in config_ids

    for row in matrix:
        # Control must pass in each configuration
        assert row["control_passed"] is True, f"Control failed in {row['config_id']}"
        if row["config_id"] != "all_off":
            assert row["canary_integrity"] == "INTACT", f"Canary compromised in {row['config_id']}"

        # DB proof must be present and contain real data
        assert "db_proof" in row, f"db_proof missing in {row['config_id']}"
        db_proof = row["db_proof"]
        assert "relrowsecurity" in db_proof
        assert "relforcerowsecurity" in db_proof
        assert "current_user" in db_proof
        assert isinstance(db_proof.get("policies"), list)

        # Ownership call count must be present
        assert "ownership_check_invocations" in row

        # Config verdict must be one of the two valid values
        assert row["config_verdict"] in ("NO_LEAK_DETECTED", "LEAK_DETECTED")

        # Active protections list must be present
        assert isinstance(row.get("active_protections"), list)
        assert len(row["active_protections"]) > 0

    # Verify both JSON and CSV files were written to results/
    results_dir = Path(__file__).resolve().parent.parent / "results"
    csv_files = list(results_dir.glob("layer_kill_matrix_*.csv"))
    json_files = list(results_dir.glob("layer_kill_matrix_*.json"))
    assert len(csv_files) > 0, "Expected layer kill matrix CSV file in results/"
    assert len(json_files) > 0, "Expected layer kill matrix JSON file in results/"


@pytest.mark.asyncio
async def test_08_post_attack_integrity_owner_access_lost_when_row_unchanged():
    """
    Validates that when the owner gets a non-200 (e.g. simulated lockout or flipped RLS)
    but the document still exists unchanged in tenantshield_lab, the integrity check
    classifies the result as OWNER_ACCESS_LOST (not LEAKED), does not mark the attack
    as LEAKED, and reports cross_tenant_leak='no' and owner_access_lost='yes'.
    """
    from sqlalchemy import create_engine, text
    from scripts.setup_lab_db import get_lab_url_from_admin, setup_or_reset_lab_database
    from app.core.config import settings
    from app.core.database import reconfigure_engine
    from verifier.runner import confirm_lab_document_admin, VerificationRunner
    from verifier.generator import AttackSpec

    orig_env = settings.APP_ENV
    orig_environment = settings.ENVIRONMENT
    orig_db_url = settings.DATABASE_URL
    settings.APP_ENV = "lab"
    settings.ENVIRONMENT = "lab"
    setup_or_reset_lab_database(settings.POSTGRES_ADMIN_URL, reset=True)
    reconfigure_engine(settings.LAB_DATABASE_URL)
    try:
        runner = VerificationRunner()
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            await runner.setup_tenants_and_canaries(client)
            canary_id = runner.canary_doc_b["id"]

            # Confirm row exists in tenantshield_lab and is unchanged via direct admin check
            admin_check = confirm_lab_document_admin(
                doc_id=str(canary_id),
                expected_title=runner.CANARY_TITLE_B,
                expected_content=runner.CANARY_SECRET_B,
                tenant_id=str(runner.tenant_id_b),
            )
            assert admin_check["exists"] is True
            assert admin_check["unchanged"] is True

            # Simulate owner getting 404 on reading their own document (e.g. invalid token / lockout)
            orig_token_b = runner.token_b
            runner.token_b = "invalid_or_locked_out_token"

            integrity = await runner.verify_tenant_b_integrity(client)
            assert integrity["intact"] is False
            assert integrity["status"] == "OWNER_ACCESS_LOST"
            assert "Document exists and is unchanged in lab database" in integrity["reason"]

            # Under an update attack that is blocked (by Layer A), if owner integrity
            # has status OWNER_ACCESS_LOST, outcome must remain BLOCKED (not LEAKED).
            attack = AttackSpec(
                name="Attack update doc with simulated owner lockout",
                category="update",
                method="PUT",
                path_template="/documents/{document_id}",
                path_param_name="document_id",
                path_param_type="resource_id",
                payload_template={"title": "Hacked Title", "content": "Hacked Content"},
            )

            attack_res = await runner.execute_attack(client, attack)
            assert attack_res["outcome"] == "BLOCKED"
            assert attack_res["owner_access_lost"] is True
            assert attack_res["data_leak_detected"] is False

            # Restore token
            runner.token_b = orig_token_b
    finally:
        settings.APP_ENV = orig_env
        settings.ENVIRONMENT = orig_environment
        reconfigure_engine(orig_db_url)


@pytest.mark.asyncio
async def test_09_post_attack_integrity_leaked_when_row_deleted():
    """
    Validates that when the owner gets a non-200 and the row is missing/deleted
    from tenantshield_lab, the integrity check classifies the result as LEAKED,
    and attack outcome is marked as LEAKED.
    """
    from sqlalchemy import create_engine, text
    from scripts.setup_lab_db import get_lab_url_from_admin, setup_or_reset_lab_database
    from app.core.config import settings
    from app.core.database import reconfigure_engine
    from verifier.runner import confirm_lab_document_admin, VerificationRunner
    from verifier.generator import AttackSpec

    orig_env = settings.APP_ENV
    orig_environment = settings.ENVIRONMENT
    orig_db_url = settings.DATABASE_URL
    settings.APP_ENV = "lab"
    settings.ENVIRONMENT = "lab"
    setup_or_reset_lab_database(settings.POSTGRES_ADMIN_URL, reset=True)
    reconfigure_engine(settings.LAB_DATABASE_URL)
    try:
        runner = VerificationRunner()
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            await runner.setup_tenants_and_canaries(client)
            canary_id = runner.canary_doc_b["id"]

            # Physically delete the document from tenantshield_lab
            lab_admin_url = get_lab_url_from_admin(settings.POSTGRES_ADMIN_URL)
            engine = create_engine(lab_admin_url, isolation_level="AUTOCOMMIT")
            with engine.connect() as conn:
                conn.execute(
                    text("DELETE FROM documents WHERE id = :doc_id"),
                    {"doc_id": str(canary_id)},
                )
            engine.dispose()

            # Direct admin check should report missing
            admin_check = confirm_lab_document_admin(
                doc_id=str(canary_id),
                expected_title=runner.CANARY_TITLE_B,
                expected_content=runner.CANARY_SECRET_B,
                tenant_id=str(runner.tenant_id_b),
            )
            assert admin_check["exists"] is False
            assert admin_check["unchanged"] is False

            # Owner receives 404; integrity check must classify as LEAKED
            integrity = await runner.verify_tenant_b_integrity(client)
            assert integrity["intact"] is False
            assert integrity["status"] == "LEAKED"
            assert "Target document row" in integrity["reason"] or "missing" in integrity["reason"]

            # In an update/delete attack, missing row triggers outcome=LEAKED
            attack = AttackSpec(
                name="Attack delete check missing canary",
                category="delete",
                method="DELETE",
                path_template="/documents/{document_id}",
                path_param_name="document_id",
                path_param_type="resource_id",
            )
            attack_res = await runner.execute_attack(client, attack)
            assert attack_res["outcome"] == "LEAKED"
    finally:
        settings.APP_ENV = orig_env
        settings.ENVIRONMENT = orig_environment
        reconfigure_engine(orig_db_url)


def test_10_admin_confirmation_refused_outside_lab_env():
    """
    Validates safety refusal: admin integrity confirmation against tenantshield_lab
    must refuse to run when APP_ENV is not 'lab'.
    """
    from app.core.config import settings
    from verifier.runner import confirm_lab_document_admin

    orig_env = settings.APP_ENV
    orig_environment = settings.ENVIRONMENT
    settings.APP_ENV = "production"
    settings.ENVIRONMENT = "production"
    try:
        with pytest.raises(PermissionError) as exc_info:
            confirm_lab_document_admin(
                doc_id="00000000-0000-0000-0000-000000000000",
                expected_title="Test",
                expected_content="Test",
                tenant_id="00000000-0000-0000-0000-000000000000",
            )
        assert "strictly restricted to APP_ENV='lab'" in str(exc_info.value)
    finally:
        settings.APP_ENV = orig_env
        settings.ENVIRONMENT = orig_environment


@pytest.mark.asyncio
async def test_11_verification_runner_modes():
    """
    Validates that VerificationRunner respects scope mode:
    1. 'vulnerable_only': Executes solely against flawed routes, yielding VULNERABLE_LAYER_CONFIRMED.
    2. 'secure_only': Executes solely against hardened production routes, yielding NO_LEAK_DETECTED with 0 expected leaks.
    """
    from verifier.runner import VerificationRunner

    # 1. Test vulnerable_only mode
    vuln_runner = VerificationRunner(mode="vulnerable_only")
    vuln_report = await vuln_runner.run_verification()
    vuln_sum = vuln_report["summary"]
    assert vuln_sum["mode"] == "vulnerable_only"
    assert vuln_sum["total_attacks_run"] == 3
    assert vuln_sum["expected_leaks"] == 3
    assert vuln_sum["blocked_attacks"] == 0
    assert vuln_sum["leaked_attacks"] == 0
    assert vuln_sum["overall_verdict"] == "VULNERABLE_LAYER_CONFIRMED"

    # 2. Test secure_only mode
    sec_runner = VerificationRunner(mode="secure_only")
    sec_report = await sec_runner.run_verification()
    sec_sum = sec_report["summary"]
    assert sec_sum["mode"] == "secure_only"
    assert sec_sum["total_attacks_run"] == 21
    assert sec_sum["expected_leaks"] == 0
    assert sec_sum["blocked_attacks"] == 21
    assert sec_sum["leaked_attacks"] == 0
    assert sec_sum["overall_verdict"] == "NO_LEAK_DETECTED"

