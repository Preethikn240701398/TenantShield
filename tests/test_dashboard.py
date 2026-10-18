"""
TenantShield - Level 11 Admin Dashboard & UI Endpoints Test Suite
==================================================================
Verifies:
1. Dashboard endpoints return 401 Unauthorized without a token.
2. Dashboard endpoints return 403 Forbidden for tenant users.
3. Dashboard endpoints return 200 OK for platform_admin.
4. Empty state is returned when results folder has no files.
5. Path traversal protection: fixed pattern resolution prevents reading arbitrary files.
6. Secret fields (tokens, passwords, DEK bytes, nonces, canary secrets) are absent from responses.
7. Document titles containing <script> are safely stored and returned as plain text.
8. Content-Security-Policy header is attached to /ui routes.
"""

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.api import dashboard

DASHBOARD_ENDPOINTS = [
    "/admin/dashboard/verification",
    "/admin/dashboard/layer-kill",
    "/admin/dashboard/mutation",
    "/admin/dashboard/noisy-neighbour",
    "/admin/dashboard/keys",
]


# ------------------------------------------------------------------------------
# 1. Authentication & Role Enforcement Tests
# ------------------------------------------------------------------------------
@pytest.mark.parametrize("endpoint", DASHBOARD_ENDPOINTS)
def test_01_dashboard_endpoints_require_authentication(client: TestClient, endpoint: str):
    """Calling dashboard endpoints without a bearer token must return HTTP 401."""
    resp = client.get(endpoint)
    assert resp.status_code == 401, f"Expected 401 for unauthenticated {endpoint}, got {resp.status_code}"


@pytest.mark.parametrize("endpoint", DASHBOARD_ENDPOINTS)
def test_02_dashboard_endpoints_forbidden_for_tenant_users(client: TestClient, acme_auth: dict, endpoint: str):
    """Calling dashboard endpoints with a tenant user token must return HTTP 403."""
    resp = client.get(endpoint, headers=acme_auth["headers"])
    assert resp.status_code == 403, f"Expected 403 for tenant user on {endpoint}, got {resp.status_code}"


@pytest.mark.parametrize("endpoint", DASHBOARD_ENDPOINTS)
def test_03_dashboard_endpoints_accessible_to_platform_admin(client: TestClient, admin_auth: dict, endpoint: str):
    """Calling dashboard endpoints with platform_admin token returns HTTP 200."""
    resp = client.get(endpoint, headers=admin_auth["headers"])
    assert resp.status_code == 200, f"Expected 200 for platform_admin on {endpoint}, got {resp.status_code}"
    data = resp.json()
    assert "status" in data
    assert data["status"] in ("success", "empty")


# ------------------------------------------------------------------------------
# 2. Empty State Handling Tests
# ------------------------------------------------------------------------------
def test_04_empty_state_when_results_directory_is_empty(client: TestClient, admin_auth: dict, tmp_path: Path, monkeypatch):
    """When the results folder contains no experiment files, endpoints return structured empty states with reproduction commands."""
    empty_dir = tmp_path / "empty_results"
    empty_dir.mkdir()
    monkeypatch.setattr(dashboard, "RESULTS_DIR", empty_dir)

    # 1. Verification empty state
    res_v = client.get("/admin/dashboard/verification", headers=admin_auth["headers"]).json()
    assert res_v["status"] == "empty"
    assert "python -m verifier.runner" in res_v["message"]

    # 2. Layer-kill empty state
    res_l = client.get("/admin/dashboard/layer-kill", headers=admin_auth["headers"]).json()
    assert res_l["status"] == "empty"
    assert "python -m verifier.layer_kill" in res_l["message"]

    # 3. Mutation empty state
    res_m = client.get("/admin/dashboard/mutation", headers=admin_auth["headers"]).json()
    assert res_m["status"] == "empty"
    assert "python scripts/run_mutation.py" in res_m["message"]

    # 4. Noisy-neighbour empty state
    res_n = client.get("/admin/dashboard/noisy-neighbour", headers=admin_auth["headers"]).json()
    assert res_n["status"] == "empty"
    assert "python -m loadtests.runner" in res_n["message"]


# ------------------------------------------------------------------------------
# 3. Path Traversal & File Pattern Isolation Tests
# ------------------------------------------------------------------------------
def test_05_path_isolation_and_fixed_pattern_resolution(tmp_path: Path, monkeypatch):
    """
    Verifies that get_latest_result_file only matches files with the exact
    expected prefix in the designated directory and refuses path traversal.
    """
    test_dir = tmp_path / "test_results"
    test_dir.mkdir()
    monkeypatch.setattr(dashboard, "RESULTS_DIR", test_dir)

    # Create dummy files
    (test_dir / "unrelated_secret.txt").write_text("secret_data", encoding="utf-8")
    (test_dir / "verification_attack_report_20261017_100000.json").write_text("{}", encoding="utf-8")
    (test_dir / "verification_attack_report_20261017_200000.json").write_text("{}", encoding="utf-8")

    # Prefix resolution must only find files matching the fixed prefix
    found = dashboard.get_latest_result_file("verification_attack_report")
    assert found is not None
    assert found.name == "verification_attack_report_20261017_200000.json"

    # Must return None for non-matching or arbitrary patterns
    assert dashboard.get_latest_result_file("unrelated_secret") is None
    assert dashboard.get_latest_result_file("../../etc/passwd") is None


# ------------------------------------------------------------------------------
# 4. Secret Absence and Data Sanitization Tests
# ------------------------------------------------------------------------------
def test_06_secret_fields_absent_from_dashboard_responses(client: TestClient, admin_auth: dict):
    """Verifies that cryptographic key material, nonces, tokens, and secrets are strictly absent from dashboard responses."""
    # Check Key status endpoint
    keys_resp = client.get("/admin/dashboard/keys", headers=admin_auth["headers"])
    assert keys_resp.status_code == 200
    keys_data = keys_resp.json()

    # Recursively check for forbidden keys in keys_data
    forbidden_terms = {"wrapped_dek", "wrapping_nonce", "ciphertext", "nonce", "master_key"}
    raw_text = keys_resp.text.lower()
    for term in forbidden_terms:
        assert term not in raw_text, f"Forbidden cryptographic term '{term}' leaked in keys response"

    # Check Verification endpoint
    verif_resp = client.get("/admin/dashboard/verification", headers=admin_auth["headers"])
    assert verif_resp.status_code == 200
    verif_text = verif_resp.text
    # Ensure no canary secret string like canary_... or eyJ... JWT is leaked
    assert "canary_acme" not in verif_text
    assert "canary_beta" not in verif_text


# ------------------------------------------------------------------------------
# 5. XSS Prevention & Plain Text Storage Test
# ------------------------------------------------------------------------------
def test_07_document_title_with_script_tag_stored_and_returned_as_plain_text(client: TestClient, acme_auth: dict):
    """
    A document title containing <script>alert(1)</script> must be stored verbatim
    and returned as plain text without rendering or execution vulnerabilities.
    """
    xss_title = "<script>alert('xss_attack')</script>"
    xss_content = "Safe content body testing xss resistance."

    # Create document
    create_resp = client.post(
        "/documents",
        headers=acme_auth["headers"],
        json={"title": xss_title, "content": xss_content},
    )
    assert create_resp.status_code == 201
    created_doc = create_resp.json()
    doc_id = created_doc["id"]

    try:
        # Title returned from POST is literal plain text
        assert created_doc["title"] == xss_title

        # Read back via GET /documents/{id}
        get_resp = client.get(f"/documents/{doc_id}", headers=acme_auth["headers"])
        assert get_resp.status_code == 200
        assert get_resp.json()["title"] == xss_title

        # Read back in list GET /documents
        list_resp = client.get("/documents", headers=acme_auth["headers"])
        assert list_resp.status_code == 200
        all_titles = [d["title"] for d in list_resp.json()]
        assert xss_title in all_titles
    finally:
        # Clean up
        client.delete(f"/documents/{doc_id}", headers=acme_auth["headers"])


# ------------------------------------------------------------------------------
# 6. Content-Security-Policy & UI Delivery Tests
# ------------------------------------------------------------------------------
def test_08_ui_routes_deliver_csp_header(client: TestClient):
    """Requests to /ui static pages must include the Content-Security-Policy header restricting scripts and styles to self."""
    resp = client.get("/ui/index.html")
    assert resp.status_code == 200
    assert "Content-Security-Policy" in resp.headers
    csp = resp.headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "script-src 'self'" in csp
    assert "style-src 'self'" in csp


def test_09_user_context_endpoint_returns_tenant_name(client: TestClient, acme_auth: dict, admin_auth: dict):
    """GET /admin/dashboard/me returns role, email, and human-readable tenant name for both tenant user and admin."""
    # Tenant user
    res_acme = client.get("/admin/dashboard/me", headers=acme_auth["headers"])
    assert res_acme.status_code == 200
    acme_data = res_acme.json()
    assert acme_data["email"] == "acme_user@acme.test"
    assert acme_data["role"] == "tenant_user"
    assert "Acme" in acme_data["tenant_name"]

    # Admin user
    res_admin = client.get("/admin/dashboard/me", headers=admin_auth["headers"])
    assert res_admin.status_code == 200
    admin_data = res_admin.json()
    assert admin_data["role"] == "platform_admin"


# ------------------------------------------------------------------------------
# 7. Glossary Verification & UI Element Reference Tests (Part 1)
# ------------------------------------------------------------------------------
def _extract_js_glossary_dict() -> dict:
    """Safely extracts and parses the GLOSSARY object from ui/glossary.js."""
    glossary_path = Path(__file__).resolve().parent.parent / "ui" / "glossary.js"
    assert glossary_path.exists(), "ui/glossary.js does not exist"
    content = glossary_path.read_text(encoding="utf-8")

    # Match GLOSSARY = { ... }; block
    start_marker = "var GLOSSARY = {"
    start_idx = content.find(start_marker)
    assert start_idx != -1, "GLOSSARY definition not found in ui/glossary.js"
    brace_start = start_idx + len("var GLOSSARY =")
    
    # Simple regex parse supporting escaped characters like \'
    import re
    term_pattern = re.compile(
        r"'(?P<key>(?:\\.|[^'])+)':\s*\{\s*"
        r"name:\s*'(?P<name>(?:\\.|[^'])*)',\s*"
        r"meaning:\s*'(?P<meaning>(?:\\.|[^'])*)',\s*"
        r"calculation:\s*'(?P<calculation>(?:\\.|[^'])*)',\s*"
        r"howToRead:\s*'(?P<howToRead>(?:\\.|[^'])*)'\s*\}",
        re.MULTILINE | re.DOTALL,
    )
    terms = {}
    for m in term_pattern.finditer(content):
        d = m.groupdict()
        terms[d["key"]] = d
    return terms


def test_10_glossary_defines_all_required_terms(client: TestClient):
    """Verifies ui/glossary.js exists, is served via /ui/glossary.js, and defines all required terms with meaning, calculation, and howToRead."""
    resp = client.get("/ui/glossary.js")
    assert resp.status_code == 200
    assert "Content-Security-Policy" in resp.headers

    terms = _extract_js_glossary_dict()
    assert len(terms) >= 32, f"Expected comprehensive glossary definitions, got {len(terms)} terms"

    required_terms = [
        "Verdict", "Attacks run", "Blocked", "Leaked", "Inconclusive",
        "Canary integrity", "INTACT", "COMPROMISED", "List-leak check",
        "Method", "GET", "POST", "PUT", "DELETE",
        "HTTP status", "201", "403", "404", "429",
        "Blocking control", "TOKEN_TENANT_CONTEXT", "ROLE_CHECK", "OWNERSHIP_CHECK",
        "RLS_FILTERED", "QUERY_TENANT_FILTER", "DECRYPT_FAILED", "unknown",
        "Layer A", "Layer B", "Layer C", "Layer A, B, C",
        "Configuration (a)", "Configuration (b)", "Configuration (c)", "Configuration (d)", "Configuration (e)",
        "Configuration (a) to (e)",
        "Read leaks", "Write leaks", "Update leaks", "Delete leaks", "Read, Write, Update and Delete leaks",
        "Active protections", "Mutation", "CAUGHT", "MISSED", "CAUGHT and MISSED",
        "Isolated run", "Masked run", "Isolated run and Masked run",
        "Detection method", "ATTACK_SUITE", "DEDICATED_PROBE", "Detection method (ATTACK_SUITE, DEDICATED_PROBE)",
        "Baseline restored", "p50", "p95", "the plus-minus spread",
        "Beta error rate", "Acme 429s", "Acme timeouts", "Quiet-only baseline", "Harness overhead",
        "none", "request-count", "concurrency", "statement timeout", "cost-based", "combined", "each limiter strategy",
        "quiet baseline", "high volume", "expensive", "each load type",
        "Requests", "Errors", "Average latency", "Requests, Errors and Average latency in Tenant metrics",
        "Key version", "Key status", "active", "retired", "destroyed", "Key status (active, retired, destroyed)"
    ]

    for req in required_terms:
        assert req in terms, f"Required term '{req}' missing from ui/glossary.js"
        entry = terms[req]
        assert len(entry["meaning"].strip()) > 0, f"Term '{req}' meaning is empty"
        assert len(entry["calculation"].strip()) > 0, f"Term '{req}' calculation is empty"
        assert len(entry["howToRead"].strip()) > 0, f"Term '{req}' howToRead is empty"


def test_11_all_ui_glossary_references_exist_in_glossary():
    """Verifies that every term referenced by data-glossary in ui/index.html and ui/app.js exists in the glossary."""
    terms = _extract_js_glossary_dict()
    ui_dir = Path(__file__).resolve().parent.parent / "ui"
    index_html = (ui_dir / "index.html").read_text(encoding="utf-8")
    app_js = (ui_dir / "app.js").read_text(encoding="utf-8")

    import re
    # Extract data-glossary="..." from index.html
    html_refs = set(re.findall(r'data-glossary="([^"]+)"', index_html))
    for ref in html_refs:
        assert ref in terms, f"UI index.html references '{ref}' which is missing from glossary"

    # Extract createInfoButton('...') calls in app.js
    js_refs = set(re.findall(r"createInfoButton\(['\"]([^'\"]+)['\"]\)", app_js))
    for ref in js_refs:
        # Check direct or normalized key presence
        assert ref in terms or ref.lower() in [k.lower() for k in terms], (
            f"app.js creates info button for '{ref}' which is missing from glossary"
        )


def test_12_glossary_text_renders_as_plain_text():
    """Verifies that glossary definitions, calculations, and examples are pure plain text without HTML tags."""
    terms = _extract_js_glossary_dict()
    import re
    html_tag_re = re.compile(r"<[^>]+>")

    for key, item in terms.items():
        for field in ("meaning", "calculation", "howToRead"):
            val = item[field]
            assert not html_tag_re.search(val), f"Term '{key}' field '{field}' contains unescaped HTML tag: {val}"

