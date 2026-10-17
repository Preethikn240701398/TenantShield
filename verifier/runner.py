"""
TenantShield - Verification Runner & Isolation Evaluator
========================================================
Orchestrates end-to-end verification of multi-tenant isolation boundaries.

Changes in this revision (Level 7 review):
- create_injection: queries ownership as both tenants, deletes attack docs afterwards.
  BLOCKED only if new doc belongs to attacker and Beta is unchanged.
- Verdict: NO_LEAK_DETECTED / LEAK_DETECTED. No 'verified secure' wording.
- List-leak check: GET /documents as Tenant A; fails if Beta data appears.
- HTTP 429 is INCONCLUSIVE (never BLOCKED), counted separately.
- Each attack result carries a blocking_control field.
- All attacks are real HTTP requests through httpx.ASGITransport (full app stack).
"""

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx

from app.core.config import settings
from app.main import app
from app.services.auth import AuthService
from verifier.generator import AttackGenerator, AttackSpec

logger = logging.getLogger("tenantshield.verifier")


def _detect_blocking_control(status_code: int, response_text: str, attack_category: str) -> str:
    """
    Infers which control produced the block from observable HTTP evidence.
    Cannot distinguish OWNERSHIP_CHECK vs RLS_FILTERED from a 404 alone,
    so those are labelled 'unknown'. 403 maps to ROLE_CHECK. 401 to TOKEN_TENANT_CONTEXT.
    """
    if status_code == 403:
        return "ROLE_CHECK"
    if status_code == 401:
        return "TOKEN_TENANT_CONTEXT"
    if status_code == 404:
        return "unknown"  # could be ownership check, RLS, or decrypt failure
    return "unknown"


class VerificationRunner:
    """
    Executes automated cross-tenant security verification against live application endpoints.
    """

    CANARY_SECRET_B = "CONFIDENTIAL_BETA_DATA_SECRET_9876"
    CANARY_TITLE_B = "Beta Confidential Research Project"
    CANARY_TITLE_A = "Acme Q3 Operational Plan"

    def __init__(self, base_url: str = "http://test"):
        self.base_url = base_url
        self.token_a: Optional[str] = None
        self.tenant_id_a: Optional[str] = None
        self.token_b: Optional[str] = None
        self.tenant_id_b: Optional[str] = None
        self.canary_doc_a: Optional[Dict[str, Any]] = None
        self.canary_doc_b: Optional[Dict[str, Any]] = None
        self.results: List[Dict[str, Any]] = []
        # (doc_id, auth_token) for documents created by attacks – deleted at end
        self._attack_created_doc_ids: List[Tuple[str, str]] = []

    async def setup_tenants_and_canaries(self, client: httpx.AsyncClient) -> None:
        """
        Provisions authenticated sessions and real canary documents for both tenants.
        """
        # 1. Authenticate Tenant A (Acme)
        login_res_a = await client.post(
            "/auth/login",
            json={
                "email": settings.DEV_ACME_USER_EMAIL,
                "password": settings.DEV_ACME_USER_PASSWORD,
            },
        )
        if login_res_a.status_code != 200:
            raise RuntimeError(f"Setup failed: Could not login Tenant A ({login_res_a.status_code}): {login_res_a.text}")
        login_data_a = login_res_a.json()
        self.token_a = login_data_a["access_token"]
        claims_a = AuthService.verify_token(self.token_a)
        self.tenant_id_a = str(claims_a["tenant_id"])

        # 2. Authenticate Tenant B (Beta)
        login_res_b = await client.post(
            "/auth/login",
            json={
                "email": settings.DEV_BETA_USER_EMAIL,
                "password": settings.DEV_BETA_USER_PASSWORD,
            },
        )
        if login_res_b.status_code != 200:
            raise RuntimeError(f"Setup failed: Could not login Tenant B ({login_res_b.status_code}): {login_res_b.text}")
        login_data_b = login_res_b.json()
        self.token_b = login_data_b["access_token"]
        claims_b = AuthService.verify_token(self.token_b)
        self.tenant_id_b = str(claims_b["tenant_id"])

        # 3. Provision Canary Document for Tenant A
        res_doc_a = await client.post(
            "/documents",
            json={"title": self.CANARY_TITLE_A, "content": "Internal operational procedures for Acme Corp."},
            headers={"Authorization": f"Bearer {self.token_a}"},
        )
        if res_doc_a.status_code != 201:
            raise RuntimeError(f"Setup failed: Could not create Tenant A canary document ({res_doc_a.status_code})")
        self.canary_doc_a = res_doc_a.json()

        # 4. Provision Canary Document for Tenant B (Contains high-sensitivity canary secret)
        res_doc_b = await client.post(
            "/documents",
            json={"title": self.CANARY_TITLE_B, "content": self.CANARY_SECRET_B},
            headers={"Authorization": f"Bearer {self.token_b}"},
        )
        if res_doc_b.status_code != 201:
            raise RuntimeError(f"Setup failed: Could not create Tenant B canary document ({res_doc_b.status_code})")
        self.canary_doc_b = res_doc_b.json()

    async def run_control_verification(self, client: httpx.AsyncClient) -> Dict[str, Any]:
        """
        Executes control requests where tenants access their own legitimate resources.
        Guarantees tests are not trivially succeeding due to broken endpoints.
        """
        assert self.canary_doc_a is not None and self.canary_doc_b is not None

        # Control 1: Tenant A reads their own document
        res_a = await client.get(
            f"/documents/{self.canary_doc_a['id']}",
            headers={"Authorization": f"Bearer {self.token_a}"},
        )
        passed_a = (
            res_a.status_code == 200
            and res_a.json().get("title") == self.CANARY_TITLE_A
        )

        # Control 2: Tenant B reads their own document
        res_b = await client.get(
            f"/documents/{self.canary_doc_b['id']}",
            headers={"Authorization": f"Bearer {self.token_b}"},
        )
        passed_b = (
            res_b.status_code == 200
            and res_b.json().get("content") == self.CANARY_SECRET_B
        )

        control_status = "PASSED" if (passed_a and passed_b) else "FAILED"
        return {
            "name": "Control Verification: Legitimate Same-Tenant Requests",
            "outcome": control_status,
            "details": {
                "tenant_a_self_read_status": res_a.status_code,
                "tenant_a_content_matched": passed_a,
                "tenant_b_self_read_status": res_b.status_code,
                "tenant_b_content_matched": passed_b,
            },
        }

    async def verify_tenant_b_integrity(self, client: httpx.AsyncClient) -> Dict[str, Any]:
        """
        Confirms Tenant B's canary document is intact, unmodified, and uncorrupted.
        """
        assert self.canary_doc_b is not None
        res = await client.get(
            f"/documents/{self.canary_doc_b['id']}",
            headers={"Authorization": f"Bearer {self.token_b}"},
        )
        if res.status_code != 200:
            return {"intact": False, "reason": f"Document missing or returned status {res.status_code}"}

        doc = res.json()
        if doc.get("title") != self.CANARY_TITLE_B:
            return {"intact": False, "reason": f"Document title modified to '{doc.get('title')}'"}
        if doc.get("content") != self.CANARY_SECRET_B:
            return {"intact": False, "reason": "Document content was overwritten or altered"}

        return {"intact": True, "reason": "Document content and title unaltered"}

    async def run_list_leak_check(self, client: httpx.AsyncClient) -> Dict[str, Any]:
        """
        As Tenant A, calls GET /documents and checks whether any of Tenant B's
        canary secret, title, or document ID appears in the response.
        """
        assert self.canary_doc_b is not None
        list_res = await client.get(
            "/documents",
            headers={"Authorization": f"Bearer {self.token_a}"},
        )
        evidence: List[str] = []
        leaked = False
        if list_res.status_code == 200:
            body = list_res.text
            if self.CANARY_SECRET_B in body:
                leaked = True
                evidence.append(f"Canary secret visible in GET /documents response")
            if self.CANARY_TITLE_B in body:
                leaked = True
                evidence.append(f"Canary title '{self.CANARY_TITLE_B}' visible in GET /documents response")
            canary_id = str(self.canary_doc_b["id"])
            docs = list_res.json() if isinstance(list_res.json(), list) else list_res.json().get("items", [])
            if any(str(d.get("id")) == canary_id for d in docs if isinstance(d, dict)):
                leaked = True
                evidence.append(f"Canary document ID {canary_id} in Tenant A's document list")
        else:
            evidence.append(f"GET /documents returned status {list_res.status_code}")
        return {
            "endpoint": "GET /documents",
            "status_code": list_res.status_code,
            "outcome": "FAILED" if leaked else "PASSED",
            "leaked": leaked,
            "evidence": evidence,
        }

    async def _cleanup_attack_documents(self, client: httpx.AsyncClient) -> None:
        """Deletes documents created by attacks (best-effort)."""
        for doc_id, token in self._attack_created_doc_ids:
            try:
                await client.delete(
                    f"/documents/{doc_id}",
                    headers={"Authorization": f"Bearer {token}"},
                )
            except Exception:
                pass

    async def execute_attack(self, client: httpx.AsyncClient, attack: AttackSpec) -> Dict[str, Any]:
        """
        Executes a single generated attack using Tenant A credentials against Tenant B targets.
        """
        assert self.canary_doc_b is not None

        # Resolve path parameters dynamically
        target_path = attack.path_template
        if attack.path_param_name:
            if attack.path_param_type == "tenant_id":
                target_path = target_path.replace(f"{{{attack.path_param_name}}}", str(self.tenant_id_b))
            else:
                target_path = target_path.replace(f"{{{attack.path_param_name}}}", str(self.canary_doc_b["id"]))

        # Resolve payload templates
        payload = None
        if attack.payload_template:
            payload = {}
            for k, v in attack.payload_template.items():
                if isinstance(v, str) and "{target_tenant_id}" in v:
                    payload[k] = v.replace("{target_tenant_id}", str(self.tenant_id_b))
                else:
                    payload[k] = v

        # Resolve query parameters
        params = None
        if attack.query_template:
            params = {
                k: (v.replace("{target_tenant_id}", str(self.tenant_id_b)) if isinstance(v, str) else v)
                for k, v in attack.query_template.items()
            }

        # Resolve headers
        headers = {"Authorization": f"Bearer {self.token_a}"}
        if attack.headers_template:
            for k, v in attack.headers_template.items():
                headers[k] = (v.replace("{target_tenant_id}", str(self.tenant_id_b)) if isinstance(v, str) else v)

        # Execute real HTTP request through the full ASGI stack (httpx.ASGITransport)
        res = await client.request(
            method=attack.method,
            url=target_path,
            json=payload,
            params=params,
            headers=headers,
        )

        response_text = res.text
        response_status = res.status_code

        # HTTP 429 is INCONCLUSIVE – the rate limiter may mask the real control
        if response_status == 429:
            return {
                "attack_name": attack.name,
                "category": attack.category,
                "method": attack.method,
                "target_path": target_path,
                "status_code": response_status,
                "outcome": "INCONCLUSIVE",
                "data_leak_detected": False,
                "leak_evidence": "HTTP 429 received; rate limiter may obscure the real control.",
                "integrity_check": None,
                "blocking_control": "unknown",
                "description": attack.description,
                "create_injection_proof": None,
            }

        # Leak detection: check response body for canary data
        data_leak_detected = False
        leak_evidence = None

        if self.CANARY_SECRET_B in response_text:
            data_leak_detected = True
            leak_evidence = f"Canary secret leaked in response body."
        elif self.CANARY_TITLE_B in response_text:
            data_leak_detected = True
            leak_evidence = f"Canary title '{self.CANARY_TITLE_B}' leaked in response body."

        # Outcome evaluation
        outcome = "BLOCKED"
        integrity_check = None
        blocking_control = "unknown"
        create_injection_proof: Optional[Dict[str, Any]] = None

        if attack.category in ("read", "update", "delete", "action"):
            if response_status in (200, 201, 204) or data_leak_detected:
                outcome = "LEAKED"
                blocking_control = "none"
            else:
                outcome = "BLOCKED"
                blocking_control = _detect_blocking_control(response_status, response_text, attack.category)

            if attack.category in ("update", "delete"):
                integrity = await self.verify_tenant_b_integrity(client)
                integrity_check = integrity
                if not integrity["intact"]:
                    outcome = "LEAKED"
                    blocking_control = "none"
                    leak_evidence = f"Integrity violation on Tenant B resource: {integrity['reason']}"

        elif attack.category == "create_injection":
            if response_status == 201:
                created_doc = res.json()
                new_doc_id = created_doc.get("id")
                assigned_tenant = created_doc.get("tenant_id")

                # Query B: is the new doc visible to Tenant B?
                b_read = await client.get(
                    f"/documents/{new_doc_id}",
                    headers={"Authorization": f"Bearer {self.token_b}"},
                )
                b_list = await client.get(
                    "/documents",
                    headers={"Authorization": f"Bearer {self.token_b}"},
                )
                b_list_data = b_list.json() if isinstance(b_list.json(), list) else b_list.json().get("items", [])
                visible_to_b_via_list = any(
                    str(d.get("id")) == str(new_doc_id) for d in b_list_data if isinstance(d, dict)
                )
                visible_to_b_via_get = b_read.status_code == 200

                # Query A: is the new doc visible to Tenant A?
                a_read = await client.get(
                    f"/documents/{new_doc_id}",
                    headers={"Authorization": f"Bearer {self.token_a}"},
                )
                visible_to_a = a_read.status_code == 200

                beta_integrity = await self.verify_tenant_b_integrity(client)

                create_injection_proof = {
                    "new_doc_id": new_doc_id,
                    "assigned_tenant_id": assigned_tenant,
                    "attacker_tenant_id": self.tenant_id_a,
                    "target_tenant_id": self.tenant_id_b,
                    "new_doc_owned_by_attacker": assigned_tenant == str(self.tenant_id_a),
                    "new_doc_owned_by_target": assigned_tenant == str(self.tenant_id_b),
                    "visible_to_b_via_get": visible_to_b_via_get,
                    "visible_to_b_via_list": visible_to_b_via_list,
                    "visible_to_a": visible_to_a,
                    "beta_canary_intact": beta_integrity["intact"],
                }

                # BLOCKED only if: new doc belongs to attacker, not visible to B, Beta unchanged
                if (
                    assigned_tenant == str(self.tenant_id_b)
                    or visible_to_b_via_get
                    or visible_to_b_via_list
                    or not beta_integrity["intact"]
                ):
                    outcome = "LEAKED"
                    blocking_control = "none"
                    leak_evidence = "Document created in or visible to Tenant B's namespace."
                else:
                    outcome = "BLOCKED"
                    blocking_control = "TOKEN_TENANT_CONTEXT"

                # Track for cleanup
                if new_doc_id:
                    self._attack_created_doc_ids.append((str(new_doc_id), self.token_a))
            else:
                outcome = "BLOCKED"
                blocking_control = _detect_blocking_control(response_status, response_text, "create_injection")

        return {
            "attack_name": attack.name,
            "category": attack.category,
            "method": attack.method,
            "target_path": target_path,
            "status_code": response_status,
            "outcome": outcome,
            "data_leak_detected": data_leak_detected,
            "leak_evidence": leak_evidence,
            "integrity_check": integrity_check,
            "blocking_control": blocking_control,
            "description": attack.description,
            "create_injection_proof": create_injection_proof,
        }

    async def run_verification(self) -> Dict[str, Any]:
        """
        Executes full verification workflow and returns structured results dictionary.
        """
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url=self.base_url) as client:
            # 1. Setup step
            await self.setup_tenants_and_canaries(client)

            # 2. Control verification
            control_result = await self.run_control_verification(client)
            if control_result["outcome"] != "PASSED":
                raise RuntimeError(f"Control verification failed: {control_result['details']}")

            # 3. Dynamic Attack Discovery from OpenAPI
            generator = AttackGenerator.from_app(app)
            discovered_endpoints = generator.discover_resource_endpoints()
            attacks = generator.generate_attacks()

            # 4. Execute all generated attacks
            attack_results = []
            for attack in attacks:
                result = await self.execute_attack(client, attack)
                attack_results.append(result)

            # 5. List-leak check
            list_leak_result = await self.run_list_leak_check(client)

            # 6. Final integrity check of Tenant B canary
            final_integrity = await self.verify_tenant_b_integrity(client)

            # 7. Delete documents created by attacks
            await self._cleanup_attack_documents(client)

            # Compile counts
            total_attacks = len(attack_results)
            blocked_count = sum(1 for a in attack_results if a["outcome"] == "BLOCKED")
            leaked_count = sum(1 for a in attack_results if a["outcome"] == "LEAKED")
            inconclusive_count = sum(1 for a in attack_results if a["outcome"] == "INCONCLUSIVE")
            list_leak_detected = list_leak_result["leaked"]
            if list_leak_detected:
                leaked_count += 1

            overall_verdict = (
                "NO_LEAK_DETECTED"
                if (leaked_count == 0 and final_integrity["intact"] and not list_leak_detected)
                else "LEAK_DETECTED"
            )

            now_iso = datetime.now(timezone.utc).isoformat()
            timestamp_slug = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

            report = {
                "suite": "TenantShield Verification Package: Dynamic Cross-Tenant Attack Verification",
                "generated_at_utc": now_iso,
                "environment": {
                    "database_url": settings.DATABASE_URL.split("@")[-1],
                    "redis_url": settings.REDIS_URL,
                    "target_app": settings.APP_NAME,
                },
                "discovered_endpoints": discovered_endpoints,
                "summary": {
                    "total_attacks_run": total_attacks,
                    "blocked_attacks": blocked_count,
                    "leaked_attacks": leaked_count,
                    "inconclusive_attacks": inconclusive_count,
                    "control_verification": control_result["outcome"],
                    "tenant_b_canary_integrity": "INTACT" if final_integrity["intact"] else "COMPROMISED",
                    "list_leak_check": list_leak_result["outcome"],
                    "overall_verdict": overall_verdict,
                },
                "control_verification": control_result,
                "list_leak_check": list_leak_result,
                "final_canary_integrity": final_integrity,
                "attack_results": attack_results,
            }

            # 6. Save JSON report to results/
            results_dir = Path(__file__).resolve().parent.parent / "results"
            results_dir.mkdir(parents=True, exist_ok=True)
            report_file = results_dir / f"verification_attack_report_{timestamp_slug}.json"

            with open(report_file, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)

            # 7. Print short console summary
            self._print_console_summary(report, report_file)
            return report

    def _print_console_summary(self, report: Dict[str, Any], report_file: Path) -> None:
        summary = report["summary"]
        print("\n" + "=" * 72)
        print(" TENANTSHIELD VERIFICATION PACKAGE -- ATTACK REPORT SUMMARY")
        print("=" * 72)
        print(f" Generated At       : {report['generated_at_utc']}")
        print(f" Control Check      : {summary['control_verification']}")
        print(f" Total Attacks Run  : {summary['total_attacks_run']}")
        print(f" Blocked            : {summary['blocked_attacks']}")
        print(f" Leaked             : {summary['leaked_attacks']}")
        print(f" Inconclusive (429) : {summary['inconclusive_attacks']}")
        print(f" List-Leak Check    : {summary['list_leak_check']}")
        print(f" Canary Integrity   : {summary['tenant_b_canary_integrity']}")
        print(f" Verdict            : {summary['overall_verdict']}")
        print("-" * 72)
        print(" ATTACK BREAKDOWN:")
        for a in report["attack_results"]:
            tag = {
                "BLOCKED": "[BLOCKED]",
                "LEAKED": "[LEAKED!]",
                "INCONCLUSIVE": "[INCONC.]",
            }.get(a["outcome"], "[???????]")
            ctrl = a.get("blocking_control", "unknown")
            print(
                f"  {tag:<10} {a['method']:<6} {a['target_path']:<35} "
                f"(HTTP {a['status_code']}) blocked_by={ctrl}"
            )
            if a.get("create_injection_proof"):
                proof = a["create_injection_proof"]
                print(
                    f"             create_injection: new_doc={proof['new_doc_id']} "
                    f"assigned_tenant={proof['assigned_tenant_id']} "
                    f"visible_to_b={proof['visible_to_b_via_get']} "
                    f"beta_canary_intact={proof['beta_canary_intact']}"
                )
        print("-" * 72)
        print(f" JSON Report  : {report_file}")
        print("=" * 72 + "\n")
