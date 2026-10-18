"""
TenantShield - Part 5 Single Attack Demonstration Script
=========================================================
Executes a single, targeted cross-tenant attack between selected tenants
and reports the outcome, blocking control, and victim integrity state.

Rules:
- Refuses when APP_ENV is 'lab'.
- Refuses when target is not localhost or 127.0.0.1.
- Never prints passwords, tokens, canary strings, or document content.
- Cleanly deletes planted test documents at the end.
"""

import argparse
from datetime import datetime, timezone
import json
import os
import sys
from urllib.parse import urlparse
import uuid

import httpx

# Map tenant names to credential resolvers
def get_credentials(tenant_name: str) -> tuple[str, str]:
    tenant_lower = tenant_name.strip().lower()
    if "acme" in tenant_lower:
        email = os.getenv("DEMO_ACME_EMAIL", "acme_user@acme.test")
        password = os.getenv("DEMO_ACME_PASSWORD", "AcmeSecretPass123!")
        return email, password
    elif "beta" in tenant_lower:
        email = os.getenv("DEMO_BETA_EMAIL", "beta_user@beta.test")
        password = os.getenv("DEMO_BETA_PASSWORD", "BetaSecretPass123!")
        return email, password
    elif "demo" in tenant_lower:
        email = os.getenv("DEMO_COMPANY_EMAIL", "demo_user@democo.test")
        password = os.getenv("DEMO_COMPANY_PASSWORD", "DemoCoPass123!")
        return email, password
    else:
        raise ValueError(f"Unknown tenant: {tenant_name}")


def detect_blocking_control(status_code: int, response_text: str, action: str) -> str:
    """
    Infers which control produced the block from observable HTTP evidence.
    Mirrors verifier/runner.py logic.
    """
    if status_code == 403:
        return "ROLE_CHECK"
    if status_code == 401:
        return "TOKEN_TENANT_CONTEXT"
    if status_code == 404:
        return "unknown"  # could be ownership check, RLS, or decrypt failure
    return "unknown"


def emit_progress(step: int, total: int, message: str, progress_file: str | None = None) -> None:
    record = {
        "step": step,
        "total": total,
        "message": message,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    line = json.dumps(record)
    print(f"[{step}/{total}] {message}", flush=True)
    if progress_file:
        try:
            with open(progress_file, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description="TenantShield Single Attack Demo")
    parser.add_argument("--attacker", required=True, choices=["Acme", "Beta", "Demo Co"])
    parser.add_argument("--victim", required=True, choices=["Acme", "Beta", "Demo Co"])
    parser.add_argument("--action", required=True, choices=["read", "update", "delete", "create-into-victim"])
    parser.add_argument("--target-url", default="http://127.0.0.1:8000")
    parser.add_argument("--progress-file", default=None)
    parser.add_argument("--output-file", default=None)
    args = parser.parse_args()

    # Rule 1: Refuse when APP_ENV is lab
    app_env = (os.getenv("APP_ENV") or os.getenv("ENVIRONMENT") or "").lower()
    if app_env == "lab":
        print("Refused: Single attack demo is disabled when APP_ENV is lab.", file=sys.stderr)
        return 1

    # Rule 2: Refuse non-localhost target
    parsed = urlparse(args.target_url)
    hostname = (parsed.hostname or "").lower()
    if hostname not in ("localhost", "127.0.0.1", "::1"):
        print(f"Refused: Target must be localhost (got '{hostname}').", file=sys.stderr)
        return 1

    # Rule 3: Attacker and victim must differ
    if args.attacker == args.victim:
        print("Refused: Attacker and victim must be different tenants.", file=sys.stderr)
        return 1

    total_steps = 6
    client = httpx.Client(base_url=args.target_url, timeout=10.0)

    victim_token = None
    attacker_token = None
    victim_tenant_id = None
    canary_doc_id = None
    created_attack_doc_id = None

    try:
        # Step 1: Authenticate sessions
        emit_progress(1, total_steps, f"Authenticating {args.attacker} and {args.victim} sessions...", args.progress_file)
        vic_email, vic_pass = get_credentials(args.victim)
        vic_res = client.post("/auth/login", json={"email": vic_email, "password": vic_pass})
        if vic_res.status_code != 200:
            print(f"Authentication failed for victim tenant {args.victim}: {vic_res.status_code}", file=sys.stderr)
            return 1
        victim_token = vic_res.json()["access_token"]

        att_email, att_pass = get_credentials(args.attacker)
        att_res = client.post("/auth/login", json={"email": att_email, "password": att_pass})
        if att_res.status_code != 200:
            print(f"Authentication failed for attacker tenant {args.attacker}: {att_res.status_code}", file=sys.stderr)
            return 1
        attacker_token = att_res.json()["access_token"]

        # Get victim's tenant ID via /admin/dashboard/me or user profile
        vic_me = client.get("/admin/dashboard/me", headers={"Authorization": f"Bearer {victim_token}"})
        if vic_me.status_code == 200:
            victim_tenant_id = vic_me.json().get("tenant_id")

        # Step 2: Plant canary document as victim
        emit_progress(2, total_steps, f"Planting canary document in {args.victim}'s workspace...", args.progress_file)
        canary_secret = f"CANARY_SECRET_{uuid.uuid4().hex}"
        canary_title = f"Single Attack Canary {uuid.uuid4().hex[:8]}"

        plant_res = client.post(
            "/documents",
            json={"title": canary_title, "content": canary_secret},
            headers={"Authorization": f"Bearer {victim_token}"},
        )
        if plant_res.status_code != 201:
            print(f"Failed to plant canary document in victim workspace: {plant_res.status_code}", file=sys.stderr)
            return 1
        planted_data = plant_res.json()
        canary_doc_id = planted_data["id"]
        if not victim_tenant_id:
            victim_tenant_id = planted_data.get("tenant_id")

        # Step 3: Send attack request as attacker
        emit_progress(3, total_steps, f"Sending {args.action} attack from {args.attacker} against target resource...", args.progress_file)
        attack_status = 500
        attack_text = ""
        request_info = {}

        if args.action == "read":
            request_info = {"method": "GET", "path": f"/documents/{canary_doc_id}"}
            atk_res = client.get(
                f"/documents/{canary_doc_id}",
                headers={"Authorization": f"Bearer {attacker_token}"},
            )
            attack_status = atk_res.status_code
            attack_text = atk_res.text

        elif args.action == "update":
            request_info = {"method": "PUT", "path": f"/documents/{canary_doc_id}"}
            atk_res = client.put(
                f"/documents/{canary_doc_id}",
                json={"title": "TAMPERED_BY_ATTACKER", "content": "MALICIOUS_OVERWRITE_DATA"},
                headers={"Authorization": f"Bearer {attacker_token}"},
            )
            attack_status = atk_res.status_code
            attack_text = atk_res.text

        elif args.action == "delete":
            request_info = {"method": "DELETE", "path": f"/documents/{canary_doc_id}"}
            atk_res = client.delete(
                f"/documents/{canary_doc_id}",
                headers={"Authorization": f"Bearer {attacker_token}"},
            )
            attack_status = atk_res.status_code
            attack_text = atk_res.text

        elif args.action == "create-into-victim":
            request_info = {"method": "POST", "path": "/documents"}
            target_tid = str(victim_tenant_id) if victim_tenant_id else "00000000-0000-0000-0000-000000000000"
            atk_res = client.post(
                "/documents",
                json={
                    "title": "Injected Document",
                    "content": "Malicious payload planted in foreign workspace",
                    "tenant_id": target_tid,
                },
                headers={
                    "Authorization": f"Bearer {attacker_token}",
                    "X-Tenant-ID": target_tid,
                },
                params={"tenant_id": target_tid},
            )
            attack_status = atk_res.status_code
            attack_text = atk_res.text
            if attack_status == 201:
                try:
                    created_attack_doc_id = atk_res.json().get("id")
                except Exception:
                    pass

        # Step 4: Verify victim document integrity
        emit_progress(4, total_steps, f"Checking integrity of {args.victim}'s canary document...", args.progress_file)
        victim_check = client.get(
            f"/documents/{canary_doc_id}",
            headers={"Authorization": f"Bearer {victim_token}"},
        )

        victim_doc_state = "UNKNOWN"
        if victim_check.status_code == 200:
            doc_data = victim_check.json()
            if doc_data.get("title") == canary_title and doc_data.get("content") == canary_secret:
                victim_doc_state = "INTACT"
            else:
                victim_doc_state = "COMPROMISED"
        elif victim_check.status_code == 404:
            victim_doc_state = "OWNER_ACCESS_LOST"
        else:
            victim_doc_state = "COMPROMISED"

        # Check create-into-victim isolation
        visible_to_victim = False
        assigned_to_victim = False
        if args.action == "create-into-victim" and created_attack_doc_id:
            try:
                vic_read_created = client.get(
                    f"/documents/{created_attack_doc_id}",
                    headers={"Authorization": f"Bearer {victim_token}"},
                )
                if vic_read_created.status_code == 200:
                    visible_to_victim = True
                
                # Check assigned tenant id
                created_json = atk_res.json()
                if str(created_json.get("tenant_id")) == str(victim_tenant_id):
                    assigned_to_victim = True
            except Exception:
                pass

        # Step 5: Clean up planted documents
        emit_progress(5, total_steps, "Cleaning up planted test documents...", args.progress_file)
        if canary_doc_id and victim_token:
            try:
                client.delete(f"/documents/{canary_doc_id}", headers={"Authorization": f"Bearer {victim_token}"})
            except Exception:
                pass
        if created_attack_doc_id and attacker_token:
            try:
                client.delete(f"/documents/{created_attack_doc_id}", headers={"Authorization": f"Bearer {attacker_token}"})
            except Exception:
                pass

        # Step 6: Evaluate attack outcome
        emit_progress(6, total_steps, "Evaluating attack outcome...", args.progress_file)
        blocking_control = detect_blocking_control(attack_status, attack_text, args.action)

        if attack_status == 429:
            outcome = "INCONCLUSIVE"
            explanation = "Attack received HTTP 429; rate limiter obscured the isolation control."
        elif args.action in ("read", "update", "delete"):
            if attack_status in (200, 201, 204) or canary_secret in attack_text:
                outcome = "LEAKED"
                blocking_control = "none"
                explanation = f"Cross-tenant {args.action} attack succeeded (HTTP {attack_status}); victim isolation was bypassed."
            elif victim_doc_state != "INTACT":
                outcome = "LEAKED"
                blocking_control = "none"
                explanation = f"Victim resource was affected or lost (state: {victim_doc_state}); isolation failure detected."
            else:
                outcome = "BLOCKED"
                explanation = f"Cross-tenant {args.action} attack was blocked with HTTP {attack_status} ({blocking_control}); victim canary document remained intact."
        elif args.action == "create-into-victim":
            if attack_status == 201 and (visible_to_victim or assigned_to_victim):
                outcome = "LEAKED"
                blocking_control = "none"
                explanation = "Document injection into victim workspace succeeded; foreign tenant namespace was compromised."
            elif attack_status == 201:
                outcome = "BLOCKED"
                blocking_control = "TOKEN_TENANT_CONTEXT"
                explanation = "Document creation succeeded but was strictly bound to attacker's tenant; victim namespace remained untouched."
            else:
                outcome = "BLOCKED"
                explanation = f"Document creation attempt with spoofed tenant parameters was blocked with HTTP {attack_status} ({blocking_control})."

        result = {
            "request": request_info,
            "status_code": attack_status,
            "outcome": outcome,
            "blocking_control": blocking_control,
            "victim_doc_state": victim_doc_state,
            "explanation": explanation,
        }

        # Format and save output
        result_json = json.dumps(result, indent=2)
        print(result_json)

        if args.output_file:
            try:
                with open(args.output_file, "w", encoding="utf-8") as f:
                    f.write(result_json)
            except Exception as e:
                print(f"Could not write output file: {e}", file=sys.stderr)

        return 0
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())
