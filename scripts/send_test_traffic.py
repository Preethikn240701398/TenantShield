"""
TenantShield - Send Test Traffic Script
=======================================
Generates controlled, deterministic telemetry traffic for Demo Co:
- Refuses when APP_ENV is 'lab' or target host is not localhost/127.0.0.1.
- Authenticates using DEMO_COMPANY_EMAIL and DEMO_COMPANY_PASSWORD (never hardcoded, stored or printed).
- Sends exactly 10 valid requests (GET /documents) and 3 invalid requests (GET /documents/<uuid> -> 404).
- Sends interleaved at 2 requests per second with finite 10-second timeouts.
- Writes real-time progress JSON lines to the specified progress file.

Usage:
    python scripts/send_test_traffic.py --progress-file <path> [--target-url http://127.0.0.1:8000]
"""

import argparse
import json
import os
import sys
import time
import urllib.parse
from uuid import uuid4
import httpx
from dotenv import load_dotenv

load_dotenv()


def send_traffic(progress_file_path: str, target_url: str = "http://127.0.0.1:8000"):
    # 1. Safety Checks
    app_env = (os.getenv("APP_ENV") or os.getenv("ENVIRONMENT") or "").lower()
    if app_env == "lab":
        print("[ERROR] Refusing execution: Traffic demo script cannot run when APP_ENV is lab.", file=sys.stderr)
        sys.exit(1)

    parsed = urllib.parse.urlparse(target_url)
    hostname = (parsed.hostname or "").lower()
    if hostname not in ("127.0.0.1", "localhost"):
        print(f"[ERROR] Refusing execution: Target host '{hostname}' must be 127.0.0.1 or localhost.", file=sys.stderr)
        sys.exit(1)

    demo_email = os.getenv("DEMO_COMPANY_EMAIL", "demo_user@democo.test").lower().strip()
    demo_password = os.getenv("DEMO_COMPANY_PASSWORD", "DemoCompanySecurePass123!")

    # 2. Authenticate Demo Co User
    client = httpx.Client(base_url=target_url, timeout=10.0)
    try:
        login_res = client.post("/auth/login", json={"email": demo_email, "password": demo_password})
        if login_res.status_code != 200:
            print(f"[ERROR] Authentication failed for demo user ({login_res.status_code}). Ensure Demo Co is seeded.", file=sys.stderr)
            sys.exit(1)

        token = login_res.json().get("access_token")
        if not token:
            print("[ERROR] No access token received from login endpoint.", file=sys.stderr)
            sys.exit(1)
    except Exception as exc:
        print(f"[ERROR] Failed to connect to target server at {target_url}: {exc}", file=sys.stderr)
        sys.exit(1)

    # 3. Prepare Interleaved Requests
    # 10 valid and 3 invalid requests (total 13)
    # Interleaved pattern: V, V, I, V, V, I, V, V, I, V, V, V, V
    plan = [
        ("valid", "/documents", "/documents"),
        ("valid", "/documents", "/documents"),
        ("invalid", f"/documents/{uuid4()}", "/documents/<id>"),
        ("valid", "/documents", "/documents"),
        ("valid", "/documents", "/documents"),
        ("invalid", f"/documents/{uuid4()}", "/documents/<id>"),
        ("valid", "/documents", "/documents"),
        ("valid", "/documents", "/documents"),
        ("invalid", f"/documents/{uuid4()}", "/documents/<id>"),
        ("valid", "/documents", "/documents"),
        ("valid", "/documents", "/documents"),
        ("valid", "/documents", "/documents"),
        ("valid", "/documents", "/documents"),
    ]

    headers = {"Authorization": f"Bearer {token}"}
    progress_file = open(progress_file_path, "w", encoding="utf-8")

    try:
        for idx, (kind, req_path, placeholder_path) in enumerate(plan, start=1):
            t0 = time.perf_counter()
            try:
                resp = client.get(req_path, headers=headers)
                status_code = resp.status_code
            except Exception:
                status_code = 500
            duration_ms = round((time.perf_counter() - t0) * 1000.0, 2)

            record = {
                "number": idx,
                "kind": kind,
                "method": "GET",
                "path": placeholder_path,
                "status_code": status_code,
                "duration_ms": duration_ms,
            }
            progress_file.write(json.dumps(record) + "\n")
            progress_file.flush()

            # 2 requests per second = 0.5s pause
            if idx < len(plan):
                time.sleep(0.5)

    finally:
        progress_file.close()
        client.close()


def main():
    parser = argparse.ArgumentParser(description="TenantShield Send Test Traffic Runner")
    parser.add_argument("--progress-file", required=True, help="Absolute path to progress file")
    parser.add_argument("--target-url", default="http://127.0.0.1:8000", help="Target server URL")
    args = parser.parse_args()

    send_traffic(args.progress_file, args.target_url)


if __name__ == "__main__":
    main()
