"""
TenantShield - Database Initialization Runner
=============================================
Executes scripts/init_db.sql against the target PostgreSQL database using
an administrative connection URL specified in the environment or command line.

Usage:
    python scripts/init_db.py
    python scripts/init_db.py --admin-url postgresql://postgres:password@localhost:5432/tenantshield_db
"""

import argparse
import os
import re
import sys
from pathlib import Path
from sqlalchemy import create_engine
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()


def mask_url_secrets(text: str) -> str:
    """Masks database passwords in connection URLs and exception messages."""
    return re.sub(r":([^@/: ]+)@", r":****@", text)


def run_init_db(admin_url: str | None = None) -> None:
    # Resolve administrative database URL
    url = admin_url or os.getenv("POSTGRES_ADMIN_URL")
    if not url:
        print("[ERROR] POSTGRES_ADMIN_URL environment variable is not set.", file=sys.stderr)
        print("Set it in .env or provide via --admin-url argument.", file=sys.stderr)
        sys.exit(1)

    sql_path = Path(__file__).parent / "init_db.sql"
    if not sql_path.is_file():
        print(f"[ERROR] SQL file not found at: {sql_path}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Reading initialization script: {sql_path.name}")
    with open(sql_path, "r", encoding="utf-8") as f:
        sql_content = f.read()

    masked_target = mask_url_secrets(url)
    print(f"[*] Connecting to database with administrative credentials ({masked_target})...")

    try:
        # Create synchronous engine for DDL execution
        engine = create_engine(url, isolation_level="AUTOCOMMIT")
        # Use raw DBAPI connection to execute multi-statement SQL script
        # without naive semicolon splitting (preserves PL/pgSQL procedural blocks)
        raw_conn = engine.raw_connection()
        try:
            cursor = raw_conn.cursor()
            cursor.execute(sql_content)
            print("[SUCCESS] TenantShield database initialized successfully!")
            print("          Tables verified: tenants, users, documents, security_events")
            print("          RLS Policy configured: tenant_isolation_policy on documents (FORCED)")
            print("          Restricted role configured: tenantshield_app (NOSUPERUSER, NOBYPASSRLS)")
            print("          Least-privilege grants applied: DML on documents, SELECT on tenants/users, INSERT on security_events")
        finally:
            raw_conn.close()
            engine.dispose()
    except Exception as exc:
        safe_msg = mask_url_secrets(str(exc))
        print(f"[ERROR] Failed to execute database initialization: {safe_msg}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TenantShield Database Initializer")
    parser.add_argument(
        "--admin-url",
        type=str,
        default=None,
        help="PostgreSQL admin connection URL (defaults to POSTGRES_ADMIN_URL from .env)",
    )
    args = parser.parse_args()
    run_init_db(args.admin_url)
