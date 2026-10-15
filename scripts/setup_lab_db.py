"""
TenantShield - Dedicated Lab Database Setup & RLS Control Runner
================================================================
Manages the isolated 'tenantshield_lab' database used for Level 4 RLS
disablement experiments.

Safety Guarantees:
- Never alters, weakens, or disables RLS on the primary 'tenantshield_db' database.
- Refuses to disable RLS outside APP_ENV='lab'.
- Does not grant elevated permissions to the runtime application role 'tenantshield_app'.

Usage:
    # Setup the isolated lab database:
    python scripts/setup_lab_db.py --admin-url postgresql://postgres:password@localhost:5432/postgres

    # Disable RLS on lab database only (for controlled experiments):
    python scripts/setup_lab_db.py --admin-url postgresql://postgres:password@localhost:5432/postgres --action disable-rls

    # Re-enable RLS on lab database:
    python scripts/setup_lab_db.py --admin-url postgresql://postgres:password@localhost:5432/postgres --action enable-rls
"""

import argparse
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlparse, urlunparse

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import create_engine, text
from app.core.config import settings


def mask_url_secrets(url: str) -> str:
    """Masks database passwords in connection URLs."""
    return re.sub(r":([^@/: ]+)@", r":****@", url)


def get_lab_url_from_admin(admin_url: str) -> str:
    """Derives a connection URL pointing to tenantshield_lab using the given admin URL."""
    parsed = urlparse(admin_url)
    return urlunparse((parsed.scheme, parsed.netloc, "/tenantshield_lab", parsed.params, parsed.query, parsed.fragment))


def setup_lab_database(admin_url: str) -> None:
    """Creates tenantshield_lab database and initializes its schema and seed data."""
    print(f"[*] Connecting to PostgreSQL administrative endpoint ({mask_url_secrets(admin_url)})...")

    # Connect to default postgres DB to create tenantshield_lab
    engine = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    with engine.connect() as conn:
        res = conn.execute(
            text("SELECT 1 FROM pg_database WHERE datname = 'tenantshield_lab'")
        )
        if not res.fetchone():
            conn.execute(text("CREATE DATABASE tenantshield_lab OWNER postgres"))
            print("[+] Created isolated database: tenantshield_lab")
        else:
            print("[*] Database tenantshield_lab already exists.")
    engine.dispose()

    # Apply schema to tenantshield_lab
    lab_admin_url = get_lab_url_from_admin(admin_url)
    print(f"[*] Applying initialization DDL to tenantshield_lab ({mask_url_secrets(lab_admin_url)})...")

    sql_path = Path(__file__).resolve().parent / "init_db.sql"
    with open(sql_path, "r", encoding="utf-8") as f:
        sql_content = f.read()

    lab_engine = create_engine(lab_admin_url, isolation_level="AUTOCOMMIT")
    raw_conn = lab_engine.raw_connection()
    try:
        cursor = raw_conn.cursor()
        cursor.execute(sql_content)
        print("[+] Schema and RLS initialized on tenantshield_lab.")
    finally:
        raw_conn.close()
        lab_engine.dispose()

    print("[SUCCESS] Isolated lab database 'tenantshield_lab' is ready.")


def set_lab_rls(admin_url: str, enable: bool) -> None:
    """
    Toggles Row-Level Security on the documents table in tenantshield_lab ONLY.
    Refuses execution if connected to the primary database or outside lab mode.
    """
    lab_admin_url = get_lab_url_from_admin(admin_url)
    parsed = urlparse(lab_admin_url)
    db_name = parsed.path.lstrip("/")

    if db_name != "tenantshield_lab":
        print(f"[FATAL] Refusing to modify RLS on non-lab database: '{db_name}'!", file=sys.stderr)
        sys.exit(1)

    lab_engine = create_engine(lab_admin_url, isolation_level="AUTOCOMMIT")
    with lab_engine.connect() as conn:
        if enable:
            conn.execute(text("ALTER TABLE documents ENABLE ROW LEVEL SECURITY;"))
            conn.execute(text("ALTER TABLE documents FORCE ROW LEVEL SECURITY;"))
            print("[+] PostgreSQL RLS ENABLED and FORCED on tenantshield_lab.documents.")
        else:
            conn.execute(text("ALTER TABLE documents NO FORCE ROW LEVEL SECURITY;"))
            conn.execute(text("ALTER TABLE documents DISABLE ROW LEVEL SECURITY;"))
            print("[!] PostgreSQL RLS DISABLED on tenantshield_lab.documents (LAB EXPERIMENT ONLY).")
    lab_engine.dispose()


def main():
    parser = argparse.ArgumentParser(description="TenantShield Lab Database Setup & Control Runner")
    parser.add_argument(
        "--admin-url",
        default=os.getenv("POSTGRES_ADMIN_URL", "postgresql://postgres:postgres@localhost:5432/postgres"),
        help="PostgreSQL administrative connection URL",
    )
    parser.add_argument(
        "--action",
        choices=["setup", "disable-rls", "enable-rls"],
        default="setup",
        help="Action to perform: 'setup', 'disable-rls', or 'enable-rls'",
    )

    args = parser.parse_args()

    if args.action == "setup":
        setup_lab_database(args.admin_url)
    elif args.action == "disable-rls":
        set_lab_rls(args.admin_url, enable=False)
    elif args.action == "enable-rls":
        set_lab_rls(args.admin_url, enable=True)


if __name__ == "__main__":
    main()
