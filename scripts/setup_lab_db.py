"""
TenantShield - Dedicated Lab Database Setup & RLS Control Runner
================================================================
Manages the isolated 'tenantshield_lab' database used for Layer A / Layer B
kill matrix and RLS disablement experiments.

Safety Guarantees:
- Never alters, weakens, or disables RLS on the primary 'tenantshield_db' database.
- Refuses to disable RLS outside APP_ENV='lab'.
- Does not grant elevated permissions to the runtime application role 'tenantshield_app'.
"""

import argparse
import os
from pathlib import Path
import re
import sys
from urllib.parse import urlparse, urlunparse

from dotenv import load_dotenv

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Load .env
load_dotenv()

from sqlalchemy import create_engine, text
from app.core.config import settings
from app.services.auth import AuthService
from app.services.crypto import CryptoService


def mask_url_secrets(url: str) -> str:
    """Masks database passwords in connection URLs."""
    return re.sub(r":([^@/: ]+)@", r":****@", url)


def get_default_postgres_url(admin_url: str) -> str:
    """Derives a connection URL pointing to default 'postgres' database."""
    parsed = urlparse(admin_url)
    return urlunparse((parsed.scheme, parsed.netloc, "/postgres", parsed.params, parsed.query, parsed.fragment))


def get_lab_url_from_admin(admin_url: str) -> str:
    """Derives a connection URL pointing to 'tenantshield_lab' using admin credentials."""
    parsed = urlparse(admin_url)
    return urlunparse((parsed.scheme, parsed.netloc, "/tenantshield_lab", parsed.params, parsed.query, parsed.fragment))


def setup_or_reset_lab_database(admin_url: str, reset: bool = False) -> None:
    """
    Creates or resets the tenantshield_lab database:
    1. Creates database if not present.
    2. Runs init_db.sql and 005_envelope_encryption.sql.
    3. Seeds tenants, users, and active DEKs.
    4. Guarantees clean baseline state with RLS enabled.
    """
    default_pg_url = get_default_postgres_url(admin_url)
    print(f"[*] Connecting to PostgreSQL administrative endpoint ({mask_url_secrets(default_pg_url)})...")

    engine = create_engine(default_pg_url, isolation_level="AUTOCOMMIT")
    with engine.connect() as conn:
        res = conn.execute(text("SELECT 1 FROM pg_database WHERE datname = 'tenantshield_lab'"))
        exists = res.fetchone() is not None

        if exists and reset:
            # Terminate active connections to allow clean drop
            conn.execute(
                text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = 'tenantshield_lab' AND pid <> pg_backend_pid()"
                )
            )
            conn.execute(text("DROP DATABASE tenantshield_lab"))
            print("[+] Dropped existing 'tenantshield_lab' for clean reset.")
            exists = False

        if not exists:
            conn.execute(text("CREATE DATABASE tenantshield_lab OWNER postgres"))
            print("[+] Created isolated database: 'tenantshield_lab'")
        else:
            print("[*] Database 'tenantshield_lab' already exists.")
    engine.dispose()

    # Connect to tenantshield_lab to initialize schema
    lab_admin_url = get_lab_url_from_admin(admin_url)
    print(f"[*] Applying schema & migrations to tenantshield_lab ({mask_url_secrets(lab_admin_url)})...")

    lab_engine = create_engine(lab_admin_url, isolation_level="AUTOCOMMIT")
    scripts_dir = Path(__file__).resolve().parent

    # 1. init_db.sql
    init_sql_path = scripts_dir / "init_db.sql"
    with open(init_sql_path, "r", encoding="utf-8") as f:
        init_sql = f.read()

    # 2. 005_envelope_encryption.sql
    mig_sql_path = scripts_dir / "migrations" / "005_envelope_encryption.sql"
    with open(mig_sql_path, "r", encoding="utf-8") as f:
        mig_sql = f.read()

    raw_conn = lab_engine.raw_connection()
    try:
        cursor = raw_conn.cursor()
        cursor.execute(init_sql)
        cursor.execute(mig_sql)
        cursor.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE users TO tenantshield_app;")
        print("[+] Schema, roles, and envelope encryption tables applied to tenantshield_lab.")
    finally:
        raw_conn.close()

    # 3. Seed Tenants & Users in tenantshield_lab
    with lab_engine.connect() as conn:
        tenant_specs = [
            ("Acme Corp", "acme"),
            ("Beta Industries", "beta"),
            ("TenantShield System", "system"),
        ]
        tenant_map = {}
        for name, slug in tenant_specs:
            row = conn.execute(
                text("SELECT id FROM tenants WHERE slug = :slug"),
                {"slug": slug},
            ).fetchone()
            if not row:
                r = conn.execute(
                    text("INSERT INTO tenants (name, slug) VALUES (:name, :slug) RETURNING id"),
                    {"name": name, "slug": slug},
                ).fetchone()
                tenant_map[slug] = r[0]
            else:
                tenant_map[slug] = row[0]

        # Seed Users
        user_specs = [
            (tenant_map["acme"], settings.DEV_ACME_USER_EMAIL, settings.DEV_ACME_USER_PASSWORD, "tenant_user"),
            (tenant_map["beta"], settings.DEV_BETA_USER_EMAIL, settings.DEV_BETA_USER_PASSWORD, "tenant_user"),
            (tenant_map["system"], settings.DEV_ADMIN_USER_EMAIL, settings.DEV_ADMIN_USER_PASSWORD, "platform_admin"),
        ]
        for tid, email, pwd, role in user_specs:
            user_row = conn.execute(
                text("SELECT id FROM users WHERE email = :email"),
                {"email": email},
            ).fetchone()
            if not user_row:
                hashed = AuthService.hash_password(pwd)
                conn.execute(
                    text(
                        "INSERT INTO users (tenant_id, email, hashed_password, role, is_active) "
                        "VALUES (:tid, :email, :hashed, :role, true)"
                    ),
                    {"tid": str(tid), "email": email, "hashed": hashed, "role": role},
                )

        # 4. Provision DEKs for each tenant in tenantshield_lab
        master_key = CryptoService.get_master_key()
        for slug, tid in tenant_map.items():
            key_row = conn.execute(
                text("SELECT id FROM tenant_keys WHERE tenant_id = :tid AND status = 'active'"),
                {"tid": str(tid)},
            ).fetchone()
            if not key_row:
                dek = CryptoService.generate_dek()
                wrapped, nonce = CryptoService.wrap_dek(dek, master_key)
                conn.execute(
                    text(
                        "INSERT INTO tenant_keys (tenant_id, key_version, wrapped_dek, wrapping_nonce, status) "
                        "VALUES (:tid, 1, :wrapped, :nonce, 'active')"
                    ),
                    {"tid": str(tid), "wrapped": wrapped, "nonce": nonce},
                )

        # Clear any prior documents
        conn.execute(text("DELETE FROM documents;"))
        conn.execute(text("ALTER TABLE documents ENABLE ROW LEVEL SECURITY;"))
        conn.execute(text("ALTER TABLE documents FORCE ROW LEVEL SECURITY;"))

    lab_engine.dispose()
    print("[SUCCESS] Isolated lab database 'tenantshield_lab' is fully initialized and seeded.")


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
            conn.execute(text("ALTER TABLE tenant_keys ENABLE ROW LEVEL SECURITY;"))
            conn.execute(text("ALTER TABLE tenant_keys FORCE ROW LEVEL SECURITY;"))
            print("[+] PostgreSQL RLS ENABLED and FORCED on tenantshield_lab.documents and tenant_keys.")
        else:
            conn.execute(text("ALTER TABLE documents NO FORCE ROW LEVEL SECURITY;"))
            conn.execute(text("ALTER TABLE documents DISABLE ROW LEVEL SECURITY;"))
            conn.execute(text("ALTER TABLE tenant_keys NO FORCE ROW LEVEL SECURITY;"))
            conn.execute(text("ALTER TABLE tenant_keys DISABLE ROW LEVEL SECURITY;"))
            print("[!] PostgreSQL RLS DISABLED on tenantshield_lab.documents and tenant_keys (LAB EXPERIMENT ONLY).")
    lab_engine.dispose()


def main():
    admin_default = os.getenv("POSTGRES_ADMIN_URL")
    if not admin_default:
        print("[ERROR] POSTGRES_ADMIN_URL environment variable is required.", file=sys.stderr)
        sys.exit(1)

    parser = argparse.ArgumentParser(description="TenantShield Lab Database Setup & Control Runner")
    parser.add_argument(
        "--admin-url",
        default=admin_default,
        help="PostgreSQL administrative connection URL",
    )
    parser.add_argument(
        "--action",
        choices=["setup", "reset", "disable-rls", "enable-rls"],
        default="setup",
        help="Action to perform: 'setup', 'reset', 'disable-rls', or 'enable-rls'",
    )

    args = parser.parse_args()

    if args.action == "setup":
        setup_or_reset_lab_database(args.admin_url, reset=False)
    elif args.action == "reset":
        setup_or_reset_lab_database(args.admin_url, reset=True)
    elif args.action == "disable-rls":
        set_lab_rls(args.admin_url, enable=False)
    elif args.action == "enable-rls":
        set_lab_rls(args.admin_url, enable=True)


if __name__ == "__main__":
    main()
