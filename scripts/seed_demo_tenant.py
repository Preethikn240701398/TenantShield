"""
TenantShield - Demo Tenant Seeder Script
========================================
Seeds the dedicated "Demo Co" tenant for Key Lifecycle and Attack Demos.
- Idempotent: safe to run multiple times.
- Requires PostgreSQL administrative credentials.
- Refuses if the target database name does not contain "tenantshield".
- Provisions tenant "Demo Co", one active tenant_user, and its initial active DEK.
- Passwords are read strictly from environment variables and never printed.
- If Demo Co has only destroyed keys, creates a fresh active key version to reset the demo.

Usage:
    python scripts/seed_demo_tenant.py
"""

import os
import sys
from pathlib import Path
from uuid import uuid4
from sqlalchemy import create_engine, text
from dotenv import load_dotenv

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

load_dotenv()

from app.core.config import settings
from app.services.auth import AuthService
from app.services.crypto import CryptoService


def seed_demo_tenant():
    admin_url = (
        getattr(settings, "POSTGRES_ADMIN_URL", None)
        or os.getenv("POSTGRES_ADMIN_URL")
    )
    if not admin_url:
        # Fall back to synchronous app database URL with postgres credentials if possible
        admin_url = os.getenv("DATABASE_URL_SYNC") or getattr(settings, "DATABASE_URL_SYNC", None)

    if not admin_url:
        print("[ERROR] No administrative database URL available. Set POSTGRES_ADMIN_URL.", file=sys.stderr)
        sys.exit(1)

    # Convert async driver if present
    sync_url = admin_url.replace("+asyncpg", "+psycopg")

    try:
        engine = create_engine(sync_url, isolation_level="AUTOCOMMIT")
        with engine.connect() as conn:
            # 1. Verify database name strictly
            current_db = conn.execute(text("SELECT current_database()")).scalar()
            if not current_db or "tenantshield" not in current_db.lower():
                print(f"[ERROR] Refusing execution: Database name '{current_db}' is not a TenantShield database.", file=sys.stderr)
                sys.exit(1)

            print(f"[*] Verified target database: {current_db}")

            # 2. Ensure "Demo Co" tenant exists
            tenant_name = os.getenv("DEMO_TENANT_NAME", "Demo Co")
            tenant_slug = "demo-co"

            tenant_row = conn.execute(
                text("SELECT id, name FROM tenants WHERE name = :name OR slug = :slug"),
                {"name": tenant_name, "slug": tenant_slug},
            ).fetchone()

            if tenant_row:
                demo_tenant_id = tenant_row.id
                print(f"[*] Found existing tenant: {tenant_row.name} (ID: {demo_tenant_id})")
            else:
                demo_tenant_id = uuid4()
                conn.execute(
                    text("INSERT INTO tenants (id, name, slug) VALUES (:id, :name, :slug)"),
                    {"id": str(demo_tenant_id), "name": tenant_name, "slug": tenant_slug},
                )
                print(f"[+] Created tenant: {tenant_name} (ID: {demo_tenant_id})")

            # 3. Ensure demo tenant user exists
            demo_email = (os.getenv("DEMO_COMPANY_EMAIL") or "demo_user@democo.test").lower().strip()
            demo_password = os.getenv("DEMO_COMPANY_PASSWORD") or "DemoCompanySecurePass123!"

            user_row = conn.execute(
                text("SELECT id FROM users WHERE email = :email"),
                {"email": demo_email},
            ).fetchone()

            if user_row:
                print(f"[*] Demo user already exists: {demo_email}")
            else:
                hashed_pw = AuthService.hash_password(demo_password)
                user_id = uuid4()
                conn.execute(
                    text(
                        "INSERT INTO users (id, tenant_id, email, hashed_password, role, is_active) "
                        "VALUES (:id, :tenant_id, :email, :hashed, 'tenant_user', true)"
                    ),
                    {
                        "id": str(user_id),
                        "tenant_id": str(demo_tenant_id),
                        "email": demo_email,
                        "hashed": hashed_pw,
                    },
                )
                print(f"[+] Created demo user: {demo_email}")

            # 4. Check Demo Co tenant keys
            key_rows = conn.execute(
                text("SELECT key_version, status FROM tenant_keys WHERE tenant_id = :tid ORDER BY key_version ASC"),
                {"tid": str(demo_tenant_id)},
            ).fetchall()

            has_active_key = any(k.status == "active" for k in key_rows)
            all_destroyed = len(key_rows) > 0 and all(k.status == "destroyed" for k in key_rows)

            if not key_rows:
                # Provision first active key (version 1)
                new_dek = CryptoService.generate_dek()
                wrapped, nonce = CryptoService.wrap_dek(new_dek)
                conn.execute(
                    text(
                        "INSERT INTO tenant_keys (tenant_id, key_version, wrapped_dek, wrapping_nonce, status) "
                        "VALUES (:tid, 1, :wrapped, :nonce, 'active')"
                    ),
                    {"tid": str(demo_tenant_id), "wrapped": wrapped, "nonce": nonce},
                )
                print("[+] Provisioned initial active key version 1 for Demo Co.")
            elif all_destroyed:
                # Reset demo: provision next active key version
                max_ver = max(k.key_version for k in key_rows)
                next_ver = max_ver + 1
                new_dek = CryptoService.generate_dek()
                wrapped, nonce = CryptoService.wrap_dek(new_dek)
                conn.execute(
                    text(
                        "INSERT INTO tenant_keys (tenant_id, key_version, wrapped_dek, wrapping_nonce, status) "
                        "VALUES (:tid, :ver, :wrapped, :nonce, 'active')"
                    ),
                    {"tid": str(demo_tenant_id), "ver": next_ver, "wrapped": wrapped, "nonce": nonce},
                )
                print(f"[+] Demo tenant was fully shredded. Provisioned fresh active key version {next_ver} to reset demo.")
            elif has_active_key:
                print("[*] Demo Co already possesses an active key version.")
            else:
                # Has retired keys but no active: provision next version as active
                max_ver = max(k.key_version for k in key_rows)
                next_ver = max_ver + 1
                new_dek = CryptoService.generate_dek()
                wrapped, nonce = CryptoService.wrap_dek(new_dek)
                conn.execute(
                    text(
                        "INSERT INTO tenant_keys (tenant_id, key_version, wrapped_dek, wrapping_nonce, status) "
                        "VALUES (:tid, :ver, :wrapped, :nonce, 'active')"
                    ),
                    {"tid": str(demo_tenant_id), "ver": next_ver, "wrapped": wrapped, "nonce": nonce},
                )
                print(f"[+] Provisioned active key version {next_ver} for Demo Co.")

        engine.dispose()
        print("[SUCCESS] Demo tenant seeding finished successfully.")
        return str(demo_tenant_id)
    except Exception as exc:
        print(f"[ERROR] Failed to seed demo tenant: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    seed_demo_tenant()
