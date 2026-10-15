"""
TenantShield - Multi-Tenant Data & User Seeder
==============================================
Seeds sample tenants, confidential documents, and development users:
- Acme Corp tenant & Acme user (role: tenant_user)
- Beta Industries tenant & Beta user (role: tenant_user)
- TenantShield System tenant & Platform Admin (role: platform_admin)

Requirements:
- Passwords are strictly hashed with Argon2id before saving.
- Plaintext passwords are loaded from environment variables or settings defaults.
- Idempotent execution (skips duplicates or updates safely).
- Documents are seeded strictly using transaction-local tenant context.

Usage:
    python scripts/seed_tenants.py
"""

import asyncio
import os
import sys
from pathlib import Path
from uuid import UUID

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import create_engine, text
from app.core.config import settings
from app.core.database import AsyncSessionLocal, tenant_session
from app.services.auth import AuthService


def ensure_tenants_admin() -> dict[str, UUID]:
    """
    Attempts administrative connection to ensure tenants exist.
    Falls back gracefully if admin credentials are unavailable.
    """
    admin_url = getattr(settings, "POSTGRES_ADMIN_URL", None) or os.getenv("POSTGRES_ADMIN_URL")
    tenants = {}
    if not admin_url:
        return tenants

    try:
        engine = create_engine(admin_url, isolation_level="AUTOCOMMIT")
        with engine.connect() as conn:
            tenant_specs = [
                ("Acme Corp", "acme"),
                ("Beta Industries", "beta"),
                ("TenantShield System", "system"),
            ]
            for name, slug in tenant_specs:
                row = conn.execute(
                    text("SELECT id FROM tenants WHERE slug = :slug"),
                    {"slug": slug},
                ).fetchone()
                if not row:
                    insert_res = conn.execute(
                        text("INSERT INTO tenants (name, slug) VALUES (:name, :slug) RETURNING id"),
                        {"name": name, "slug": slug},
                    ).fetchone()
                    tenants[slug] = insert_res[0]
                    print(f"[+] Admin created tenant: {name} (slug: {slug})")
                else:
                    tenants[slug] = row[0]
        engine.dispose()
    except Exception:
        # Fall back to application connection
        pass
    return tenants


async def seed_data():
    if settings.ENVIRONMENT.lower() in ("production", "prod"):
        print(
            f"[ERROR] Refusing to seed development data in production environment (ENVIRONMENT={settings.ENVIRONMENT}).",
            file=sys.stderr,
        )
        sys.exit(1)

    reset_passwords = "--reset-passwords" in sys.argv
    print(f"[*] Starting multi-tenant and user seeding (reset_passwords={reset_passwords})...")

    # 1. Resolve Tenants
    admin_tenants = ensure_tenants_admin()
    tenants = dict(admin_tenants)

    async with AsyncSessionLocal() as session:
        res = await session.execute(text("SELECT id, slug FROM tenants"))
        for row in res.fetchall():
            tenants[row.slug] = row.id

    # If system tenant is still missing, create it if permissions allow
    if "system" not in tenants:
        async with AsyncSessionLocal() as session:
            try:
                async with session.begin():
                    res = await session.execute(
                        text("INSERT INTO tenants (name, slug) VALUES ('TenantShield System', 'system') RETURNING id")
                    )
                    tenants["system"] = res.scalar_one()
                    print("[+] Created tenant: TenantShield System (slug: system)")
            except Exception:
                # If cannot insert system tenant, associate admin with acme
                tenants["system"] = tenants.get("acme")

    acme_id = tenants.get("acme")
    beta_id = tenants.get("beta")
    system_id = tenants.get("system", acme_id)

    if not acme_id or not beta_id:
        print("[ERROR] Acme and Beta tenants must exist before seeding.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Acme Tenant ID: {acme_id}")
    print(f"[*] Beta Tenant ID: {beta_id}")
    print(f"[*] System Tenant ID: {system_id}")

    # 2. Seed Acme Confidential Documents (strict Acme tenant context)
    async with tenant_session(acme_id) as session:
        res = await session.execute(
            text("SELECT count(*) FROM documents WHERE tenant_id = :tenant_id"),
            {"tenant_id": str(acme_id)},
        )
        if res.scalar_one() == 0:
            await session.execute(
                text(
                    "INSERT INTO documents (tenant_id, title, content) VALUES "
                    "(:tenant_id, 'Acme Q3 Financial Strategy', 'Acme confidential financial records and forecasts.'), "
                    "(:tenant_id, 'Acme Secret Product Specs', 'Proprietary algorithm architecture and specifications.')"
                ),
                {"tenant_id": str(acme_id)},
            )
            print("[+] Seeded Acme documents under Acme tenant context.")
        else:
            print("[*] Acme documents already present.")

    # 3. Seed Beta Confidential Documents (strict Beta tenant context)
    async with tenant_session(beta_id) as session:
        res = await session.execute(
            text("SELECT count(*) FROM documents WHERE tenant_id = :tenant_id"),
            {"tenant_id": str(beta_id)},
        )
        if res.scalar_one() == 0:
            await session.execute(
                text(
                    "INSERT INTO documents (tenant_id, title, content) VALUES "
                    "(:tenant_id, 'Beta Cybersecurity Audit', 'Beta internal vulnerability scan reports and remediation plan.'), "
                    "(:tenant_id, 'Beta Client Contracts', 'Enterprise SLA contracts and pricing tiers.')"
                ),
                {"tenant_id": str(beta_id)},
            )
            print("[+] Seeded Beta documents under Beta tenant context.")
        else:
            print("[*] Beta documents already present.")

    # 4. Seed Development Users with Argon2id Password Hashes
    user_specs = [
        {
            "email": settings.DEV_ACME_USER_EMAIL.lower().strip(),
            "password": settings.DEV_ACME_USER_PASSWORD,
            "tenant_id": acme_id,
            "role": "tenant_user",
            "name": "Acme User",
        },
        {
            "email": settings.DEV_BETA_USER_EMAIL.lower().strip(),
            "password": settings.DEV_BETA_USER_PASSWORD,
            "tenant_id": beta_id,
            "role": "tenant_user",
            "name": "Beta User",
        },
        {
            "email": settings.DEV_ADMIN_USER_EMAIL.lower().strip(),
            "password": settings.DEV_ADMIN_USER_PASSWORD,
            "tenant_id": system_id,
            "role": "platform_admin",
            "name": "Platform Admin",
        },
    ]

    async with AsyncSessionLocal() as session:
        async with session.begin():
            for u in user_specs:
                # Check if user already exists
                check_res = await session.execute(
                    text("SELECT id FROM users WHERE email = :email"),
                    {"email": u["email"]},
                )
                existing = check_res.fetchone()

                if existing:
                    if reset_passwords:
                        hashed_pw = AuthService.hash_password(u["password"])
                        await session.execute(
                            text(
                                "UPDATE users SET hashed_password = :hashed, role = :role, "
                                "is_active = true, tenant_id = :tenant_id WHERE email = :email"
                            ),
                            {
                                "hashed": hashed_pw,
                                "role": u["role"],
                                "tenant_id": str(u["tenant_id"]),
                                "email": u["email"],
                            },
                        )
                        print(f"[*] Updated existing user credentials (--reset-passwords): {u['email']} (role: {u['role']})")
                    else:
                        print(f"[*] User already exists: {u['email']} (role: {u['role']}). Preserving existing credentials.")
                else:
                    # Insert new user with Argon2id hash
                    hashed_pw = AuthService.hash_password(u["password"])
                    insert_res = await session.execute(
                        text(
                            "INSERT INTO users (tenant_id, email, hashed_password, role, is_active) "
                            "VALUES (:tenant_id, :email, :hashed, :role, true) "
                            "RETURNING id"
                        ),
                        {
                            "tenant_id": str(u["tenant_id"]),
                            "email": u["email"],
                            "hashed": hashed_pw,
                            "role": u["role"],
                        },
                    )
                    user_id = insert_res.scalar_one()
                    print(f"[+] Created user: {u['email']} (role: {u['role']}, id: {user_id})")

    print("[SUCCESS] Multi-tenant data and user seeding completed successfully!")
    return tenants


if __name__ == "__main__":
    asyncio.run(seed_data())
