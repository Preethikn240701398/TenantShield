"""
TenantShield - Multi-Tenant Data Seeder
======================================
Seeds sample tenants (Acme Corp, Beta Industries) and confidential documents.
- Tenant creation uses an administrative connection (since tenantshield_app
  has least-privilege SELECT-only permissions on tenants).
- Document seeding operates strictly through the restricted application role
  (tenantshield_app) using transaction-local tenant context.

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
from app.core.database import AsyncSessionLocal, tenant_session


def ensure_tenants_admin() -> tuple[UUID, UUID]:
    """
    Ensures Acme and Beta tenants exist in the database.
    Attempts administrative connection to create them if missing.
    """
    admin_url = os.getenv("POSTGRES_ADMIN_URL")
    if not admin_url:
        return None, None

    try:
        engine = create_engine(admin_url, isolation_level="AUTOCOMMIT")
        with engine.connect() as conn:
            # Acme Corp
            res = conn.execute(
                text("SELECT id FROM tenants WHERE slug = :slug"),
                {"slug": "acme"},
            ).fetchone()
            if not res:
                res = conn.execute(
                    text("INSERT INTO tenants (name, slug) VALUES (:name, :slug) RETURNING id"),
                    {"name": "Acme Corp", "slug": "acme"},
                ).fetchone()
                print(f"[+] Admin created tenant: Acme Corp (ID: {res[0]})")
            acme_id = res[0]

            # Beta Industries
            res = conn.execute(
                text("SELECT id FROM tenants WHERE slug = :slug"),
                {"slug": "beta"},
            ).fetchone()
            if not res:
                res = conn.execute(
                    text("INSERT INTO tenants (name, slug) VALUES (:name, :slug) RETURNING id"),
                    {"name": "Beta Industries", "slug": "beta"},
                ).fetchone()
                print(f"[+] Admin created tenant: Beta Industries (ID: {res[0]})")
            beta_id = res[0]

        engine.dispose()
        return acme_id, beta_id
    except Exception as exc:
        # Fall back to reading existing tenants as tenantshield_app
        return None, None


async def seed_data():
    print("[*] Checking tenant data...")

    acme_id = None
    beta_id = None

    # First attempt to read existing tenants as tenantshield_app (SELECT permission)
    async with AsyncSessionLocal() as session:
        res = await session.execute(
            text("SELECT id, slug FROM tenants WHERE slug IN ('acme', 'beta')")
        )
        rows = {row.slug: row.id for row in res.fetchall()}
        acme_id = rows.get("acme")
        beta_id = rows.get("beta")

    # If tenants are missing, attempt administrative creation
    if not acme_id or not beta_id:
        print("[*] Tenants missing. Using administrative setup to provision tenants...")
        admin_acme, admin_beta = ensure_tenants_admin()
        acme_id = acme_id or admin_acme
        beta_id = beta_id or admin_beta

    if not acme_id or not beta_id:
        print("[ERROR] Could not resolve Acme and Beta tenants. Please run migrations first.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Acme Corp ID: {acme_id}")
    print(f"[*] Beta Industries ID: {beta_id}")

    # Seed Acme Documents strictly under restricted role with Acme tenant context
    async with tenant_session(acme_id) as session:
        existing_acme_docs = await session.execute(
            text("SELECT count(*) FROM documents WHERE tenant_id = :tenant_id"),
            {"tenant_id": str(acme_id)},
        )
        if existing_acme_docs.scalar_one() == 0:
            await session.execute(
                text(
                    "INSERT INTO documents (tenant_id, title, content) VALUES "
                    "(:tenant_id, 'Acme Q3 Financial Strategy', 'Acme confidential financial records and forecasts.'), "
                    "(:tenant_id, 'Acme Secret Product Specs', 'Proprietary algorithm architecture and specifications.')"
                ),
                {"tenant_id": str(acme_id)},
            )
            print("[+] Seeded Acme Corp documents within Acme tenant context (tenantshield_app).")
        else:
            print("[*] Acme Corp documents already present.")

    # Seed Beta Documents strictly under restricted role with Beta tenant context
    async with tenant_session(beta_id) as session:
        existing_beta_docs = await session.execute(
            text("SELECT count(*) FROM documents WHERE tenant_id = :tenant_id"),
            {"tenant_id": str(beta_id)},
        )
        if existing_beta_docs.scalar_one() == 0:
            await session.execute(
                text(
                    "INSERT INTO documents (tenant_id, title, content) VALUES "
                    "(:tenant_id, 'Beta Cybersecurity Audit', 'Beta internal vulnerability scan reports and remediation plan.'), "
                    "(:tenant_id, 'Beta Client Contracts', 'Enterprise SLA contracts and pricing tiers.')"
                ),
                {"tenant_id": str(beta_id)},
            )
            print("[+] Seeded Beta Industries documents within Beta tenant context (tenantshield_app).")
        else:
            print("[*] Beta Industries documents already present.")

    print("[SUCCESS] Multi-tenant seeding completed successfully!")
    return acme_id, beta_id


if __name__ == "__main__":
    asyncio.run(seed_data())
