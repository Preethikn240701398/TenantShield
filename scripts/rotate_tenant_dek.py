"""
TenantShield - Controlled Tenant Key Rotation Script
====================================================
Rotates a tenant's active Data Encryption Key (DEK):
- Retires current active key version (status = 'retired').
- Provisions a new random 256-bit DEK wrapped with the Master Key (status = 'active').
- Older documents remain decryptable using their retired key version.

Usage:
    python scripts/rotate_tenant_dek.py --tenant-slug acme
    python scripts/rotate_tenant_dek.py --tenant-id <UUID>
"""

import argparse
import asyncio
import os
import sys
from pathlib import Path
from uuid import UUID
from sqlalchemy import text
from dotenv import load_dotenv

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

load_dotenv()

from app.core.database import AsyncSessionLocal
from app.services.crypto import CryptoService


async def rotate_key(tenant_slug: str | None = None, tenant_id_str: str | None = None):
    async with AsyncSessionLocal() as session:
        async with session.begin():
            if tenant_slug:
                res = await session.execute(
                    text("SELECT id, name FROM tenants WHERE slug = :slug"),
                    {"slug": tenant_slug},
                )
                row = res.fetchone()
                if not row:
                    print(f"[ERROR] Tenant with slug '{tenant_slug}' not found.", file=sys.stderr)
                    sys.exit(1)
                tenant_id = row.id
                tenant_name = row.name
            elif tenant_id_str:
                tenant_id = UUID(tenant_id_str)
                res = await session.execute(
                    text("SELECT id, name FROM tenants WHERE id = :id"),
                    {"id": str(tenant_id)},
                )
                row = res.fetchone()
                if not row:
                    print(f"[ERROR] Tenant with id '{tenant_id_str}' not found.", file=sys.stderr)
                    sys.exit(1)
                tenant_name = row.name
            else:
                print("[ERROR] Must provide either --tenant-slug or --tenant-id.", file=sys.stderr)
                sys.exit(1)

            print(f"[*] Initiating DEK rotation for tenant: {tenant_name} ({tenant_id})...")
            new_version = await CryptoService.rotate_tenant_dek(session, tenant_id)
            print(f"[SUCCESS] Rotated DEK for tenant {tenant_name}. New active version: {new_version}")


def main():
    parser = argparse.ArgumentParser(description="TenantShield DEK Rotation Runner")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--tenant-slug", type=str, help="Tenant slug (e.g. acme, beta)")
    group.add_argument("--tenant-id", type=str, help="Tenant UUID")

    args = parser.parse_args()
    asyncio.run(rotate_key(args.tenant_slug, args.tenant_id))


if __name__ == "__main__":
    main()
