"""
TenantShield - Controlled Tenant Crypto-Shredding Script
========================================================
Permanently destroys wrapped DEK material for a tenant:
- Nullifies wrapped_dek and wrapping_nonce.
- Sets status = 'destroyed'.
- Renders all ciphertexts encrypted with destroyed key(s) permanently unreadable.
- Does not affect other tenants.

Usage:
    python scripts/shred_tenant_dek.py --tenant-slug acme [--key-version 1]
    python scripts/shred_tenant_dek.py --tenant-id <UUID> [--key-version 1]
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


async def shred_key(tenant_slug: str | None, tenant_id_str: str | None, key_version: int | None):
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

            scope = f"version {key_version}" if key_version else "ALL versions (Full Offboarding)"
            print(f"[!] INITIATING CRYPTO-SHREDDING for tenant: {tenant_name} ({tenant_id}) [{scope}]...")
            shredded = await CryptoService.crypto_shred_tenant_dek(session, tenant_id, key_version)
            print(f"[SUCCESS] Crypto-shredded {shredded} key(s) for tenant {tenant_name}.")


def main():
    parser = argparse.ArgumentParser(description="TenantShield Crypto-Shredding Runner")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--tenant-slug", type=str, help="Tenant slug")
    group.add_argument("--tenant-id", type=str, help="Tenant UUID")
    parser.add_argument("--key-version", type=int, default=None, help="Specific key version to shred (default: all)")

    args = parser.parse_args()
    asyncio.run(shred_key(args.tenant_slug, args.tenant_id, args.key_version))


if __name__ == "__main__":
    main()
