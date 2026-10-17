"""
TenantShield - Reset Lab Database Script
========================================
One-command reset utility for 'tenantshield_lab' database:
1. Resets tables, schemas, and RLS policies.
2. Reseeds tenants, users, and cryptographic DEKs.
3. Clears any test artifacts or documents.
Usage:
    python scripts/reset_lab_db.py
"""

import os
from pathlib import Path
import sys

from dotenv import load_dotenv

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

load_dotenv()

from scripts.setup_lab_db import setup_or_reset_lab_database


def main():
    admin_url = os.getenv("POSTGRES_ADMIN_URL")
    if not admin_url:
        print("[ERROR] POSTGRES_ADMIN_URL is not set.", file=sys.stderr)
        sys.exit(1)

    print("[*] Performing full state reset on 'tenantshield_lab' database...")
    setup_or_reset_lab_database(admin_url, reset=True)
    print("[SUCCESS] Lab database reset complete.")


if __name__ == "__main__":
    main()
