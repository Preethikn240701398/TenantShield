"""
TenantShield - Level 5 Database Migration & Plaintext Backfill Runner
====================================================================
1. Executes scripts/migrations/005_envelope_encryption.sql with admin credentials.
2. Provisions initial active DEKs (version 1) for all existing tenants.
3. Backfills all existing documents:
   - Encrypts plaintext content with AES-256-GCM, fresh 96-bit nonce, and deterministic AAD.
   - Populates ciphertext, nonce, and key_version.
   - Clears plaintext content (content = NULL).
4. Asserts zero plaintext remains in the database.

Usage:
    python scripts/migrate_level5.py
    python scripts/migrate_level5.py --admin-url postgresql://postgres:password@localhost:5432/tenantshield_db
"""

import argparse
import os
import re
import sys
from pathlib import Path
from sqlalchemy import create_engine, text
from dotenv import load_dotenv

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

load_dotenv()

from app.core.config import settings
from app.services.crypto import CryptoService


def mask_url_secrets(text: str) -> str:
    """Masks database passwords in connection URLs."""
    return re.sub(r":([^@/: ]+)@", r":****@", text)


def run_level5_migration(admin_url: str | None = None) -> None:
    url = admin_url or os.getenv("POSTGRES_ADMIN_URL")
    if not url:
        print("[ERROR] POSTGRES_ADMIN_URL is not set.", file=sys.stderr)
        sys.exit(1)

    migration_file = Path(__file__).resolve().parent / "migrations" / "005_envelope_encryption.sql"
    if not migration_file.is_file():
        print(f"[ERROR] Migration file not found: {migration_file}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Reading Level 5 migration: {migration_file.name}")
    with open(migration_file, "r", encoding="utf-8") as f:
        sql_content = f.read()

    masked_target = mask_url_secrets(url)
    print(f"[*] Applying schema migration with admin credentials ({masked_target})...")

    # Connect with admin credentials (autocommit for DDL)
    engine = create_engine(url, isolation_level="AUTOCOMMIT")
    raw_conn = engine.raw_connection()
    try:
        cursor = raw_conn.cursor()
        cursor.execute(sql_content)
        print("[+] Table 'tenant_keys' created with Row-Level Security enforced.")
        print("[+] Added 'key_version', 'nonce', and 'ciphertext' columns to 'documents'.")
        print("[+] Altered 'content' column to NULL.")
        print("[+] Least-privilege permissions on 'tenant_keys' granted to 'tenantshield_app'.")
    finally:
        raw_conn.close()

    # Step 2: Backfill DEKs and Encrypt Existing Plaintext Documents
    print("[*] Starting cryptographic backfill of existing tenants and documents...")
    master_key = CryptoService.get_master_key()
    print("[+] Master Key validated successfully from environment.")

    with engine.connect() as conn:
        # Get all tenants
        tenants = conn.execute(text("SELECT id, name, slug FROM tenants")).fetchall()
        print(f"[*] Found {len(tenants)} tenants to verify for active DEKs.")

        tenant_deks = {}
        for t in tenants:
            tenant_id = str(t.id)
            # Check if active key already exists
            existing_key = conn.execute(
                text("SELECT key_version, wrapped_dek, wrapping_nonce FROM tenant_keys WHERE tenant_id = :tenant_id AND status = 'active'"),
                {"tenant_id": tenant_id},
            ).fetchone()

            if existing_key:
                dek = CryptoService.unwrap_dek(existing_key.wrapped_dek, existing_key.wrapping_nonce, master_key)
                tenant_deks[tenant_id] = (existing_key.key_version, dek)
                print(f"[*] Tenant {t.slug} already has active DEK (v{existing_key.key_version}).")
            else:
                new_dek = CryptoService.generate_dek()
                wrapped, nonce = CryptoService.wrap_dek(new_dek, master_key)
                conn.execute(
                    text(
                        "INSERT INTO tenant_keys (tenant_id, key_version, wrapped_dek, wrapping_nonce, status) "
                        "VALUES (:tenant_id, 1, :wrapped, :nonce, 'active')"
                    ),
                    {
                        "tenant_id": tenant_id,
                        "wrapped": wrapped,
                        "nonce": nonce,
                    },
                )
                tenant_deks[tenant_id] = (1, new_dek)
                print(f"[+] Provisioned new active DEK (v1) for tenant: {t.slug} ({t.name})")

        # Query all documents with plaintext content
        plaintext_docs = conn.execute(
            text("SELECT id, tenant_id, title, content FROM documents WHERE content IS NOT NULL")
        ).fetchall()

        print(f"[*] Found {len(plaintext_docs)} plaintext documents requiring envelope encryption.")

        for doc in plaintext_docs:
            doc_id = str(doc.id)
            tenant_id = str(doc.tenant_id)

            if tenant_id not in tenant_deks:
                # Provision on the fly if needed
                new_dek = CryptoService.generate_dek()
                wrapped, nonce = CryptoService.wrap_dek(new_dek, master_key)
                conn.execute(
                    text(
                        "INSERT INTO tenant_keys (tenant_id, key_version, wrapped_dek, wrapping_nonce, status) "
                        "VALUES (:tenant_id, 1, :wrapped, :nonce, 'active')"
                    ),
                    {"tenant_id": tenant_id, "wrapped": wrapped, "nonce": nonce},
                )
                tenant_deks[tenant_id] = (1, new_dek)

            key_version, dek = tenant_deks[tenant_id]
            doc_nonce, ciphertext = CryptoService.encrypt_document(
                dek=dek,
                plaintext=doc.content,
                tenant_id=tenant_id,
                document_id=doc_id,
            )

            # Update document row: store ciphertext, nonce, key_version; NULL out plaintext content
            conn.execute(
                text(
                    "UPDATE documents "
                    "SET key_version = :key_version, nonce = :nonce, ciphertext = :ciphertext, content = NULL "
                    "WHERE id = :id"
                ),
                {
                    "id": doc_id,
                    "key_version": key_version,
                    "nonce": doc_nonce,
                    "ciphertext": ciphertext,
                },
            )
            print(f"[+] Encrypted document {doc_id} ('{doc.title}') under tenant {tenant_id} (key v{key_version}).")

        # Step 3: Plaintext Elimination Assertions
        remaining_plaintext_count = conn.execute(
            text("SELECT count(*) FROM documents WHERE content IS NOT NULL")
        ).scalar()

        unencrypted_docs_count = conn.execute(
            text("SELECT count(*) FROM documents WHERE ciphertext IS NULL")
        ).scalar()

        total_docs = conn.execute(text("SELECT count(*) FROM documents")).scalar()

        print("=" * 60)
        print("DATABASE ENCRYPTION VERIFICATION ASSERTIONS:")
        print(f"  Total documents in database: {total_docs}")
        print(f"  Documents with non-null plaintext content: {remaining_plaintext_count}")
        print(f"  Documents with null ciphertext: {unencrypted_docs_count}")
        print("=" * 60)

        assert remaining_plaintext_count == 0, f"Violation: {remaining_plaintext_count} plaintext documents remain in database!"
        assert unencrypted_docs_count == 0, f"Violation: {unencrypted_docs_count} documents lack ciphertext!"

    engine.dispose()
    print("[SUCCESS] Level 5 migration and plaintext backfill completed successfully!")
    print("          Zero plaintext document content remains in tenantshield_db.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TenantShield Level 5 Database Migration & Backfill")
    parser.add_argument(
        "--admin-url",
        type=str,
        default=None,
        help="PostgreSQL admin connection URL",
    )
    args = parser.parse_args()
    run_level5_migration(args.admin_url)
