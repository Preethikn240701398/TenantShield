"""
TenantShield - Cryptography & Envelope Encryption Service
=========================================================
Implements tenant-specific envelope encryption and crypto-shredding using
AES-256-GCM via the Python `cryptography` library.

Key Hierarchy:
1. Master Key (KEK): 256-bit key loaded from environment variable TENANTSHIELD_MASTER_KEY.
   Never persisted in the database or logged.
2. Data Encryption Key (DEK): 256-bit randomly generated per tenant and key version.
   Stored only in wrapped (encrypted) form in the `tenant_keys` table.

Guarantees:
- Deterministic AAD binding: `tenant_id:{tenant_id}|document_id:{document_id}`
- Unique 96-bit random nonce per AES-GCM encryption
- Key versioning and rotation
- Irreversible crypto-shredding: wrapped DEK material is permanently nullified,
  rendering dependent ciphertexts cryptographically inaccessible.
"""

import os
from typing import Optional, Tuple
from uuid import UUID
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings


class CryptoError(Exception):
    """Base exception for cryptographic operations."""
    pass


class CryptoAuthenticationError(CryptoError):
    """Raised when AES-GCM authentication fails (ciphertext, nonce, or AAD tampering)."""
    pass


class CryptoKeyNotFoundError(CryptoError):
    """Raised when a requested tenant encryption key version is not found."""
    pass


class CryptoShreddedError(CryptoError):
    """Raised when attempting to access or decrypt with a crypto-shredded (destroyed) DEK."""
    pass


class CryptoService:
    """Provides cryptographic operations for tenant envelope encryption and key lifecycle."""

    _WRAPPING_AAD = b"tenantshield:dek_wrapping:v1"

    @classmethod
    def get_master_key(cls) -> bytes:
        """
        Retrieves the 256-bit master key from settings.
        Validates key length and returns raw 32 bytes.
        """
        raw_str = (settings.TENANTSHIELD_MASTER_KEY or "").strip()
        if not raw_str:
            raise CryptoError("Master key is missing. Ensure TENANTSHIELD_MASTER_KEY is configured.")

        # Attempt hex decode
        if len(raw_str) == 64:
            try:
                key_bytes = bytes.fromhex(raw_str)
                if len(key_bytes) == 32:
                    return key_bytes
            except ValueError:
                pass

        # Attempt base64 decode
        import base64
        try:
            key_bytes = base64.b64decode(raw_str, validate=True)
            if len(key_bytes) == 32:
                return key_bytes
        except Exception:
            pass

        raise CryptoError("Invalid TENANTSHIELD_MASTER_KEY: must be exactly 32 bytes (256 bits).")

    @classmethod
    def generate_dek(cls) -> bytes:
        """Generates a cryptographically secure 256-bit random Data Encryption Key."""
        return os.urandom(32)

    @classmethod
    def wrap_dek(cls, dek: bytes, master_key: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Encrypts a DEK using the 256-bit Master Key with AES-256-GCM.
        Returns: (wrapped_dek, wrapping_nonce)
        """
        kek = master_key or cls.get_master_key()
        nonce = os.urandom(12)
        aesgcm = AESGCM(kek)
        wrapped_dek = aesgcm.encrypt(nonce, dek, cls._WRAPPING_AAD)
        return wrapped_dek, nonce

    @classmethod
    def unwrap_dek(cls, wrapped_dek: bytes, wrapping_nonce: bytes, master_key: Optional[bytes] = None) -> bytes:
        """
        Decrypts a wrapped DEK using the 256-bit Master Key with AES-256-GCM.
        Raises CryptoAuthenticationError on corrupted key material or wrong master key.
        """
        kek = master_key or cls.get_master_key()
        try:
            aesgcm = AESGCM(kek)
            dek = aesgcm.decrypt(wrapping_nonce, wrapped_dek, cls._WRAPPING_AAD)
            return dek
        except InvalidTag as exc:
            raise CryptoAuthenticationError("Failed to unwrap DEK: Master key mismatch or corrupted key material.") from exc

    @classmethod
    def build_aad(cls, tenant_id: UUID | str, document_id: UUID | str) -> bytes:
        """
        Constructs deterministic Authenticated Additional Data (AAD)
        binding tenant identity and document identity.
        """
        return f"tenant_id:{str(tenant_id)}|document_id:{str(document_id)}".encode("utf-8")

    @classmethod
    def encrypt_document(
        cls,
        dek: bytes,
        plaintext: str,
        tenant_id: UUID | str,
        document_id: UUID | str,
    ) -> Tuple[bytes, bytes]:
        """
        Encrypts document plaintext using the tenant's DEK with AES-256-GCM.
        Binds tenant_id and document_id via deterministic AAD.
        Returns: (nonce, ciphertext)
        """
        nonce = os.urandom(12)
        aad = cls.build_aad(tenant_id, document_id)
        aesgcm = AESGCM(dek)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad)
        return nonce, ciphertext

    @classmethod
    def decrypt_document(
        cls,
        dek: bytes,
        ciphertext: bytes,
        nonce: bytes,
        tenant_id: UUID | str,
        document_id: UUID | str,
    ) -> str:
        """
        Decrypts document ciphertext using tenant DEK with AES-256-GCM.
        Verifies authentication tag against deterministic AAD.
        Raises CryptoAuthenticationError on tampering, cross-tenant copying,
        cross-document copying, or wrong DEK.
        """
        aad = cls.build_aad(tenant_id, document_id)
        try:
            aesgcm = AESGCM(dek)
            plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, aad)
            return plaintext_bytes.decode("utf-8")
        except InvalidTag as exc:
            raise CryptoAuthenticationError(
                "Document decryption failed: Ciphertext, nonce, or authenticated metadata verification failed."
            ) from exc

    @classmethod
    async def get_or_create_active_dek(
        cls,
        session: AsyncSession,
        tenant_id: UUID | str,
    ) -> Tuple[int, bytes]:
        """
        Fetches the current active DEK for a tenant, or provisions version 1 if none exists.
        Returns: (key_version, unwrapped_dek)
        """
        tenant_str = str(tenant_id)
        result = await session.execute(
            text(
                "SELECT key_version, wrapped_dek, wrapping_nonce, status "
                "FROM tenant_keys "
                "WHERE tenant_id = :tenant_id AND status = 'active' "
                "ORDER BY key_version DESC LIMIT 1"
            ),
            {"tenant_id": tenant_str},
        )
        row = result.fetchone()

        if row:
            dek = cls.unwrap_dek(row.wrapped_dek, row.wrapping_nonce)
            return row.key_version, dek

        # Determine next key version: max(existing) + 1
        max_res = await session.execute(
            text("SELECT COALESCE(MAX(key_version), 0) FROM tenant_keys WHERE tenant_id = :tenant_id"),
            {"tenant_id": tenant_str},
        )
        next_ver = max_res.scalar_one() + 1

        new_dek = cls.generate_dek()
        wrapped, nonce = cls.wrap_dek(new_dek)
        await session.execute(
            text(
                "INSERT INTO tenant_keys (tenant_id, key_version, wrapped_dek, wrapping_nonce, status) "
                "VALUES (:tenant_id, :key_version, :wrapped_dek, :wrapping_nonce, 'active')"
            ),
            {
                "tenant_id": tenant_str,
                "key_version": next_ver,
                "wrapped_dek": wrapped,
                "wrapping_nonce": nonce,
            },
        )
        return next_ver, new_dek

    @classmethod
    async def get_dek_for_version(
        cls,
        session: AsyncSession,
        tenant_id: UUID | str,
        key_version: int,
    ) -> bytes:
        """
        Retrieves and unwraps the DEK for a specific version.
        Raises CryptoShreddedError if the key was destroyed.
        Raises CryptoKeyNotFoundError if the version does not exist.
        """
        result = await session.execute(
            text(
                "SELECT wrapped_dek, wrapping_nonce, status "
                "FROM tenant_keys "
                "WHERE tenant_id = :tenant_id AND key_version = :key_version"
            ),
            {
                "tenant_id": str(tenant_id),
                "key_version": key_version,
            },
        )
        row = result.fetchone()

        if not row:
            raise CryptoKeyNotFoundError(f"Key version {key_version} not found for tenant.")

        if row.status == "destroyed" or row.wrapped_dek is None:
            raise CryptoShreddedError(
                f"Encryption key version {key_version} for tenant has been permanently shredded."
            )

        return cls.unwrap_dek(row.wrapped_dek, row.wrapping_nonce)

    @classmethod
    async def rotate_tenant_dek(
        cls,
        session: AsyncSession,
        tenant_id: UUID | str,
    ) -> int:
        """
        Rotates a tenant's active DEK:
        1. Retires existing active DEK (status = 'retired').
        2. Generates new DEK (version N + 1) and stores it as 'active'.
        Returns the new active key version.
        """
        tenant_str = str(tenant_id)

        # Lock active key row to prevent concurrent rotation races
        result = await session.execute(
            text(
                "SELECT key_version FROM tenant_keys "
                "WHERE tenant_id = :tenant_id AND status = 'active' "
                "ORDER BY key_version DESC LIMIT 1 FOR UPDATE"
            ),
            {"tenant_id": tenant_str},
        )
        active_row = result.fetchone()

        if active_row:
            current_version = active_row.key_version
            # Retire current active key
            await session.execute(
                text(
                    "UPDATE tenant_keys SET status = 'retired', retired_at = CURRENT_TIMESTAMP "
                    "WHERE tenant_id = :tenant_id AND key_version = :key_version"
                ),
                {
                    "tenant_id": tenant_str,
                    "key_version": current_version,
                },
            )
            next_version = current_version + 1
        else:
            # Check maximum version among retired/destroyed
            max_res = await session.execute(
                text("SELECT COALESCE(MAX(key_version), 0) FROM tenant_keys WHERE tenant_id = :tenant_id"),
                {"tenant_id": tenant_str},
            )
            next_version = max_res.scalar_one() + 1

        new_dek = cls.generate_dek()
        wrapped, nonce = cls.wrap_dek(new_dek)

        await session.execute(
            text(
                "INSERT INTO tenant_keys (tenant_id, key_version, wrapped_dek, wrapping_nonce, status) "
                "VALUES (:tenant_id, :key_version, :wrapped_dek, :wrapping_nonce, 'active')"
            ),
            {
                "tenant_id": tenant_str,
                "key_version": next_version,
                "wrapped_dek": wrapped,
                "wrapping_nonce": nonce,
            },
        )
        return next_version

    @classmethod
    async def crypto_shred_tenant_dek(
        cls,
        session: AsyncSession,
        tenant_id: UUID | str,
        key_version: Optional[int] = None,
    ) -> int:
        """
        Permanently destroys tenant encryption key material (Crypto-Shredding):
        - Nullifies wrapped_dek and wrapping_nonce.
        - Marks status as 'destroyed' with destroyed_at timestamp.
        - If key_version is specified, shreds only that version.
        - If key_version is None, shreds ALL keys for the tenant (full crypto-offboarding).
        Returns the number of keys destroyed.
        """
        tenant_str = str(tenant_id)
        if key_version is not None:
            update_sql = (
                "UPDATE tenant_keys "
                "SET wrapped_dek = NULL, wrapping_nonce = NULL, status = 'destroyed', destroyed_at = CURRENT_TIMESTAMP "
                "WHERE tenant_id = :tenant_id AND key_version = :key_version AND status != 'destroyed'"
            )
            params = {"tenant_id": tenant_str, "key_version": key_version}
        else:
            update_sql = (
                "UPDATE tenant_keys "
                "SET wrapped_dek = NULL, wrapping_nonce = NULL, status = 'destroyed', destroyed_at = CURRENT_TIMESTAMP "
                "WHERE tenant_id = :tenant_id AND status != 'destroyed'"
            )
            params = {"tenant_id": tenant_str}

        result = await session.execute(text(update_sql), params)
        shredded_count = result.rowcount
        return shredded_count
