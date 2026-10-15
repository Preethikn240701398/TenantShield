# TenantShield — Security, Cryptography & Configuration Contract

> **Document Version**: 1.1.0 (Level 5 — Envelope Encryption & Crypto-Shredding)  
> **Target Environment**: Windows Native PostgreSQL 16, Python 3.10+, FastAPI  
> **Mandatory Principle**: Do not invent results or claim the system is secure.

---

## 1. Formal Configuration Contract

| Parameter | Type | Default / Requirement | Permissible Values | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| `APP_ENV` | `string` | `"development"` | `"development"`, `"test"`, `"lab"`, `"production"` | Controls environment-specific behavior and governs security control switches. |
| `ENABLE_APP_OWNERSHIP_CHECK` | `boolean` | `true` | `true`, `false` (only if `APP_ENV=lab`) | **Layer A Switch**: Service-layer document tenant ownership checks before data operations. |
| `ENABLE_DB_RLS` | `boolean` | `true` | `true`, `false` (only if `APP_ENV=lab`) | **Layer B Switch**: Database Row-Level Security enforcement for isolation experiments. |
| `TENANTSHIELD_MASTER_KEY` | `string` | Required 256-bit hex | 64 hexadecimal characters (32 bytes) | **Cryptographic Master Key (KEK)**: Wraps/unwraps per-tenant DEKs via AES-256-GCM. Never stored in DB or committed. |
| `DATABASE_URL` | `string` | `postgresql+asyncpg://...` | Connection URL | Primary database connection (`tenantshield_db`) using restricted role `tenantshield_app`. |
| `LAB_DATABASE_URL` | `string` | `postgresql+asyncpg://...` | Connection URL | Isolated lab database connection (`tenantshield_lab`). |
| `POSTGRES_ADMIN_URL` | `string` | Administrative URL | Connection URL | DDL migrations & database provisioning (role: `postgres`). |

---

## 2. Cryptographic Architecture: Envelope Encryption

TenantShield implements a two-tier key hierarchy using the Python `cryptography` library and AES-256-GCM:

```
                  TENANTSHIELD_MASTER_KEY (Environment Variable)
                                  │
                                  ▼ (AES-256-GCM Wrap / Unwrap)
                       Wrapped DEK in Database
                      (tenant_keys.wrapped_dek)
                                  │
                                  ▼ (Unwrapped into memory per operation)
                   Tenant Data Encryption Key (DEK)
                                  │
                                  ▼ (AES-256-GCM Encrypt / Decrypt with AAD)
                   Document Payload (documents.ciphertext)
```

### Deterministic Authenticated Additional Data (AAD)
Every document encryption and decryption binds tenant and document identity deterministically:
```python
aad = f"tenant_id:{tenant_id}|document_id:{document_id}".encode("utf-8")
```
- **Relocation Immunity**: Moving ciphertext or nonce to a different `tenant_id` or `document_id` triggers AES-GCM tag verification failure (`InvalidTag`), returning generic `404 Not Found` without disclosing cryptographic errors.
- **Nonce Freshness**: A cryptographically random 96-bit (12-byte) nonce is generated independently for every encryption operation (`os.urandom(12)`).

---

## 3. Database Isolation & Row-Level Security (RLS)

### Session Variable & Policies
- **PostgreSQL Context Setting**: `app.current_tenant_id` (transaction-local: `is_local = true`).
- **Policy on `documents`**:
  ```sql
  CREATE POLICY tenant_isolation_policy ON documents
      FOR ALL
      USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
      WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
  ```
- **Policy on `tenant_keys`**:
  ```sql
  CREATE POLICY tenant_keys_isolation_policy ON tenant_keys
      FOR ALL
      USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
      WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
  ```
- **Table Permissions**: Role `tenantshield_app` possesses least-privilege `SELECT, INSERT, UPDATE` on `tenant_keys` and `SELECT, INSERT, UPDATE, DELETE` on `documents`. `DELETE` is prohibited on `tenant_keys` to enforce auditability.

---

## 4. Key Lifecycle Operations

### DEK Rotation vs. Master Key Rewrapping
1. **Tenant DEK Rotation**:
   - Generates a new 256-bit DEK (version $N+1$).
   - Marks previous active DEK as `retired`.
   - New document writes use version $N+1$.
   - Existing documents remain decryptable using their stored `key_version`.
2. **Master Key (KEK) Rotation**:
   - An independent cryptographic operation where the environment Master Key is replaced.
   - All existing `wrapped_dek` rows are unwrapped with the old Master Key and rewrapped with the new Master Key.
   - Tenant DEKs and document ciphertexts are unaltered.

### Crypto-Shredding (Tenant Offboarding)
- **Mechanism**:
  - Permanently overwrites `wrapped_dek = NULL` and `wrapping_nonce = NULL`.
  - Sets `status = 'destroyed'` and records `destroyed_at = CURRENT_TIMESTAMP`.
- **Result**:
  - Documents dependent on destroyed keys become cryptographically inaccessible forever.
  - The API returns a controlled `404 Not Found` without crashing or returning raw ciphertext.
  - Other tenants' keys and documents remain completely unaffected.
- **Honest Limitations**:
  - Crypto-shredding renders data in the active database cryptographically unrecoverable.
  - Pre-existing offline database backups, external export files, operating system core dumps, or application swap/memory prior to shredding are not erased by database nullification and must be governed by data retention and purge policies.
