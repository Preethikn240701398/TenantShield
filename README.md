# TenantShield

> **Secure Multi-Tenant SaaS Workspace API**  
> Built with **FastAPI**, **PostgreSQL 16**, **Row-Level Security (RLS)**, and **AES-256-GCM Envelope Encryption & Crypto-Shredding**.  
> **Mandatory principle: Do not invent results or claim the system is secure.**

---

## 1. Project Overview & Multi-Layer Defense

TenantShield is an enterprise multi-tenant SaaS workspace API engineered with defense-in-depth:
1. **Layer A: Application-Level Tenant Ownership Checks**: Enforced in FastAPI services (`check_document_ownership`).
2. **Layer B: PostgreSQL Row-Level Security (RLS)**: Enforced directly inside PostgreSQL 16 on `documents` and `tenant_keys` tables using transaction-scoped context `app.current_tenant_id` (`is_local=true`) under restricted role `tenantshield_app` (`NOSUPERUSER`, `NOBYPASSRLS`).
3. **Layer C: Envelope Encryption at Rest**: Per-tenant AES-256-GCM encryption for sensitive document contents using versioned Data Encryption Keys (DEKs) wrapped by a dedicated Master Key (`TENANTSHIELD_MASTER_KEY`).
4. **Deterministic AAD Binding**: Binds `tenant_id` and `document_id` into AES-GCM Authenticated Additional Data (`f"tenant_id:{tenant_id}|document_id:{document_id}"`). Ciphertext copied across tenants or documents fails authentication (`InvalidTag`).
5. **Key Versioning & Rotation**: Writing new documents uses the active DEK version ($N+1$), while older documents remain decryptable using their retired DEKs.
6. **Crypto-Shredding (Tenant Offboarding)**: Irreversible destruction of wrapped DEKs (`wrapped_dek = NULL`, `status = 'destroyed'`), rendering dependent ciphertexts permanently unreadable while keeping other tenants unaffected.

---

## 2. Directory Structure

```
TenantShield/
├── CONTRACT.md                  # Formal security and configuration contract
├── README.md                    # Project documentation and setup guide
├── requirements.txt             # Dependencies (FastAPI, cryptography, SQLAlchemy, pytest)
├── pytest.ini                   # Pytest configuration
├── .env.example                 # Environment configuration template
│
├── scripts/
│   ├── init_db.sql              # Base schema with RLS and least-privilege role setup
│   ├── init_db.py               # Administrative schema initialization runner
│   ├── seed_tenants.py          # Seeds Acme, Beta, and System tenants, users, and docs
│   ├── migrate_level5.py        # Applies Level 5 migration, provisions DEKs, backfills plaintext
│   ├── rotate_tenant_dek.py     # CLI runner to rotate tenant DEK
│   ├── shred_tenant_dek.py      # CLI runner to crypto-shred tenant DEK
│   ├── setup_lab_db.py          # Dedicated lab database runner for isolation experiments
│   └── migrations/
│       └── 005_envelope_encryption.sql  # Level 5 SQL migration
│
├── app/
│   ├── main.py                  # FastAPI application entrypoint and router registration
│   ├── core/
│   │   ├── config.py            # Settings with startup validation for Master Key & lab switches
│   │   └── database.py          # Database engines, sessionmakers, and tenant_session context
│   ├── api/
│   │   ├── deps.py              # Authentication and trusted tenant context dependencies
│   │   ├── auth.py              # Login and token endpoints
│   │   ├── documents.py         # Multi-tenant document CRUD with envelope encryption
│   │   ├── admin.py             # Platform admin endpoints for key rotation and shredding
│   │   └── routes.py            # Base endpoints (/ and /health)
│   ├── models/                  # SQLAlchemy ORM models
│   ├── schemas/                 # Pydantic schemas (auth, documents)
│   └── services/
│       ├── auth.py              # Argon2id password hashing and PyJWT token handling
│       ├── crypto.py            # Envelope encryption, DEK wrapping, AES-256-GCM, AAD binding
│       └── document_ownership.py# Layer A application ownership checks
│
├── results/                     # Verifiable timestamped experiment evidence JSON logs
└── tests/
    ├── test_health.py           # Health endpoint tests
    ├── test_auth.py             # JWT authentication and trusted context tests
    ├── test_tenant_isolation.py # PostgreSQL RLS and restricted role tests
    ├── test_document_api.py     # Document CRUD and dual-layer switch tests
    └── test_crypto_envelope.py  # 15 tests: Envelope encryption, rotation, shredding, AAD
```

---

## 3. Cryptographic Specification (Level 5)

### Key Hierarchy
- **Master Key (KEK)**: 256-bit key configured in `TENANTSHIELD_MASTER_KEY` as 64 hexadecimal characters. Validated at startup; never logged or stored in the database.
- **Tenant Data Encryption Key (DEK)**: 256-bit cryptographically random key (`os.urandom(32)`) generated per tenant and version, wrapped using AES-256-GCM with the Master Key and stored in `tenant_keys`.

### Document Encryption Details
- **Algorithm**: AES-256-GCM via Python `cryptography`.
- **Nonce**: Fresh 96-bit random nonce (`os.urandom(12)`) per encryption operation.
- **AAD**: Deterministic byte string:
  ```python
  aad = f"tenant_id:{tenant_id}|document_id:{document_id}".encode("utf-8")
  ```
- **Plaintext Elimination**: Persisted `content` column is strictly NULL for all application documents. Only `ciphertext`, `nonce`, and `key_version` are saved in PostgreSQL.

---

## 4. Setup & Running on Windows (PowerShell)

### Step 1: Virtual Environment & Dependencies
```powershell
# Activate Python 3.10 virtual environment
.\.venv\Scripts\Activate.ps1

# Install requirements
pip install -r requirements.txt
```

### Step 2: Configure Environment
Copy `.env.example` to `.env` if not already present.
Generate a secure 256-bit Master Key in PowerShell:
```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```
Place the 64-character hex string into `.env`:
```ini
TENANTSHIELD_MASTER_KEY=your_64_character_hex_master_key
POSTGRES_ADMIN_URL=postgresql+psycopg://postgres:YOUR_PASSWORD@localhost:5432/tenantshield_db
```

### Step 3: Run Level 5 Database Migration & Backfill
```powershell
python scripts\migrate_level5.py
```
This script:
1. Executes `scripts/migrations/005_envelope_encryption.sql` to create `tenant_keys` with RLS.
2. Adds `key_version`, `nonce`, and `ciphertext` to `documents`.
3. Provisions initial active DEKs (version 1) for all tenants.
4. Encrypts all existing plaintext documents with AES-256-GCM and deterministic AAD.
5. Nullifies `content` column and asserts zero plaintext documents remain in `tenantshield_db`.

### Step 4: Run the Development Server
```powershell
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```
- Interactive Swagger UI: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- Health Endpoint: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)

### Step 5: Key Rotation & Crypto-Shredding CLI Commands
```powershell
# Rotate DEK for Acme Corp (provisions version N+1)
python scripts\rotate_tenant_dek.py --tenant-slug acme

# Crypto-shred all DEKs for Acme Corp (permanent tenant offboarding)
python scripts\shred_tenant_dek.py --tenant-slug acme

# Crypto-shred a specific DEK version
python scripts\shred_tenant_dek.py --tenant-slug acme --key-version 1
```

---

## 5. Automated Verification & Test Results

Run the entire test suite from the project root:
```powershell
pytest -v
```

Current test status: **62 passed in 14.58s (100% passing)**.
- `tests/test_health.py`: 2 passed
- `tests/test_auth.py`: 16 passed
- `tests/test_tenant_isolation.py`: 15 passed
- `tests/test_document_api.py`: 14 passed
- `tests/test_crypto_envelope.py`: 15 passed

All test outcomes and non-sensitive cryptographic assertions are automatically saved to `results/level5_experiment_results_<timestamp>.json`.
