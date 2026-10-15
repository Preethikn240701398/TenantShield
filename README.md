# TenantShield

> **Secure Multi-Tenant SaaS Workspace API**  
> Built with **FastAPI**, **PostgreSQL 16**, and **Row-Level Security (RLS)**.

---

## 1. Project Overview & Architecture

TenantShield is a foundational multi-tenant SaaS backend engineered for strict tenant isolation. It enforces tenant boundaries directly inside the PostgreSQL 16 database using Row-Level Security (RLS) coupled with a restricted database role (`tenantshield_app`) operating under the principle of least privilege.

### Key Defense Mechanisms
1. **Row-Level Security (RLS) on Documents**:
   - `ALTER TABLE documents ENABLE ROW LEVEL SECURITY;`
   - `ALTER TABLE documents FORCE ROW LEVEL SECURITY;`
   - Policy `tenant_isolation_policy` enforces:
     ```sql
     tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
     ```
   - Applies to both `USING` (read/update/delete) and `WITH CHECK` (insert/update). If tenant context is unset or mismatched, PostgreSQL rejects access.

2. **Restricted Application Database Role (`tenantshield_app`)**:
   - **Privileges**: `LOGIN`, `NOSUPERUSER`, `NOCREATEDB`, `NOCREATEROLE`, `NOBYPASSRLS`.
   - **Table Ownership**: The application role does NOT own any tables (`postgres` owns all tables).
   - **Least-Privilege Grants**:
     - `documents`: `SELECT`, `INSERT`, `UPDATE`, `DELETE` (full workspace CRUD for active tenant).
     - `tenants`: `SELECT` only (tenant provisioning requires administrative access).
     - `users`: `SELECT` only (user management handled by administrative or auth modules).
     - `security_events`: `SELECT`, `INSERT` (audit event ingestion; tampering prohibited).
     - Schema DDL: Cannot `CREATE` or `DROP` tables.

3. **Transaction-Local Tenant Context (`tenant_session`)**:
   - Uses `SELECT set_config('app.current_tenant_id', :tenant_id, true)`.
   - The third parameter `is_local = true` scopes the context strictly to the active transaction block.
   - When the transaction commits or aborts, the session variable immediately clears, preventing context leaks across pooled connections.

---

## 2. Project Structure & File Guide

```
TenantShield/
├── docker-compose.yml           # PostgreSQL 16 & Redis 7 container orchestration
├── pytest.ini                   # Pytest configuration (pythonpath and asyncio mode)
├── .env.example                 # Template for environment configuration (DB, JWT, seeds)
├── .gitignore                    # Ensures .env, caches, and virtual environments are never committed
├── requirements.txt             # Direct project dependencies (FastAPI, SQLAlchemy, PyJWT, Argon2, etc.)
├── README.md                    # Project documentation, architecture overview, and setup guide
│
├── scripts/
│   ├── init_db.sql              # PostgreSQL 16 DDL: tables, indexes, RLS policies, and restricted app role
│   ├── init_db.py               # Python execution runner for init_db.sql using admin credentials
│   └── seed_tenants.py          # Seeds Acme, Beta, Admin tenants, users (Argon2id), and documents
│
├── app/
│   ├── __init__.py              # Application package marker and version info
│   ├── main.py                  # FastAPI application entrypoint, routes registration, and lifespan
│   │
│   ├── core/
│   │   ├── __init__.py          # Core package marker
│   │   ├── config.py            # Pydantic Settings model loading environment variables from .env
│   │   └── database.py          # Decoupled async engine (NullPool in tests), session management, RLS context
│   │
│   ├── api/
│   │   ├── __init__.py          # API package marker
│   │   ├── deps.py              # Dependencies: get_current_user, get_tenant_db (trusted tenant context)
│   │   ├── routes.py            # Base endpoints: GET / (metadata) and GET /health (component health)
│   │   ├── auth.py              # Auth endpoints: POST /auth/login and GET /auth/me
│   │   └── documents.py         # Multi-tenant document endpoints: GET /documents, POST /documents
│   │
│   ├── models/
│   │   ├── __init__.py          # Models package marker
│   │   ├── base.py              # SQLAlchemy DeclarativeBase
│   │   └── user.py              # User ORM model mapping to users table
│   │
│   ├── schemas/
│   │   ├── __init__.py          # Schemas package marker
│   │   └── auth.py              # Pydantic models: LoginRequest, TokenResponse, AuthenticatedUser
│   │
│   └── services/
│       ├── __init__.py          # Services package marker
│       ├── auth.py              # Argon2id password hashing, PyJWT issuance, strict claims verification
│       ├── crypto.py            # Stub: Per-tenant envelope encryption (AES-256-GCM) for documents (Level 5)
│       ├── rate_limiter.py      # Stub: Redis-backed tenant-aware rate limiter (Level 4)
│       ├── metrics.py           # Stub: Multi-tenant observability and security event telemetry
│       └── security_auditor.py  # Stub: Automated cross-tenant attack generator & fuzzing
│
└── tests/
    ├── __init__.py              # Test suite package marker
    ├── conftest.py              # Pytest fixtures, test env configuration, TestClient provider
    ├── test_health.py           # Integration tests for GET / and GET /health (2 tests)
    ├── test_tenant_isolation.py # Automated RLS tests strictly under restricted role (15 tests)
    └── test_auth.py             # Auth & trusted tenant context security tests (13 tests)
```

---

## 3. Getting Started on Windows (PowerShell)

### Step 1: Create and Activate Virtual Environment
```powershell
cd c:\Users\Preethi\Downloads\TenantShield

# Create virtual environment
python -m venv .venv

# Activate virtual environment
.\.venv\Scripts\Activate.ps1
```
*(If PowerShell blocks script execution, run: `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`)*

### Step 2: Install Dependencies
```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Step 3: Configure Environment Variables
Copy `.env.example` to `.env`:
```powershell
Copy-Item .env.example .env
```
> [!IMPORTANT]
> The passwords in `.env.example` are development placeholders. Never reuse them in production environments. `.env` is ignored by Git and must never be committed.

### Step 4: Database Infrastructure & Port Configuration

#### Local Windows PostgreSQL (Port 5432)
Ensure PostgreSQL is running on port `5432` and run database initialization if not already done:
```powershell
python scripts\init_db.py --admin-url postgresql+psycopg://postgres:YOUR_PASSWORD@localhost:5432/tenantshield_db
```

### Step 5: Seed Multi-Tenant Data & Users (Acme, Beta, Admin)
```powershell
python scripts\seed_tenants.py
```
This script idempotently seeds:
- **Acme Corp**: user `acme_user@acme.test` (`AcmeSecretPassword123!`), confidential strategy documents.
- **Beta Industries**: user `beta_user@beta.test` (`BetaSecretPassword123!`), confidential specifications.
- **TenantShield System**: platform admin `admin@tenantshield.test` (`PlatformAdminPassword123!`).

All passwords are hashed with **Argon2id**.

### Step 6: Run the FastAPI Development Server
```powershell
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```
- **Root**: [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
- **Health**: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)
- **Interactive OpenAPI Docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

### Step 7: Authenticating and Testing API via PowerShell
Obtain a JWT for Acme Corp:
```powershell
$response = Invoke-RestMethod -Uri http://127.0.0.1:8000/auth/login -Method Post -ContentType "application/json" -Body '{"email":"acme_user@acme.test","password":"AcmeSecretPassword123!"}'
$token = $response.access_token

# Access current authenticated user profile
Invoke-RestMethod -Uri http://127.0.0.1:8000/auth/me -Method Get -Headers @{ Authorization = "Bearer $token" }

# Read documents (scoped strictly to Acme via RLS)
Invoke-RestMethod -Uri http://127.0.0.1:8000/documents -Method Get -Headers @{ Authorization = "Bearer $token" }
```

### Step 8: Run Automated Tests
```powershell
# Run full test suite (30 tests)
pytest -v

# Run authentication and trusted tenant context tests only (13 tests)
pytest -v tests\test_auth.py

# Run database tenant isolation and RLS tests only (15 tests)
pytest -v tests\test_tenant_isolation.py
```

---

## 4. Scope and Security Boundaries

- **Verified by Tests (30/30 Passing)**:
  - **Argon2id Password Hashing**: Passwords stored as cryptographically salted Argon2id hashes.
  - **PyJWT Issuance & Verification**: Enforces signature validity, expiration (`exp`), and required claims (`user_id`, `tenant_id`, `role`). Rejects wrong secrets and algorithm tampering (e.g. `none` algorithm).
  - **Anti-Enumeration Login**: Returns identical generic HTTP 401 on incorrect password or non-existent user.
  - **Trusted Tenant Context**: `get_tenant_db` derives tenant context strictly from the verified JWT claims and invokes `set_config('app.current_tenant_id', :tenant_id, true)` transaction-locally (`is_local=true`).
  - **Client Override Immunity**: Headers (like `X-Tenant-ID`), query parameters, and body payloads cannot alter the database tenant context.
  - **Account Status Enforcement**: Disabled or deleted users cannot use unexpired tokens.
  - **PostgreSQL Row-Level Security**: `FORCE ROW LEVEL SECURITY` on `documents` table ensures no cross-tenant read, write, update, or delete under `tenantshield_app` role.
  - **Platform Admin Boundaries**: Platform admins do not bypass document RLS; queries remain scoped to their respective tenant context.

- **Out of Scope (Future Hackathon Levels 4+)**:
  - Redis tenant-aware rate limiting (Level 4).
  - Per-tenant envelope encryption with KMS (Level 5).
  - Automated penetration attack generation & security audit (Level 11).
