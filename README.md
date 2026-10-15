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
├── .env.example                 # Template for environment configuration (DB, Redis, app settings)
├── .gitignore                    # Ensures .env, caches, and virtual environments are never committed
├── requirements.txt             # Direct project dependencies (FastAPI, SQLAlchemy, Pytest, etc.)
├── README.md                    # Project documentation, architecture overview, and setup guide
│
├── scripts/
│   ├── init_db.sql              # PostgreSQL 16 DDL: tables, indexes, RLS policies, and restricted app role
│   ├── init_db.py               # Python execution runner for init_db.sql using admin credentials
│   └── seed_tenants.py          # Seeds Acme and Beta tenants & documents using restricted app role
│
├── app/
│   ├── __init__.py              # Application package marker and version info
│   ├── main.py                  # FastAPI application entrypoint, lifespan manager, and CORS middleware
│   │
│   ├── core/
│   │   ├── __init__.py          # Core package marker
│   │   ├── config.py            # Pydantic Settings model loading environment variables from .env
│   │   └── database.py          # Decoupled async SQLAlchemy engine, tenant_session manager, and health check
│   │
│   ├── api/
│   │   ├── __init__.py          # API package marker
│   │   └── routes.py            # Base endpoints: GET / (metadata) and GET /health (component health)
│   │
│   ├── models/
│   │   └── __init__.py          # Directory for upcoming SQLAlchemy ORM data models
│   │
│   ├── schemas/
│   │   └── __init__.py          # Directory for upcoming Pydantic request/response schemas
│   │
│   └── services/                # Architectural stubs for future hackathon capabilities
│       ├── __init__.py          # Services package marker
│       ├── auth.py              # Stub: Multi-tenant JWT auth, tenant resolution & password hashing
│       ├── crypto.py            # Stub: Per-tenant envelope encryption (AES-256-GCM) for documents
│       ├── rate_limiter.py      # Stub: Redis-backed tenant-aware rate limiter (prevents noisy neighbors)
│       ├── metrics.py           # Stub: Multi-tenant observability, telemetry, and security event counters
│       └── security_auditor.py  # Stub: Automated cross-tenant attack generator & isolation fuzzing
│
└── tests/
    ├── __init__.py              # Test suite package marker
    ├── conftest.py              # Pytest fixtures, setting test env and providing FastAPI TestClient
    ├── test_health.py           # Integration tests for GET / and GET /health
    └── test_tenant_isolation.py # Automated RLS tests strictly executed under restricted role
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

### Step 4: Database Infrastructure & Port Conflict Resolution

#### Scenario A: Using Local Windows PostgreSQL (Port 5432)
If PostgreSQL is already installed and running natively on Windows on port `5432`:
- In `.env`, ensure `POSTGRES_PORT=5432` and `DATABASE_URL` uses port `5432`.
- Run database initialization:
  ```powershell
  python scripts\init_db.py --admin-url postgresql+psycopg://postgres:YOUR_PASSWORD@localhost:5432/tenantshield_db
  ```

#### Scenario B: Using Docker Compose (Port 5433 Default)
If Docker Desktop is installed, start PostgreSQL 16 and Redis 7:
```powershell
docker compose up -d
```
- Docker PostgreSQL is mapped to host port `5433` by default via `docker-compose.yml` (`127.0.0.1:5433:5432`) to avoid collisions with port `5432`.
- Update `.env` to connect to port `5433`:
  ```ini
  POSTGRES_PORT=5433
  DATABASE_URL=postgresql+asyncpg://tenantshield_app:change_this_secure_password@localhost:5433/tenantshield_db
  POSTGRES_ADMIN_URL=postgresql+psycopg://postgres:postgres_password@localhost:5433/tenantshield_db
  ```

> [!NOTE]
> Docker entrypoint scripts in `/docker-entrypoint-initdb.d/` run **only once** when the volume is newly created. If the database already exists, run `python scripts\init_db.py` to update the schema rather than deleting data volumes.

### Step 5: Seed Sample Multi-Tenant Data (Acme & Beta)
```powershell
python scripts\seed_tenants.py
```
This script provisions Acme Corp and Beta Industries sample tenants and populates their confidential documents using the restricted role with transaction-local tenant context.

### Step 6: Run the FastAPI Development Server
```powershell
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```
- **Root**: [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
- **Health**: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)
- **Interactive OpenAPI Docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

### Step 7: Run Automated Tests
```powershell
# Run full test suite (17 tests)
pytest -v

# Run tenant isolation tests only (15 tests)
pytest -v tests\test_tenant_isolation.py
```

---

## 4. Scope and Security Boundaries

- **Verified by Tests**:
  - PostgreSQL Row-Level Security on `documents` table (`FORCE ROW LEVEL SECURITY`).
  - Restricted role `tenantshield_app` lacks `SUPERUSER`, `BYPASSRLS`, `CREATEDB`, `CREATEROLE`, and table ownership.
  - Cross-tenant read, update, and delete are completely blocked.
  - Cross-tenant insert is rejected by PostgreSQL `WITH CHECK` constraint.
  - Unauthenticated sessions without tenant context cannot view or insert documents.
  - Transaction-local context (`is_local = true`) does not leak into subsequent queries.

- **Out of Scope (Future Hackathon Phases)**:
  - Cryptographic token authentication (JWT issuance and validation in `app/services/auth.py`).
  - Redis tenant-aware rate limiting (`app/services/rate_limiter.py`).
  - Per-tenant AES-256-GCM envelope encryption (`app/services/crypto.py`).
  - Automated penetration attack generation (`app/services/security_auditor.py`).
