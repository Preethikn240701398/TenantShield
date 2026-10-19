# TenantShield

> **Secure Multi-Tenant SaaS Workspace API**  
> Built with **FastAPI**, **PostgreSQL 16 (native Windows)**, **Row-Level Security (RLS)**, **AES-256-GCM Envelope Encryption & Crypto-Shredding**, **Redis/Memurai Tenant-Aware Rate Limiting**, and an **interactive single-page web dashboard**.  
> **Mandatory principle: Do not invent results or claim the system is secure.**

---

## 1. What TenantShield Is

TenantShield is a multi-tenant document storage API that lets multiple customers (tenants) share the same server and database without being able to see each other's data. Every document belongs to exactly one tenant. When a user logs in, the server issues a JWT token that records which tenant they belong to. Every subsequent request uses that token - clients never send a tenant ID directly; the server derives it from the verified token.

The project is an **engineering experiment and interactive demonstration platform** used to study, measure, and attack the isolation properties of a multi-tenant system. It features automated attack suites, mutation testing, a layer-kill matrix, noisy-neighbour load experiments, in-browser live verification, key lifecycle crypto-shredding demos, single-attack inspectors, and intentionally flawed routes for side-by-side comparison - all backed by machine-readable evidence in `results/`.

---

## 2. Architecture Overview

The system implements isolation at multiple independent layers, so that a bug in any single layer does not cause a data leak (defense-in-depth).

| Layer / Component | Mechanism | Key file |
|-------------------|-----------|----------|
| **Token & Ownership (Layer A)** | JWT verified on every request; `check_document_ownership` rejects requests where the token's `tenant_id` does not match the document's `tenant_id` | `app/services/document_ownership.py` |
| **Query Filter (Layer C)** | Every SQL query carries `WHERE tenant_id = :tenant_id` parameterised to the token's `tenant_id` | `app/api/documents.py` |
| **Row-Level Security (Layer B)** | PostgreSQL 16 RLS policy `tenant_isolation_policy` on the `documents` table filters rows based on `app.current_tenant_id`, set `LOCAL` (transaction-scoped) by the restricted database role `tenantshield_app` (NOSUPERUSER, NOBYPASSRLS) | `scripts/init_db.sql` |
| **Envelope Encryption** | Document content is encrypted with per-tenant AES-256-GCM Data Encryption Keys (DEKs). The DEK is wrapped by a master key (`TENANTSHIELD_MASTER_KEY`). AAD binds `tenant_id` and `document_id` so cross-tenant ciphertext replay fails authentication | `app/services/crypto.py` |
| **Rate Limiter** | Fixed-window Redis rate limiter keyed to verified JWT tenant context; returns HTTP 429 with `Retry-After` header; tenant A quota is independent of tenant B quota | `app/services/rate_limiter.py` |
| **Interactive Demos & Verification API** | Endpoints for live verification polling, key lifecycle (rotation, crypto-shredding), paced multi-tenant traffic simulation, single-attack execution, live benchmark runner, and real-time configuration audit checks | `app/api/runs.py`, `app/api/demo.py`, `app/api/traffic_demo.py`, `app/api/attack_demo.py`, `app/api/benchmark_demo.py`, `app/api/config_check.py` |
| **Flawed Route Comparison** | Deliberately vulnerable routes omitting Layer A, Layer B context, and Layer C query filters for side-by-side demonstration of cross-tenant data leaks | `app/vulnerable/documents_flawed.py` |
| **Verifier Suite** | Automated HTTP attack suite that executes cross-tenant read, write, update, delete, and inject attacks against a live server | `verifier/` |
| **Dashboard & Glossary** | Platform-admin and tenant web UI surfacing live verifier results, layer-kill matrix, mutation test scores, noisy-neighbour telemetry, key lifecycle state, and interactive in-context glossary tooltips | `app/api/dashboard.py`, `ui/app.js`, `ui/glossary.js` |

The tenant lifecycle for a secure document request:

```
Client --[JWT]--> FastAPI
    --> auth.get_current_user()          # verifies token, extracts tenant_id
    --> deps.check_tenant_rate_limit()   # Redis quota check
    --> check_document_ownership()       # Layer A (ownership check)
    --> SQL + WHERE tenant_id = :tid     # Layer C (query filter)
    --> DB under tenant_session context  # SET LOCAL app.current_tenant_id
    --> RLS filters in PostgreSQL        # Layer B (row-level security)
    --> CryptoService.decrypt()          # Envelope decryption + AAD validation
```

---

## 3. Directory Structure

```
TenantShield/
+-- README.md                     # This file
+-- CONTRACT.md                   # Formal security contract
+-- requirements.txt              # Python dependencies
+-- pytest.ini                    # Pytest configuration
+-- .env.example                  # Environment template
+-- docker-compose.yml            # Optional (NOT tested - see comment in file)
|
+-- app/
|   +-- main.py                   # FastAPI app entrypoint
|   +-- core/
|   |   +-- config.py             # Settings and startup validation
|   |   +-- database.py           # Async DB engines, tenant_session context
|   +-- api/
|   |   +-- auth.py               # Login / token endpoints
|   |   +-- documents.py          # Multi-tenant document CRUD (secure)
|   |   +-- admin.py              # Platform admin: metrics, DEK rotation, shred
|   |   +-- dashboard.py          # Admin dashboard data endpoints
|   |   +-- runs.py               # Live verification runner & streaming endpoints
|   |   +-- demo.py               # Key lifecycle demo (seed, rotate, shred, read)
|   |   +-- traffic_demo.py       # Paced test traffic simulation endpoints
|   |   +-- attack_demo.py        # Single attack demo & inspection endpoints
|   |   +-- benchmark_demo.py     # Live benchmark runner endpoints
|   |   +-- config_check.py       # Live security & database audit check endpoint
|   |   +-- routes.py             # / and /health
|   +-- vulnerable/
|   |   +-- documents_flawed.py   # Flawed route demo (omits security layers)
|   +-- models/                   # SQLAlchemy ORM models
|   +-- schemas/                  # Pydantic schemas
|   +-- services/
|       +-- auth.py               # Argon2id hashing, PyJWT
|       +-- crypto.py             # AES-256-GCM envelope encryption
|       +-- rate_limiter.py       # Redis fixed-window rate limiter
|       +-- metrics.py            # Per-tenant Redis telemetry
|       +-- document_ownership.py # Layer A ownership check
|
+-- verifier/                     # Cross-tenant attack verification suite
+-- loadtests/                    # Noisy-neighbour experiment orchestrator
+-- scripts/
|   +-- init_db.sql               # Schema, RLS, role setup
|   +-- init_db.py                # Schema initialiser runner
|   +-- seed_tenants.py           # Seeds Acme, Beta, Admin users
|   +-- seed_demo_tenant.py       # Seeds Demo Co tenant for key lifecycle demos
|   +-- migrate_level5.py         # Encryption migration + DEK provisioning
|   +-- setup_lab_db.ps1          # Set up isolated tenantshield_lab DB
|   +-- run_matrix.ps1            # Layer-Kill Matrix runner
|   +-- run_mutation.ps1          # Mutation testing runner
|   +-- run_verifier.py           # Verifier runner
|   +-- single_attack.py          # Standalone CLI single-attack execution script
|   +-- send_test_traffic.py      # Standalone CLI paced traffic generator
|   +-- live_benchmark.py         # Standalone CLI live benchmark runner
|
+-- ui/
|   +-- index.html                # Single-page web UI
|   +-- app.js                    # Frontend script with interactive panels
|   +-- glossary.js               # Interactive glossary definitions & tooltips
|   +-- style.css                 # Dashboard styles and animations
|
+-- tests/                        # Automated test suite (176 tests across 16 files)
+-- results/                      # Timestamped experiment evidence files
```

---

## 4. Environment: PostgreSQL 16 and Memurai on Windows

These experiments ran on native Windows PostgreSQL 16 and Memurai Developer on a single laptop with one uvicorn worker.

### Assumptions for this document
- PostgreSQL 16 is installed and running natively on Windows (not Docker).
- The main database is `tenantshield_db`; the lab database for experiments is `tenantshield_lab`.
- The restricted application role is `tenantshield_app` (NOSUPERUSER, NOBYPASSRLS).
- Memurai Developer is installed and running as a Windows service on `localhost:6379`.
- Python virtual environment is at `.venv\` in the project root.

---

## 5. PostgreSQL 16 Setup (One-Time)

Run as the PostgreSQL administrative user (`postgres`). Run these commands once:

```powershell
# 1. Verify PostgreSQL is running (native Windows service)
Get-Service -Name postgresql*

# 2. Create the main application database
psql -U postgres -c "CREATE DATABASE tenantshield_db;"

# 3. Initialise schema, RLS policies, and restricted role
psql -U postgres -d tenantshield_db -f scripts\init_db.sql

# 4. Set the tenantshield_app password to match your .env
psql -U postgres -d tenantshield_db -c "ALTER ROLE tenantshield_app WITH PASSWORD 'your_app_password';"

# 5. Run the Python schema initialiser (creates tables via SQLAlchemy)
.venv\Scripts\python.exe scripts\init_db.py

# 6. Apply Level 5 encryption migration and provision DEKs
.venv\Scripts\python.exe scripts\migrate_level5.py

# 7. Seed development tenants, users, and sample documents
.venv\Scripts\python.exe scripts\seed_tenants.py

# 8. (Optional) Seed dedicated demo tenant "Demo Co" for key lifecycle & attack demos
.venv\Scripts\python.exe scripts\seed_demo_tenant.py
```

**Seeded credentials (development only):**

| Role / Tenant | Email | Password |
|---------------|-------|----------|
| Tenant A (Acme) | `acme_user@acme.test` | `AcmeSecretPassword123!` |
| Tenant B (Beta) | `beta_user@beta.test` | `BetaSecretPassword123!` |
| Demo Co (Demo Tenant) | `demo_user@democo.test` | `DemoCompanySecurePass123!` |
| Platform Admin | `admin@tenantshield.test` | `PlatformAdminPassword123!` |

---

## 6. Memurai Developer Setup (One-Time)

1. Download and install Memurai Developer from <https://www.memurai.com/>.
2. Verify the Memurai Windows service is running:
   ```powershell
   Get-Service memurai
   ```
3. Test connectivity:
   ```powershell
   memurai-cli ping
   # Expected: PONG
   ```

---

## 7. Configure the Environment

Copy `.env.example` to `.env`, then fill in the required values:

```powershell
copy .env.example .env
```

Minimum required settings in `.env`:

```ini
# PostgreSQL restricted role (runtime)
POSTGRES_APP_PASSWORD=your_app_password
DATABASE_URL=postgresql+asyncpg://tenantshield_app:your_app_password@localhost:5432/tenantshield_db
DATABASE_URL_SYNC=postgresql+psycopg://tenantshield_app:your_app_password@localhost:5432/tenantshield_db
LAB_DATABASE_URL=postgresql+asyncpg://tenantshield_app:your_app_password@localhost:5432/tenantshield_lab

# Admin URL (used only by init scripts)
POSTGRES_ADMIN_URL=postgresql+psycopg://postgres:your_admin_password@localhost:5432/tenantshield_db

# Redis / Memurai
REDIS_URL=redis://127.0.0.1:6379/0

# JWT secret - generate with: python -c "import secrets; print(secrets.token_hex(32))"
SECRET_KEY=your_64_character_hex_secret_key

# Master Key for envelope encryption (64 hex characters = 256-bit AES key)
# Generate with: python -c "import secrets; print(secrets.token_hex(32))"
TENANTSHIELD_MASTER_KEY=your_64_character_hex_master_key
```

> **Note:** `SECRET_KEY` and `POSTGRES_APP_PASSWORD` are intentionally blank in `.env` - they must be filled in with values you generate. The application will refuse to start if these are left at placeholder defaults.

---

## 8. Install Dependencies

```powershell
# Activate virtual environment
.venv\Scripts\Activate.ps1

# Install all dependencies
pip install -r requirements.txt
```

---

## 9. Running the Application

```powershell
# From the project root, with virtual environment active:
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

| URL | Description |
|-----|-------------|
| `http://127.0.0.1:8000/` | API root metadata |
| `http://127.0.0.1:8000/health` | Health check |
| `http://127.0.0.1:8000/docs` | Interactive Swagger / OpenAPI UI |
| `http://127.0.0.1:8000/ui` | Interactive Web Dashboard (workspace, admin, demos, glossary) |
| `http://127.0.0.1:8000/admin/config/check` | Real-time configuration & security audit endpoint |
| `http://127.0.0.1:8000/vulnerable/documents` | Flawed route endpoint (demonstrates raw vulnerability for comparison) |

---

## 10. Opening the Dashboard

1. Start the server (see section 9).
2. Open `http://127.0.0.1:8000/ui` in a web browser.
3. Choose your login role:
   - **Tenant User** (`acme_user@acme.test`, `beta_user@beta.test`, or `demo_user@democo.test`):
     - View, create, edit, and delete tenant-isolated documents.
     - Observe transparent encryption/decryption in real time.
   - **Platform Admin** (`admin@tenantshield.test`):
     - **Live Configuration Audit**: Instant diagnostic check of PostgreSQL connectivity, table RLS status, restricted user role privileges (`NOSUPERUSER, NOBYPASSRLS`), Redis status, and Master Key validity.
     - **Run Verification Now**: One-click in-browser execution of the verification suite with real-time progress polling and live log streaming.
     - **Key Lifecycle Demo**: Provision demo tenant "Demo Co", rotate active DEK versions, test decryption of older documents, crypto-shred the key, and witness immediate cryptographic denial.
     - **Try One Attack by Hand**: Select any attacker/victim pair and attack action (`read`, `update`, `delete`, `create-into-victim`) targeting either the `secure` route or the `vulnerable` route. Inspect the raw HTTP response code and the exact defense layer that blocked the attempt.
     - **Send Test Traffic & Dynamic Benchmark**: Launch paced simulated multi-tenant traffic and benchmark workloads, observing real-time request counts, error rates, and latency metrics.
     - **Results Visualisation**: Displays the latest timestamped verifier runs, layer-kill matrix, mutation testing scores, and noisy-neighbour latency charts from `results/`.
     - **Interactive Glossary**: Contextual tooltips and explanation cards for Layer A, Layer B, Layer C, RLS, DEKs, AAD, and Crypto-shredding.

---

## 11. Running the Tests

TenantShield includes 176 automated tests across 16 test files covering unit behavior, cryptographic envelope security, multi-tenant isolation, demo workflows, and verification tooling.

```powershell
# Run the full automated test suite
pytest -v
```

The core unit and API tests use in-memory mocks (`fakeredis` and simulated contexts) and do not require live Redis or database seeding:

```powershell
# Run fast in-memory unit and endpoint tests:
pytest -v tests/test_auth.py tests/test_crypto_envelope.py tests/test_dashboard.py tests/test_runs.py tests/test_config_check.py tests/test_attack_demo.py tests/test_traffic_demo.py tests/test_demo.py tests/test_health.py
```

### Test Suite Breakdown (176 tests)

| Test File | Tests | Purpose |
|-----------|-------|---------|
| `tests/test_health.py` | 2 | Root metadata and health check endpoints |
| `tests/test_auth.py` | 13 | Argon2id password hashing, JWT issue/verify, and auth endpoints |
| `tests/test_crypto_envelope.py` | 5 | AES-256-GCM envelope encryption, key wrapping, AAD binding |
| `tests/test_document_api.py` | 13 | Secure document CRUD operations and multi-tenant boundary checks |
| `tests/test_tenant_isolation.py` | 15 | Direct database RLS enforcement, role privileges, and cross-tenant checks |
| `tests/test_rate_limiter_metrics.py` | 25 | Redis fixed-window rate limiter, 429 Retry-After, and tenant telemetry |
| `tests/test_limiter_strategies.py` | 6 | Concurrency, cost budget, and statement timeout limiting strategies |
| `tests/test_dashboard.py` | 12 | Admin dashboard data endpoints and results parsing |
| `tests/test_runs.py` | 7 | Background verification execution and live status polling |
| `tests/test_demo.py` | 8 | Key lifecycle demonstration (seed, rotate, crypto-shred, read) |
| `tests/test_traffic_demo.py` | 6 | Multi-tenant test traffic simulation and metrics comparison |
| `tests/test_attack_demo.py` | 6 | Single attack execution, parameter validation, and layer detection |
| `tests/test_config_check.py` | 10 | Security configuration audit and database permission checks |
| `tests/test_verifier.py` | 10 | Verification runner logic, OpenAPI discovery, and leak detection |
| `tests/test_mutation.py` | 7 | Mutation testing harness, baseline checks, and injected bug detection |
| `tests/test_noisy_neighbour.py` | 1 | Noisy-neighbour battery smoke test |

To skip slow or long-running integration tests:

```powershell
pytest -v -m "not slow"
```

---

## 12. Running the Experiments and Demonstrations

All experiments require:
- The `.env` file configured (section 7).
- The lab database set up for matrix and mutation experiments (see below).

The **verifier**, **single attack demo**, and **traffic generator** require the main server to be running (`uvicorn app.main:app`).  
The **layer-kill matrix**, **mutation tester**, and **noisy-neighbour runner** manage their own server subprocess.

### Demonstration 1: Single Attack by Hand (`scripts/single_attack.py`)

Run an isolated, interactive attack by hand against a running server:

```powershell
# Attack victim Beta from attacker Acme targeting the secure endpoint
.venv\Scripts\python.exe scripts\single_attack.py --attacker Acme --victim Beta --action read --target-mode secure

# Attack victim Beta from attacker Acme targeting the flawed/vulnerable endpoint
.venv\Scripts\python.exe scripts\single_attack.py --attacker Acme --victim Beta --action read --target-mode vulnerable
```

Supported actions: `read`, `update`, `delete`, `create-into-victim`.

### Demonstration 2: Paced Test Traffic Generator (`scripts/send_test_traffic.py`)

Generate realistic multi-tenant traffic with paced requests, latency simulation, and 429 quota exhaustion:

```powershell
.venv\Scripts\python.exe scripts\send_test_traffic.py --progress-file progress.json --tenant demo
```

### Demonstration 3: Live Dynamic Benchmark (`scripts/live_benchmark.py`)

Run a dynamic noisy-neighbour benchmark with configurable load and limiter strategies:

```powershell
.venv\Scripts\python.exe scripts\live_benchmark.py --progress-file benchmark_progress.json --noisy-tenant acme --victim-tenant beta --load-type expensive --duration 10
```

### Demonstration 4: Dedicated Demo Tenant Seeder (`scripts/seed_demo_tenant.py`)

Provision or reset the isolated "Demo Co" tenant for key lifecycle and attack demonstrations:

```powershell
.venv\Scripts\python.exe scripts\seed_demo_tenant.py
```

### Experiment 1: Automated Verification Attack Suite

Runs full automated verification against `tenantshield_db`. Requires a running server.

```powershell
# Terminal 1 - start the server
uvicorn app.main:app --host 127.0.0.1 --port 8000

# Terminal 2 - run the attack verifier (default: all endpoints)
.venv\Scripts\python.exe scripts\run_verifier.py

# Optional: target specific scope modes
.venv\Scripts\python.exe scripts\run_verifier.py --mode vulnerable_only  # Flawed routes demo alone
.venv\Scripts\python.exe scripts\run_verifier.py --mode secure_only      # Hardened production routes only
```

Results saved to: `results/verification_attack_report_<timestamp>.json`

### Experiment 2: Layer-Kill Matrix

Tests isolation with every combination of Layer A (application check) and Layer B (PostgreSQL RLS) being enabled or disabled. Targets `tenantshield_lab`.

```powershell
# Step 1: Set up the isolated lab database
.\scripts\setup_lab_db.ps1 -Action "setup"

# Step 2: Run the matrix (manages its own server subprocess)
.\scripts\run_matrix.ps1
```

Results saved to: `results/layer_kill_matrix_<timestamp>.json` and `.csv`

### Experiment 3: Isolation Mutation Testing

Injects deliberate isolation bugs one at a time and verifies that the attack suite detects them. Requires `APP_ENV=lab`. Targets `tenantshield_lab`.

```powershell
# Lab database must be set up first (see Experiment 2, Step 1)
.\scripts\run_mutation.ps1
```

Results saved to: `results/mutation_report_<timestamp>.json` and `.csv`

### Experiment 4: Noisy-Neighbour Experiment

Runs paced HTTP workloads from two simulated tenants to measure cross-tenant latency impact. Manages its own server subprocess. Targets `tenantshield_db`.

```powershell
.venv\Scripts\python.exe -m loadtests.runner
```

Results saved to: `results/noisy_neighbour_runs_<timestamp>.json`, `noisy_neighbour_summary_<timestamp>.json`, and `noisy_neighbour_summary_<timestamp>.csv`

---


