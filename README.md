# TenantShield

> **Secure Multi-Tenant SaaS Workspace API**  
> Built with **FastAPI**, **PostgreSQL 16 (native Windows)**, **Row-Level Security (RLS)**, **AES-256-GCM Envelope Encryption & Crypto-Shredding**, **Redis/Memurai Tenant-Aware Rate Limiting**, and a **lightweight web dashboard**.  
> **Mandatory principle: Do not invent results or claim the system is secure.**

---

## 1. What TenantShield Is

TenantShield is a multi-tenant document storage API that lets multiple customers (tenants) share the same server and database without being able to see each other's data. Every document belongs to exactly one tenant. When a user logs in, the server issues a JWT token that records which tenant they belong to. Every subsequent request uses that token — clients never send a tenant ID directly; the server derives it from the verified token.

The project is primarily an **engineering experiment** used to study, measure, and attack the isolation properties of a multi-tenant system. It comes with automated attack suites, mutation testing, a layer-kill matrix, and noisy-neighbour load experiments — all of which produce machine-readable evidence in `results/`.

---

## 2. Architecture Overview

The system implements isolation at multiple independent layers, so that a bug in any single layer does not immediately cause a data leak.

| Layer | Mechanism | Key file |
|-------|-----------|----------|
| **Token & Ownership (A)** | JWT verified on every request; `check_document_ownership` rejects requests where the token's `tenant_id` does not match the document's `tenant_id` | `app/services/document_ownership.py` |
| **Query Filter (C)** | Every SQL query carries `WHERE tenant_id = :tenant_id` parameterised to the token's `tenant_id` | `app/api/documents.py` |
| **Row-Level Security (B)** | PostgreSQL 16 RLS policy `tenant_isolation_policy` on the `documents` table filters rows based on `app.current_tenant_id`, which is set `LOCAL` (transaction-scoped) by the restricted database role `tenantshield_app` (NOSUPERUSER, NOBYPASSRLS) | `scripts/init_db.sql` |
| **Envelope Encryption** | Document content is encrypted with per-tenant AES-256-GCM Data Encryption Keys (DEKs). The DEK is wrapped by a master key (`TENANTSHIELD_MASTER_KEY`). AAD binds `tenant_id` and `document_id` so cross-tenant ciphertext replay fails authentication | `app/services/crypto.py` |
| **Rate Limiter** | Fixed-window Redis rate limiter keyed to verified JWT tenant context; returns HTTP 429 with `Retry-After` header; tenant A quota is independent of tenant B quota | `app/services/rate_limiter.py` |
| **Verifier** | Automated HTTP attack suite that runs cross-tenant read, write, update, delete, and inject attacks against a live server | `verifier/` |
| **Dashboard** | Platform-admin-only web UI that surfaces the latest verifier results, layer-kill matrix, mutation test scores, and noisy-neighbour data from `results/` | `app/api/dashboard.py`, `ui/` |

The tenant lifecycle for a document request:

```
Client --[JWT]--> FastAPI
    --> auth.get_current_user()          # verifies token, extracts tenant_id
    --> deps.check_tenant_rate_limit()   # Redis quota check
    --> check_document_ownership()       # Layer A
    --> SQL + WHERE tenant_id = :tid     # Layer C
    --> DB under tenant_session context  # SET LOCAL app.current_tenant_id
    --> RLS filters in PostgreSQL        # Layer B
    --> CryptoService.decrypt()          # Envelope decryption + AAD check
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
+-- docker-compose.yml            # Optional (NOT tested – see comment in file)
¦
+-- app/
¦   +-- main.py                   # FastAPI app entrypoint
¦   +-- core/
¦   ¦   +-- config.py             # Settings and startup validation
¦   ¦   +-- database.py           # Async DB engines, tenant_session context
¦   +-- api/
¦   ¦   +-- auth.py               # Login / token endpoints
¦   ¦   +-- documents.py          # Multi-tenant document CRUD
¦   ¦   +-- admin.py              # Platform admin: metrics, DEK rotation, shred
¦   ¦   +-- dashboard.py          # Admin dashboard data endpoints
¦   ¦   +-- routes.py             # / and /health
¦   +-- models/                   # SQLAlchemy ORM models
¦   +-- schemas/                  # Pydantic schemas
¦   +-- services/
¦       +-- auth.py               # Argon2id hashing, PyJWT
¦       +-- crypto.py             # AES-256-GCM envelope encryption
¦       +-- rate_limiter.py       # Redis fixed-window rate limiter
¦       +-- metrics.py            # Per-tenant Redis telemetry
¦       +-- document_ownership.py # Layer A ownership check
¦
+-- verifier/                     # Cross-tenant attack verification suite
+-- loadtests/                    # Noisy-neighbour experiment orchestrator
+-- scripts/
¦   +-- init_db.sql               # Schema, RLS, role setup
¦   +-- init_db.py                # Schema initialiser runner
¦   +-- seed_tenants.py           # Seeds Acme, Beta, Admin users
¦   +-- migrate_level5.py         # Encryption migration + DEK provisioning
¦   +-- setup_lab_db.ps1          # Set up isolated tenantshield_lab DB
¦   +-- run_matrix.ps1            # Layer-Kill Matrix runner
¦   +-- run_mutation.ps1          # Mutation testing runner
¦   +-- run_verifier.py           # Verifier runner
¦
+-- ui/
¦   +-- index.html                # Single-page web UI
¦   +-- app.js                    # Frontend script
¦
+-- tests/                        # Automated test suite (87 tests)
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

Run as the PostgreSQL administrative user (`postgres`). Run these commands once.

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
```

**Seeded credentials (development only):**

| Role | Email | Password |
|------|-------|----------|
| Tenant A (Acme) | `acme_user@acme.test` | `AcmeSecretPassword123!` |
| Tenant B (Beta) | `beta_user@beta.test` | `BetaSecretPassword123!` |
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

# JWT secret — generate with: python -c "import secrets; print(secrets.token_hex(32))"
SECRET_KEY=your_64_character_hex_secret_key

# Master Key for envelope encryption (64 hex characters = 256-bit AES key)
# Generate with: python -c "import secrets; print(secrets.token_hex(32))"
TENANTSHIELD_MASTER_KEY=your_64_character_hex_master_key
```

> **Note:** `SECRET_KEY` and `POSTGRES_APP_PASSWORD` are intentionally blank in `.env` — they must be filled in with values you generate. The application will refuse to start if these are left at placeholder defaults.

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
| `http://127.0.0.1:8000/ui` | Web dashboard (login page) |

---

## 10. Opening the Dashboard

1. Start the server (see section 9).
2. Navigate to `http://127.0.0.1:8000/ui` in a browser.
3. Log in:
   - As a **tenant user** (`acme_user@acme.test` or `beta_user@beta.test`) to reach the tenant document workspace (list, create, view, edit, delete documents).
   - As **platform admin** (`admin@tenantshield.test`) to reach the admin dashboard, which shows the latest verifier results, layer-kill matrix, mutation scores, noisy-neighbour data, and tenant encryption key status — all read from the newest files in `results/`.

---

## 11. Running the Tests

```powershell
# Run the full automated test suite from the project root
pytest -v
```

The test suite uses `fakeredis` for in-memory Redis — no live Redis service or database seeding is required.

Test breakdown (87 tests):

| File | Tests |
|------|-------|
| `tests/test_health.py` | 2 |
| `tests/test_auth.py` | 16 |
| `tests/test_tenant_isolation.py` | 15 |
| `tests/test_document_api.py` | 14 |
| `tests/test_crypto_envelope.py` | 15 |
| `tests/test_rate_limiter_metrics.py` | 25 |

To skip slow-marked tests:

```powershell
pytest -v -m "not slow"
```

---

## 12. Running the Experiments

All experiments require:
- The `.env` file configured (section 7).
- The lab database set up (for matrix, mutation, and noisy-neighbour experiments — see below).

The **verifier** requires the main server to already be running (it connects to it via HTTP).  
The **layer-kill matrix**, **mutation tester**, and **noisy-neighbour runner** manage their own server subprocess.

### Experiment 1: Verification Attack Suite

Targets `tenantshield_db`. Requires a running server.

```powershell
# Terminal 1 — start the server
uvicorn app.main:app --host 127.0.0.1 --port 8000

# Terminal 2 — run the attack verifier
.venv\Scripts\python.exe scripts\run_verifier.py
```

Results saved to: `results/verification_attack_report_<timestamp>.json`

### Experiment 2: Layer-Kill Matrix

Tests isolation with every combination of Layer A and Layer B being on or off. Targets `tenantshield_lab`.

```powershell
# Step 1: Set up the isolated lab database (one-time or after a reset)
.\scripts\setup_lab_db.ps1 -Action "setup"

# Step 2: Run the matrix (manages its own server subprocess)
.\scripts\run_matrix.ps1
```

Results saved to: `results/layer_kill_matrix_<timestamp>.json` and `.csv`

### Experiment 3: Isolation Mutation Testing

Injects deliberate bugs one at a time and verifies the attack suite detects them. Requires `APP_ENV=lab` (the runner sets this). Targets `tenantshield_lab`.

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

## 13. Limitations

The following limitations apply to all results in `results/`. They do not prove or disprove general security.

1. **Two tenants only.** All isolation tests involve exactly two tenants (Acme and Beta). Multi-tenant behaviour with three or more tenants has not been tested.

2. **Attack direction.** The attack suite runs only in one direction: Tenant A (Acme) attempts to access Tenant B (Beta) resources. Attacks in the reverse direction are not separately reported.

3. **Small attack set.** The verifier runs 7 attacks per run (create injection, read, update, delete, admin action × 2, admin injection). It does not cover every possible attack vector.

4. **Small mutation set.** Mutation testing covers 5 injected bugs. Other realistic bugs are not tested.

5. **Single laptop, one worker.** All experiments ran on one laptop (AMD Ryzen 7 7840HS, 15.29 GB RAM, Windows 11) with one uvicorn worker. Results are not representative of multi-server or multi-worker deployments.

6. **Noisy-neighbour experiment scope.** The expensive-load case used a burst volume that stayed under the rate-limit quota. The claim about request-count limiting vs expensive queries could not be confirmed or refuted at the tested burst size (see `results/noisy_neighbour_report.md`, Claim Evaluation section).

7. **Some runs tested through in-process HTTP.** The mutation tester and layer-kill matrix issue HTTP calls via httpx to a subprocess server. Network stack effects are not captured.

8. **Results describe these specific runs only.** The numbers in `results/` are the output of the runs described in `results/noisy_neighbour_plan.md` and the timestamped JSON files. They do not constitute a proof of security or insecurity.

9. **No Docker testing.** The optional `docker-compose.yml` is provided for reference only and has not been tested. The documented setup targets native Windows PostgreSQL 16 and Memurai Developer.
