# TenantShield

> **Secure Multi-Tenant SaaS Workspace API**  
> Built with **FastAPI**, **PostgreSQL 16**, **Row-Level Security (RLS)**, **AES-256-GCM Envelope Encryption & Crypto-Shredding**, and **Redis/Memurai Tenant-Aware Rate Limiting & Telemetry**.  
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
7. **Layer D: Tenant-Aware Rate Limiting (Level 6)**: Redis/Memurai-backed fixed-window rate limiter returning HTTP `429 Too Many Requests` with a valid `Retry-After` header upon quota exhaustion. Quotas are keyed strictly to verified JWT tenant context, isolating tenants completely.
8. **Layer E: Per-Tenant Observability & Telemetry (Level 6)**: Real-time request counts, error counts (HTTP 4xx/5xx), and latency tracking (in milliseconds) aggregated in time-bucketed Redis hashes with automated TTL retention and accessible via `GET /admin/metrics` for platform administrators.

---

## 2. Directory Structure

```
TenantShield/
├── CONTRACT.md                  # Formal security and configuration contract (v1.2.0)
├── README.md                    # Project documentation and setup guide
├── requirements.txt             # Dependencies (FastAPI, cryptography, redis, fakeredis, SQLAlchemy, pytest)
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
│   ├── main.py                  # FastAPI application entrypoint, TenantMetricsMiddleware, lifespan
│   ├── core/
│   │   ├── config.py            # Settings with startup validation for Master Key, Redis, and switches
│   │   └── database.py          # Database engines, sessionmakers, and tenant_session context
│   ├── api/
│   │   ├── deps.py              # Auth, rate limiting (check_tenant_rate_limit), and tenant DB deps
│   │   ├── auth.py              # Login and token endpoints
│   │   ├── documents.py         # Multi-tenant document CRUD with envelope encryption
│   │   ├── admin.py             # Platform admin endpoints (DEK rotation, shredding, GET /admin/metrics)
│   │   └── routes.py            # Base endpoints (/ and /health)
│   ├── models/                  # SQLAlchemy ORM models
│   ├── schemas/                 # Pydantic schemas (auth, documents)
│   └── services/
│       ├── auth.py              # Argon2id password hashing and PyJWT token handling
│       ├── crypto.py            # Envelope encryption, DEK wrapping, AES-256-GCM, AAD binding
│       ├── rate_limiter.py      # Atomic fixed-window Redis rate limiter without Lua scripts
│       ├── metrics.py           # Per-tenant Redis telemetry metrics (requests, errors, latency)
│       └── document_ownership.py# Layer A application ownership checks
│
├── results/                     # Verifiable timestamped experiment evidence JSON logs
└── tests/
    ├── conftest.py              # TestClient and session-wide in-memory Redis fixtures
    ├── test_health.py           # Health endpoint tests (2 tests)
    ├── test_auth.py             # JWT authentication and trusted context tests (16 tests)
    ├── test_tenant_isolation.py # PostgreSQL RLS and restricted role tests (15 tests)
    ├── test_document_api.py     # Document CRUD and dual-layer switch tests (14 tests)
    ├── test_crypto_envelope.py  # Envelope encryption, rotation, shredding, AAD (15 tests)
    └── test_rate_limiter_metrics.py # Rate limiting, isolation, metrics, failure modes (25 tests)
```

---

## 3. Rate Limiting & Telemetry Specification (Level 6)

### Atomic Fixed-Window Limiter Without Lua
- **Redis Commands**: Standard commands only (`MULTI`, `INCR`, `EXPIRE`, `EXEC`) executed in an atomic pipeline transaction:
  ```python
  pipe = client.pipeline(transaction=True)
  pipe.incr(key)
  pipe.expire(key, window_seconds + 5)
  results = await pipe.execute()
  ```
- **Zero Race Condition on Expiration**: Because `INCR` and `EXPIRE` execute atomically within `MULTI/EXEC`, every created key is guaranteed an expiration TTL even under burst concurrency.
- **Key Schema**:
  ```
  tenantshield:rate_limit:{tenant_id}:{window_bucket_timestamp}
  ```
- **Strict Tenant Context**: `tenant_id` is derived exclusively from the verified JWT bearer token via `get_current_user`. Arbitrary client headers (`X-Tenant-ID`), query parameters, or payload fields are ignored during quota accounting.
- **Quota Exhaustion**: Returns HTTP `429 Too Many Requests` with header `Retry-After: <seconds_remaining>`.
- **Tenant Isolation**: Tenant A exhausting its quota has zero effect on Tenant B's allowance.
- **Exemptions**: Liveness probes (`GET /health`), root metadata (`GET /`), OpenAPI/Swagger docs, user login (`POST /auth/login`), and platform administration are not throttled by tenant quotas.

### Metrics & Telemetry
- **Hash Bucket Storage**: 1-minute time buckets with automated TTL retention (`METRICS_RETENTION_SECONDS` = 86400 / 24 hours):
  ```
  tenantshield:metrics:{tenant_id}:{bucket_timestamp}
  ```
- **Fields Recorded**:
  - `requests`: Total requests count (`HINCRBY`)
  - `errors`: Count of HTTP 4xx and 5xx responses (`HINCRBY` when `status_code >= 400`)
  - `total_latency_ms`: Cumulative execution latency in milliseconds (`HINCRBYFLOAT`)
- **Index**: Maintains Redis Set `tenantshield:metrics:tenants` with TTL for fast reporting without unbounded `KEYS *` scans.
- **Platform Admin Endpoint**: `GET /admin/metrics` strictly requires `current_user.role == "platform_admin"`. Unauthenticated callers receive 401; non-admin users receive 403.
- **Failure Safety**: Metrics recording failures never mask application exceptions.

### Redis Failure Policies
- `fail_open` (default): Logs an operational warning and permits traffic.
- `fail_closed`: Immediately rejects traffic requiring the limiter with HTTP `503 Service Unavailable`.
- If Redis is down during `GET /admin/metrics`, the endpoint returns HTTP 503 rather than fabricating zero metrics.

---

## 4. Setup & Running on Windows (PowerShell)

### Step 1: Virtual Environment & Dependencies
```powershell
# Activate Python 3.10 virtual environment
.\.venv\Scripts\Activate.ps1

# Install requirements
pip install -r requirements.txt
```

### Step 2: Redis / Memurai Setup on Windows
TenantShield is compatible with native Redis 7 and **Memurai Developer** for Windows.
1. Download and install Memurai Developer from [https://www.memurai.com/](https://www.memurai.com/).
2. Verify the Memurai Windows Service is running:
   ```powershell
   Get-Service memurai
   ```
3. Test connectivity using `memurai-cli`:
   ```powershell
   memurai-cli ping
   # Expected response:
   # PONG
   ```
4. *Note on Development & Automated Tests*: If Memurai is not installed, TenantShield's test suite automatically provisions an in-memory Redis service (`fakeredis`) for seamless zero-dependency automated testing.

### Step 3: Configure Environment
Copy `.env.example` to `.env` if not already present:
```ini
REDIS_URL=redis://127.0.0.1:6379/0
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW_SECONDS=60
REDIS_FAILURE_POLICY=fail_open
REDIS_CONNECT_TIMEOUT=2.0
REDIS_SOCKET_TIMEOUT=2.0
METRICS_RETENTION_SECONDS=86400
TENANTSHIELD_MASTER_KEY=your_64_character_hex_master_key
POSTGRES_ADMIN_URL=postgresql+psycopg://postgres:YOUR_PASSWORD@localhost:5432/tenantshield_db
```

### Step 4: Run the Development Server
```powershell
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```
- Interactive Swagger UI: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- Health Endpoint: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)

---

## 5. Verification: Testing Rate Limiting & Admin Metrics

### Verifying Rate Limiting & Tenant Isolation
1. Obtain an access token for Acme User (`acme_user@acme.test`) via `POST /auth/login`.
2. Send requests to `GET /documents` using Acme's token until `RATE_LIMIT_REQUESTS` is exceeded.
3. Observe HTTP `429 Too Many Requests` with response header:
   ```http
   Retry-After: 45
   ```
4. Send a request to `GET /documents` using Beta User's token (`beta_user@beta.test`).
5. Observe HTTP `200 OK` (Beta is completely unaffected by Acme's exhausted quota).

### Verifying Platform Admin Metrics
1. Log in as Platform Administrator (`admin@tenantshield.test`) via `POST /auth/login`.
2. In Swagger UI or curl, invoke `GET /admin/metrics?window_minutes=60`:
   ```json
   {
     "reporting_window_minutes": 60,
     "start_time": "2026-10-16T14:30:00Z",
     "end_time": "2026-10-16T15:30:00Z",
     "tenant_count": 2,
     "tenants": [
       {
         "tenant_id": "0ec723db-84b7-471e-b913-0ee02929d0eb",
         "request_count": 25,
         "error_count": 1,
         "avg_latency_ms": 11.42
       }
     ]
   }
   ```
3. Attempt to invoke `GET /admin/metrics` using Acme or Beta token:
   Observe HTTP `403 Forbidden` (`"detail": "Forbidden: Platform administrator privileges required."`).

---

## 6. Automated Verification & Test Results

Run the entire test suite from the project root:
```powershell
pytest -v
```

Current test status: **87 passed in 26.29s (100% passing)**.
- `tests/test_health.py`: 2 passed
- `tests/test_auth.py`: 16 passed
- `tests/test_tenant_isolation.py`: 15 passed
- `tests/test_document_api.py`: 14 passed
- `tests/test_crypto_envelope.py`: 15 passed
- `tests/test_rate_limiter_metrics.py`: 25 passed

All Level 6 test outcomes and non-sensitive evidence records are automatically persisted to `results/level6_experiment_results_<timestamp>.json`.
