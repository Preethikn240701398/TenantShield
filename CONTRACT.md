# TenantShield — Security, Cryptography & Configuration Contract

> **Document Version**: 1.2.0 (Level 6 — Redis Rate Limiting & Per-Tenant Metrics)  
> **Target Environment**: Windows Native PostgreSQL 16, Memurai Developer / Redis 7, Python 3.10+, FastAPI  
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
| `LAB_DATABASE_URL` | `string` | `postgresql+asyncpg://...` | Connection URL | Dedicated lab database connection (`tenantshield_lab`). |
| `POSTGRES_ADMIN_URL` | `string` | Administrative URL | Connection URL | DDL migrations & database provisioning (role: `postgres`). |
| `REDIS_URL` | `string` | `redis://127.0.0.1:6379/0` | Connection URL | Redis-compatible service URL (Memurai Developer on Windows or Redis 7). |
| `RATE_LIMIT_REQUESTS` | `integer` | `100` | $> 0$ | Maximum allowed requests per tenant per time window. |
| `RATE_LIMIT_WINDOW_SECONDS` | `integer` | `60` | $> 0$ | Rate limit time window duration in seconds. |
| `REDIS_FAILURE_POLICY` | `string` | `"fail_open"` | `"fail_open"`, `"fail_closed"` | Behavior when Redis/Memurai is unreachable. |
| `REDIS_CONNECT_TIMEOUT` | `float` | `2.0` | $> 0.0$ | Socket connection timeout in seconds. |
| `REDIS_SOCKET_TIMEOUT` | `float` | `2.0` | $> 0.0$ | Socket read/write timeout in seconds. |
| `METRICS_RETENTION_SECONDS` | `integer` | `86400` | $> 0$ | Retention TTL for time-bucketed Redis metrics (default: 24 hours). |

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

---

## 5. Rate Limiting Architecture & Tenant Isolation

TenantShield implements tenant-aware distributed rate limiting backed by Redis/Memurai:

### Atomic Fixed-Window Limiter Without Lua
- **Redis Commands**: Standard commands only (`MULTI`, `INCR`, `EXPIRE`, `EXEC`) executed inside an atomic pipeline transaction:
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
- **Tenant Context Trust Chain**:
  `tenant_id` is derived exclusively from the verified JWT bearer token via `get_current_user`. Arbitrary client headers (`X-Tenant-ID`), query parameters, or payload fields are ignored during quota accounting.
- **Quota Exhaustion**:
  When a tenant exceeds `RATE_LIMIT_REQUESTS` within `RATE_LIMIT_WINDOW_SECONDS`, the API rejects the request with:
  - HTTP `429 Too Many Requests`
  - Header `Retry-After: <seconds_remaining>`
- **Noisy Neighbor Protection**:
  Tenant A exceeding its quota has zero impact on Tenant B's quota.
- **Exemptions**:
  Liveness probes (`GET /health`), root metadata (`GET /`), OpenAPI/Swagger docs, user login (`POST /auth/login`), and platform administration are not throttled by tenant quotas.

---

## 6. Telemetry & Per-Tenant Observability

### Redis Hash Storage Schema
- **Bucket Interval**: 1-minute buckets (`bucket_ts = int(time.time() // 60) * 60`).
- **Key Schema**:
  ```
  tenantshield:metrics:{tenant_id}:{bucket_timestamp}
  ```
- **Stored Fields**:
  - `requests`: Total requests count (`HINCRBY`)
  - `errors`: Count of HTTP 4xx and 5xx responses (`HINCRBY` when `status_code >= 400`)
  - `total_latency_ms`: Cumulative execution latency in milliseconds (`HINCRBYFLOAT`)
- **Active Tenants Index**:
  Maintains a Redis Set `tenantshield:metrics:tenants` to allow instant tenant discovery for reporting without requiring unbounded `KEYS *` scans.
- **TTL Retention**:
  Every metrics key is automatically purged after `METRICS_RETENTION_SECONDS` (default: 86400 seconds / 24 hours).

### Platform Admin Metrics Endpoint
- **Route**: `GET /admin/metrics`
- **Authorization**: Strictly requires `current_user.role == "platform_admin"`.
  - Unauthenticated requests receive HTTP `401 Unauthorized`.
  - Non-admin tenant users receive HTTP `403 Forbidden`.
- **Query Parameters**:
  - `window_minutes` (integer, 1 to 1440, default: 60)
  - `limit` (integer, 1 to 1000, default: 100)
  - `tenant_id` (optional UUID filter)
- **Response Format**:
  ```json
  {
    "reporting_window_minutes": 60,
    "start_time": "2026-10-16T14:00:00Z",
    "end_time": "2026-10-16T15:00:00Z",
    "tenant_count": 1,
    "tenants": [
      {
        "tenant_id": "0ec723db-84b7-471e-b913-0ee02929d0eb",
        "request_count": 42,
        "error_count": 2,
        "avg_latency_ms": 14.85
      }
    ]
  }
  ```

---

## 7. Redis Failure Policies

| Failure Policy | Behavior when Redis is Unreachable | Use Case |
| :--- | :--- | :--- |
| `fail_open` (default) | Logs an operational warning and permits the request to continue. Tenant rate limits and metrics are temporarily unrecorded. | Development, staging, and high-availability operations where service continuity outweighs strict rate limiting. |
| `fail_closed` | Immediately returns HTTP `503 Service Unavailable` with message `"Service unavailable: Rate limiting service unreachable."` | High-security environments where unthrottled requests cannot be tolerated. |

- **Metrics Collection Safety**:
  Metric collection failures inside middleware or services are safely logged and **never mask or alter** the original HTTP response or application exception.
- **Metrics Query Outage**:
  If Redis is down when calling `GET /admin/metrics`, the endpoint returns HTTP `503 Service Unavailable` rather than fabricating misleading zero metrics.

---

## 8. Known Limitations & Boundaries

1. **Fixed-Window Burst Limitation**:
   Fixed-window rate limiting allows a theoretical maximum of $2 \times \text{limit}$ requests across the boundary between two adjacent windows. A future sliding-window log or token bucket limiter can be swapped in via `RateLimiterInterface` if smoother burst shaping is required.
2. **Metrics Granularity**:
   Metrics are aggregated in 1-minute buckets. Sub-minute latency percentiles (e.g. p95, p99) require a dedicated time-series engine or OpenTelemetry collector.
3. **Redis Volatility**:
   Redis is treated as an ephemeral cache and operational telemetry store. It is not an append-only legal audit log; permanent audit trails continue to reside in PostgreSQL `security_events`.
