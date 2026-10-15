-- ==============================================================================
-- TenantShield - Database Initialization Script (PostgreSQL 16)
-- ==============================================================================
-- Configures multi-tenant schema, enforces Row-Level Security (RLS) on documents,
-- and grants strict least-privilege permissions to the restricted application role.
--
-- RUN AS: PostgreSQL administrative user (e.g. postgres) with CREATEDB / CREATEROLE.
-- Example:
--   psql -U postgres -d tenantshield_db -f scripts/init_db.sql
--
-- NOTE FOR DOCKER: Scripts in /docker-entrypoint-initdb.d/ execute ONLY when
-- the database volume is initialized for the first time.
-- ==============================================================================

-- 1. PostgreSQL 16 UUID Support
-- PostgreSQL 16 provides gen_random_uuid() natively in core.
-- Extension is enabled if not already present for backwards compatibility.
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 2. Configure Restricted Application Role (Least Privilege Principle)
-- This role has NOSUPERUSER, NOCREATEDB, NOCREATEROLE, and NOBYPASSRLS.
-- It cannot bypass RLS policies or alter schemas.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'tenantshield_app') THEN
        CREATE ROLE tenantshield_app WITH
            LOGIN
            PASSWORD 'change_this_secure_password'
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE
            NOBYPASSRLS;
        RAISE NOTICE 'Role tenantshield_app created with restricted privileges.';
    ELSE
        ALTER ROLE tenantshield_app WITH
            LOGIN
            PASSWORD 'change_this_secure_password'
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE
            NOBYPASSRLS;
        RAISE NOTICE 'Role tenantshield_app already exists. Attributes and credentials synchronized.';
    END IF;
END
$$;

-- 3. Core Multi-Tenant Tables (Owned by Administrator)

-- Table: tenants (isolated organization/workspace boundary)
CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Table: users (tenant-scoped membership)
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'member',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_tenant_user_email UNIQUE (tenant_id, email)
);

-- Table: tenant_keys (Versioned wrapped Data Encryption Keys per tenant)
CREATE TABLE IF NOT EXISTS tenant_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    key_version INT NOT NULL,
    wrapped_dek BYTEA,
    wrapping_nonce BYTEA,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    retired_at TIMESTAMPTZ,
    destroyed_at TIMESTAMPTZ,
    CONSTRAINT uq_tenant_key_version UNIQUE (tenant_id, key_version),
    CONSTRAINT chk_tenant_key_status CHECK (status IN ('active', 'retired', 'destroyed'))
);

-- Table: documents (tenant-owned sensitive workspace documents protected by RLS and Envelope Encryption)
CREATE TABLE IF NOT EXISTS documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    owner_id UUID REFERENCES users(id) ON DELETE SET NULL,
    title VARCHAR(255) NOT NULL,
    content TEXT,
    key_version INT DEFAULT 1,
    nonce BYTEA,
    ciphertext BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Table: security_events (audit trail for security events and anomaly detection)
CREATE TABLE IF NOT EXISTS security_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    event_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'INFO',
    details JSONB DEFAULT '{}'::jsonb,
    ip_address VARCHAR(45),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Ensure tables are owned by administrator, NOT the application role
ALTER TABLE tenants OWNER TO postgres;
ALTER TABLE users OWNER TO postgres;
ALTER TABLE tenant_keys OWNER TO postgres;
ALTER TABLE documents OWNER TO postgres;
ALTER TABLE security_events OWNER TO postgres;

-- 4. Multi-Tenant Performance Indexes
CREATE INDEX IF NOT EXISTS idx_users_tenant_id ON users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tenant_keys_tenant_id ON tenant_keys(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tenant_keys_tenant_status ON tenant_keys(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_documents_tenant_id ON documents(tenant_id);
CREATE INDEX IF NOT EXISTS idx_documents_key_version ON documents(tenant_id, key_version);
CREATE INDEX IF NOT EXISTS idx_security_events_tenant_id ON security_events(tenant_id);
CREATE INDEX IF NOT EXISTS idx_security_events_created_at ON security_events(created_at);

-- 5. Row-Level Security (RLS) Configuration
-- Enable and FORCE RLS on documents and tenant_keys
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_policy ON documents;
CREATE POLICY tenant_isolation_policy ON documents
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE tenant_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_keys FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_keys_isolation_policy ON tenant_keys;
CREATE POLICY tenant_keys_isolation_policy ON tenant_keys
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

-- 6. Enforce Least-Privilege Permissions for tenantshield_app
-- Revoke existing table permissions to ensure a clean state
REVOKE ALL ON TABLE tenants, users, tenant_keys, documents, security_events FROM tenantshield_app;

-- Grant schema access
GRANT USAGE ON SCHEMA public TO tenantshield_app;

-- Precise Level 5 Privileges:
-- - documents: SELECT, INSERT, UPDATE, DELETE (full tenant workspace operations)
-- - tenant_keys: SELECT, INSERT, UPDATE (read DEKs, provision new version, shred key)
-- - tenants: SELECT only (read tenant metadata; tenant creation requires admin)
-- - users: SELECT only (read tenant users; user administration requires admin/auth)
-- - security_events: SELECT, INSERT (audit logging; modification/deletion prohibited)
GRANT SELECT ON TABLE tenants TO tenantshield_app;
GRANT SELECT ON TABLE users TO tenantshield_app;
GRANT SELECT, INSERT, UPDATE ON TABLE tenant_keys TO tenantshield_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE documents TO tenantshield_app;
GRANT SELECT, INSERT ON TABLE security_events TO tenantshield_app;

-- Review and restrict default privileges so future tables are not granted write access automatically
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM tenantshield_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO tenantshield_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO tenantshield_app;

-- Verification notice
DO $$
BEGIN
    RAISE NOTICE 'TenantShield initialization completed: RLS enforced, least-privilege permissions applied.';
END
$$;
