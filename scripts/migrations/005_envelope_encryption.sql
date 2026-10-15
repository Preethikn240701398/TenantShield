-- ==============================================================================
-- TenantShield - Migration 005: Envelope Encryption & Crypto-Shredding
-- ==============================================================================
-- Provisions the tenant_keys table with Row-Level Security (RLS) and adds
-- encrypted payload columns (key_version, nonce, ciphertext) to documents.
--
-- RUN AS: PostgreSQL administrative user (postgres)
-- ==============================================================================

-- 1. Table: tenant_keys (Versioned wrapped Data Encryption Keys per tenant)
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

-- Ensure table ownership belongs to postgres
ALTER TABLE tenant_keys OWNER TO postgres;

-- 2. Indexes for performance and lookup
CREATE INDEX IF NOT EXISTS idx_tenant_keys_tenant_id ON tenant_keys(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tenant_keys_tenant_status ON tenant_keys(tenant_id, status);

-- 3. Row-Level Security (RLS) on tenant_keys
ALTER TABLE tenant_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_keys FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_keys_isolation_policy ON tenant_keys;

CREATE POLICY tenant_keys_isolation_policy ON tenant_keys
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

-- 4. Alter documents table for envelope encryption
ALTER TABLE documents ADD COLUMN IF NOT EXISTS key_version INT DEFAULT 1;
ALTER TABLE documents ADD COLUMN IF NOT EXISTS nonce BYTEA;
ALTER TABLE documents ADD COLUMN IF NOT EXISTS ciphertext BYTEA;
ALTER TABLE documents ALTER COLUMN content DROP NOT NULL;

-- Index on document key version
CREATE INDEX IF NOT EXISTS idx_documents_key_version ON documents(tenant_id, key_version);

-- 5. Least-Privilege Permissions for tenantshield_app
REVOKE ALL ON TABLE tenant_keys FROM tenantshield_app;
GRANT SELECT, INSERT, UPDATE ON TABLE tenant_keys TO tenantshield_app;
