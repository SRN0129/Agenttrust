-- Migration: 001_initial_schema.sql
-- Description: Baseline schema definition for AgentTrust Gateway
-- Applied At: 2026-10-26

CREATE TABLE IF NOT EXISTS agents (
    id                   VARCHAR(64) PRIMARY KEY,
    tenant_id            VARCHAR(64) DEFAULT 'default' NOT NULL,
    name                 VARCHAR(255) NOT NULL,
    description          TEXT DEFAULT '',
    operator_email       VARCHAR(255) NOT NULL,
    framework            VARCHAR(64) DEFAULT 'Custom',
    status               VARCHAR(32) NOT NULL CHECK (status IN ('ACTIVE', 'SUSPENDED', 'REVOKED')),
    api_key_hash         VARCHAR(128) NOT NULL,
    api_key_prefix       VARCHAR(32) NOT NULL,
    allowed_capabilities TEXT NOT NULL,
    rate_limit_rpm       INTEGER DEFAULT 60 NOT NULL,
    spend_limit_usd      DECIMAL(10, 4) DEFAULT 50.00 NOT NULL,
    current_spend_usd    DECIMAL(10, 4) DEFAULT 0.00 NOT NULL,
    created_at           BIGINT NOT NULL,
    updated_at           BIGINT NOT NULL,
    revoked_at           BIGINT,
    revocation_reason    TEXT
);

CREATE INDEX IF NOT EXISTS idx_agents_tenant ON agents(tenant_id);
CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);

CREATE TABLE IF NOT EXISTS agent_delegations (
    parent_agent_id VARCHAR(64) NOT NULL,
    child_agent_id  VARCHAR(64) PRIMARY KEY,
    delegated_at    BIGINT NOT NULL,
    FOREIGN KEY (parent_agent_id) REFERENCES agents(id) ON DELETE CASCADE,
    FOREIGN KEY (child_agent_id) REFERENCES agents(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS policies (
    id               VARCHAR(64) PRIMARY KEY,
    name             VARCHAR(255) NOT NULL,
    description      TEXT DEFAULT '',
    agent_id         VARCHAR(64),
    action_pattern   VARCHAR(255) NOT NULL,
    resource_pattern VARCHAR(255) NOT NULL,
    effect           VARCHAR(32) NOT NULL CHECK (effect IN ('ALLOW', 'DENY', 'REQUIRE_APPROVAL')),
    max_cost_usd     DECIMAL(10, 4) DEFAULT 0.00 NOT NULL,
    priority         INTEGER DEFAULT 10 NOT NULL,
    created_at       BIGINT NOT NULL,
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_policies_agent ON policies(agent_id);
CREATE INDEX IF NOT EXISTS idx_policies_priority ON policies(priority DESC);

CREATE TABLE IF NOT EXISTS approvals (
    id                 VARCHAR(64) PRIMARY KEY,
    agent_id           VARCHAR(64) NOT NULL,
    action             VARCHAR(255) NOT NULL,
    resource           VARCHAR(255) NOT NULL,
    parameters         TEXT NOT NULL,
    estimated_cost_usd DECIMAL(10, 4) DEFAULT 0.00 NOT NULL,
    status             VARCHAR(32) NOT NULL CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'EXPIRED', 'CONSUMED')),
    execution_nonce    VARCHAR(128) UNIQUE,
    requested_at       BIGINT NOT NULL,
    expires_at         BIGINT NOT NULL,
    decided_at         BIGINT,
    decided_by         VARCHAR(255),
    decision_reason    TEXT,
    consumed_at        BIGINT,
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_approvals_agent_status ON approvals(agent_id, status);

CREATE TABLE IF NOT EXISTS rate_limit_buckets (
    agent_id      VARCHAR(64) NOT NULL,
    window_minute BIGINT NOT NULL,
    request_count INTEGER DEFAULT 1 NOT NULL,
    PRIMARY KEY (agent_id, window_minute),
    FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_ledger (
    "index"      INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id     VARCHAR(64) UNIQUE NOT NULL,
    timestamp    BIGINT NOT NULL,
    agent_id     VARCHAR(64) NOT NULL,
    event_type   VARCHAR(64) NOT NULL,
    action       VARCHAR(255) NOT NULL,
    resource     VARCHAR(255) NOT NULL,
    decision     VARCHAR(32) NOT NULL,
    payload_json TEXT NOT NULL,
    payload_hash VARCHAR(64) NOT NULL,
    prev_hash    VARCHAR(64) NOT NULL,
    entry_hash   VARCHAR(64) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_ledger(agent_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_ledger(timestamp);

CREATE TABLE IF NOT EXISTS checkpoints (
    id              VARCHAR(64) PRIMARY KEY,
    sequence_number INTEGER NOT NULL,
    total_records   INTEGER NOT NULL,
    tip_hash        VARCHAR(64) NOT NULL,
    timestamp       BIGINT NOT NULL,
    signature_hex   TEXT NOT NULL,
    public_key_pem  TEXT NOT NULL
);
