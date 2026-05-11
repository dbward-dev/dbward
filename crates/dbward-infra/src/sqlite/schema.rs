use rusqlite::Connection;

const SCHEMA_VERSION: u32 = 1;

/// Initialize the database: set pragmas and create schema.
pub fn initialize(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA busy_timeout = 5000;
         PRAGMA synchronous = NORMAL;
         PRAGMA wal_autocheckpoint = 0;
         PRAGMA foreign_keys = ON;",
    )?;

    let current: u32 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if current == 0 {
        conn.execute_batch(SCHEMA_SQL)?;
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    }
    Ok(())
}

const SCHEMA_SQL: &str = "
-- Registered database×environment pairs
CREATE TABLE IF NOT EXISTS databases (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    environment TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(name, environment)
);

-- Users (auto-created on first auth)
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    display_name TEXT,
    email TEXT,
    groups_json TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'active',
    last_seen_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- API tokens
CREATE TABLE IF NOT EXISTS tokens (
    id TEXT PRIMARY KEY,
    subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    token_prefix TEXT NOT NULL,
    roles_json TEXT NOT NULL DEFAULT '[]',
    groups_json TEXT NOT NULL DEFAULT '[]',
    name TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    expires_at TEXT,
    created_at TEXT NOT NULL,
    revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_tokens_prefix ON tokens(token_prefix);

-- Requests
CREATE TABLE IF NOT EXISTS requests (
    id TEXT PRIMARY KEY,
    requester TEXT NOT NULL,
    operation TEXT NOT NULL,
    database_id TEXT NOT NULL REFERENCES databases(id),
    detail TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    emergency INTEGER NOT NULL DEFAULT 0,
    reason TEXT,
    idempotency_key TEXT UNIQUE,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    share_with_json TEXT NOT NULL DEFAULT '[]',
    no_store INTEGER NOT NULL DEFAULT 0,
    workflow_snapshot_json TEXT,
    cancelled_by TEXT,
    cancel_reason TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    resolved_at TEXT,
    expires_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_requests_status ON requests(status);
CREATE INDEX IF NOT EXISTS idx_requests_requester ON requests(requester);
CREATE INDEX IF NOT EXISTS idx_requests_database_id ON requests(database_id);

-- Approvals
CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL REFERENCES requests(id),
    action TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    matched_selector TEXT NOT NULL DEFAULT '',
    step_index INTEGER NOT NULL,
    comment TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_approvals_request_id ON approvals(request_id);

-- Executions (1:N per request, tracks each attempt)
CREATE TABLE IF NOT EXISTS executions (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL REFERENCES requests(id),
    agent_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'claimed',
    token TEXT NOT NULL,
    lease_expires_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    error_message TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_executions_request_id ON executions(request_id);
CREATE INDEX IF NOT EXISTS idx_executions_status ON executions(status);

-- Execution results (1:1 per execution)
CREATE TABLE IF NOT EXISTS results (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL REFERENCES requests(id),
    execution_id TEXT NOT NULL REFERENCES executions(id),
    storage_backend TEXT NOT NULL,
    storage_key TEXT NOT NULL,
    content_length INTEGER NOT NULL DEFAULT 0,
    checksum_sha256 TEXT NOT NULL DEFAULT '',
    retention_days INTEGER NOT NULL DEFAULT 30,
    status TEXT NOT NULL DEFAULT 'stored',
    truncated INTEGER NOT NULL DEFAULT 0,
    truncation_reason TEXT,
    stored_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_results_request_id ON results(request_id);

-- Result access control
CREATE TABLE IF NOT EXISTS result_access (
    id TEXT PRIMARY KEY,
    result_id TEXT NOT NULL REFERENCES results(id),
    selector_type TEXT NOT NULL,
    selector_value TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_result_access_result_id ON result_access(result_id);

-- Agents
CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    token_id TEXT NOT NULL,
    databases_json TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'active',
    max_concurrent INTEGER NOT NULL DEFAULT 1,
    in_flight INTEGER NOT NULL DEFAULT 0,
    last_seen_at TEXT,
    created_at TEXT NOT NULL
);

-- Workflows
CREATE TABLE IF NOT EXISTS workflows (
    id TEXT PRIMARY KEY,
    database_name TEXT NOT NULL,
    environment TEXT NOT NULL,
    operations_json TEXT NOT NULL DEFAULT '[]',
    steps_json TEXT NOT NULL DEFAULT '[]',
    skip_approval_for_json TEXT NOT NULL DEFAULT '[]',
    require_reason INTEGER NOT NULL DEFAULT 0,
    allow_self_approve INTEGER NOT NULL DEFAULT 0,
    allow_same_approver_across_steps INTEGER NOT NULL DEFAULT 0,
    pending_ttl_secs INTEGER,
    approval_ttl_secs INTEGER,
    UNIQUE(database_name, environment, operations_json)
);

-- Execution policies
CREATE TABLE IF NOT EXISTS execution_policies (
    id TEXT PRIMARY KEY,
    database_name TEXT NOT NULL,
    environment TEXT NOT NULL,
    max_executions INTEGER NOT NULL DEFAULT 1,
    execution_window_secs INTEGER NOT NULL DEFAULT 86400,
    retry_on_failure INTEGER NOT NULL DEFAULT 0,
    statement_timeout_secs INTEGER NOT NULL DEFAULT 30,
    max_statement_timeout_secs INTEGER NOT NULL DEFAULT 600,
    UNIQUE(database_name, environment)
);

-- Role definitions (custom roles stored in DB for API management)
CREATE TABLE IF NOT EXISTS roles (
    name TEXT PRIMARY KEY,
    permissions_json TEXT NOT NULL DEFAULT '[]',
    databases_json TEXT NOT NULL DEFAULT '[\"*\"]',
    environments_json TEXT NOT NULL DEFAULT '[\"*\"]',
    built_in INTEGER NOT NULL DEFAULT 0
);

-- Result policies
CREATE TABLE IF NOT EXISTS result_policies (
    id TEXT PRIMARY KEY,
    database_name TEXT NOT NULL,
    environment TEXT NOT NULL,
    delivery_mode TEXT NOT NULL DEFAULT 'direct',
    access_json TEXT NOT NULL DEFAULT '[]',
    UNIQUE(database_name, environment)
);

-- Notification policies
CREATE TABLE IF NOT EXISTS notification_policies (
    id TEXT PRIMARY KEY,
    database_name TEXT NOT NULL,
    environment TEXT NOT NULL,
    webhooks_json TEXT NOT NULL DEFAULT '[]',
    events_json TEXT NOT NULL DEFAULT '[]',
    UNIQUE(database_name, environment)
);

-- Webhooks
CREATE TABLE IF NOT EXISTS webhooks (
    id TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    events_json TEXT NOT NULL DEFAULT '[]',
    format TEXT NOT NULL DEFAULT 'generic',
    secret TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Audit events (hash-chained)
CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    event_category TEXT NOT NULL,
    event_version INTEGER NOT NULL DEFAULT 1,
    outcome TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_type TEXT NOT NULL,
    resource_type TEXT,
    resource_id TEXT,
    peer_ip TEXT,
    client_ip TEXT,
    client_ip_source TEXT,
    request_id TEXT,
    operation TEXT,
    database_name TEXT,
    environment TEXT,
    detail_fingerprint TEXT,
    detail_raw TEXT,
    reason TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    prev_hash TEXT,
    event_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_events_actor_id ON audit_events(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_event_type ON audit_events(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_events_created_at ON audit_events(created_at);

-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);
INSERT OR IGNORE INTO schema_version (version, applied_at) VALUES (1, datetime('now'));
";
