use rusqlite::Connection;

const SCHEMA_VERSION: u32 = 4;

const MIGRATION_V2: &str = "
CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id TEXT PRIMARY KEY,
    webhook_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 10,
    next_retry_at TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL,
    last_attempted_at TEXT,
    claimed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_status_retry
    ON webhook_deliveries(status, next_retry_at);
";

const MIGRATION_V3: &str = "
ALTER TABLE execution_policies ADD COLUMN max_rows INTEGER;
";

const MIGRATION_V4: &str = "
ALTER TABLE agents ADD COLUMN uptime_secs INTEGER NOT NULL DEFAULT 0;
ALTER TABLE agents ADD COLUMN active_jobs_json TEXT NOT NULL DEFAULT '[]';
";

/// Initialize the database: set pragmas and create schema.
pub fn initialize(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        "PRAGMA locking_mode = NORMAL;
         PRAGMA synchronous = FULL;
         PRAGMA busy_timeout = 10000;
         PRAGMA foreign_keys = ON;",
    )?;

    // journal_mode must be verified — if the DB was previously WAL and another
    // process holds it open, the mode change silently fails.
    // Skip for in-memory databases (they only support "memory" journal mode).
    let mode: String = conn.pragma_query_value(None, "journal_mode", |r| r.get(0))?;
    if mode != "memory" && mode != "persist" {
        conn.execute_batch("PRAGMA journal_mode = PERSIST;")?;
        let actual: String = conn.pragma_query_value(None, "journal_mode", |r| r.get(0))?;
        if actual != "persist" {
            return Err(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_MISUSE),
                Some(format!(
                    "failed to set journal_mode=persist (got '{actual}'). \
                     Another process may hold the database open in WAL mode."
                )),
            ));
        }
    }

    let current: u32 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if current == 0 {
        conn.execute_batch(SCHEMA_SQL)?;
        conn.execute_batch(MIGRATION_V2)?;
        conn.execute_batch(MIGRATION_V3)?;
        conn.execute_batch(MIGRATION_V4)?;
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    } else if current < SCHEMA_VERSION {
        if current < 2 {
            conn.execute_batch(MIGRATION_V2)?;
        }
        if current < 3 {
            conn.execute_batch(MIGRATION_V3)?;
        }
        if current < 4 {
            conn.execute_batch(MIGRATION_V4)?;
        }
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
CREATE UNIQUE INDEX IF NOT EXISTS idx_approvals_no_dup_approve
  ON approvals(request_id, actor_id, step_index) WHERE action = 'approve';

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
CREATE UNIQUE INDEX IF NOT EXISTS idx_executions_unique_claim ON executions(request_id) WHERE status = 'claimed';

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
    statement_timeout_secs INTEGER,
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
    retention_days INTEGER NOT NULL DEFAULT 30,
    delivery_mode TEXT NOT NULL DEFAULT 'both',
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

-- Pending approvers (populated when request enters pending state)
CREATE TABLE IF NOT EXISTS request_pending_approvers (
    request_id TEXT NOT NULL REFERENCES requests(id),
    selector TEXT NOT NULL,
    step_index INTEGER NOT NULL,
    PRIMARY KEY (request_id, selector, step_index)
);
CREATE INDEX IF NOT EXISTS idx_pending_approvers_selector ON request_pending_approvers(selector);

-- Seed built-in roles
INSERT OR IGNORE INTO roles (name, permissions_json, databases_json, environments_json, built_in) VALUES
('admin', '[\"*\"]', '[\"*\"]', '[\"*\"]', 1),
('developer', '[\"request.create\",\"request.create_select\",\"request.view\",\"request.cancel\",\"request.dispatch\",\"result.view\",\"token.revoke_own\"]', '[\"*\"]', '[\"*\"]', 1),
('readonly', '[\"request.create_select\",\"request.view\",\"result.view\"]', '[\"*\"]', '[\"*\"]', 1),
('agent-default', '[\"agent.poll\",\"agent.claim\",\"agent.heartbeat\",\"agent.submit_result\"]', '[\"*\"]', '[\"*\"]', 1);

-- Validation triggers
CREATE TRIGGER IF NOT EXISTS chk_audit_event_hash_insert
BEFORE INSERT ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'event_hash must be 64 chars')
    WHERE length(NEW.event_hash) != 64;
    SELECT RAISE(ABORT, 'prev_hash must be 64 chars or NULL')
    WHERE NEW.prev_hash IS NOT NULL AND length(NEW.prev_hash) != 64;
END;

CREATE TRIGGER IF NOT EXISTS chk_requests_status_insert
BEFORE INSERT ON requests
BEGIN
    SELECT RAISE(ABORT, 'invalid request status')
    WHERE NEW.status NOT IN ('pending','approved','rejected','dispatched','completed','cancelled','failed','auto_approved','break_glass','running','executed','expired','execution_lost');
END;

CREATE TRIGGER IF NOT EXISTS chk_requests_status_update
BEFORE UPDATE OF status ON requests
BEGIN
    SELECT RAISE(ABORT, 'invalid request status')
    WHERE NEW.status NOT IN ('pending','approved','rejected','dispatched','completed','cancelled','failed','auto_approved','break_glass','running','executed','expired','execution_lost');
END;

-- Partial indexes for hot queries
CREATE INDEX IF NOT EXISTS idx_requests_dispatched ON requests(status) WHERE status = 'dispatched';
CREATE INDEX IF NOT EXISTS idx_requests_pending ON requests(status) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_requests_claimed ON executions(status) WHERE status = 'claimed';
";
