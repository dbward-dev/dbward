# Architecture

## Components

```
┌──────────────────────────────────────────────────────────┐
│ AI Client (Kiro / Cursor / Copilot)                      │
│   uses MCP stdio to talk to dbward                       │
└──────────────┬───────────────────────────────────────────┘
               │ MCP (JSON-RPC 2.0 over stdin/stdout)
               ▼
┌──────────────────────────────────────────────────────────┐
│ Client (dbward-cli / dbward mcp)                         │
│   - NO DB credentials or DB connection                   │
│   - Creates requests, resumes, receives results       │
│   - CLI: dbward login/migrate/execute/approve/reject/... │
│   - MCP: dbward mcp (12 tools)                           │
│   - Saves results locally (~/.dbward/results/)           │
└──────────────┬───────────────────────────────────────────┘
               │ HTTPS (OIDC JWT or API token)
               ▼
┌──────────────────────────────────────────────────────────┐
│ Server (dbward server)                                   │
│   - OIDC JWT verification + API token auth               │
│   - Policy engine (4 policy types, DB×env scoped)        │
│   - Approval state (SQLite)                              │
│   - Audit log (SQLite)                                   │
│   - Ed25519 token signing                                │
│   - On-demand job dispatch (poll/claim)                  │
│   - In-memory result relay (Notify+Mutex, 10min TTL)     │
│   - Webhook notifications                                │
│   - NO DB connection                                     │
└──────────────┬───────────────────────────────────────────┘
               │ Outbound HTTPS polling (no inbound needed)
               ▼
┌──────────────────────────────────────────────────────────┐
│ Agent (dbward agent)                                     │
│   - ONLY component with DB credentials                   │
│   - Polls server for dispatched jobs                     │
│   - Claims + executes operations                         │
│   - Returns results to server                            │
│   - Runs on DB-reachable network                         │
│   - Multiple agents supported (capabilities matching)    │
└──────────────┬───────────────────────────────────────────┘
               │ DatabaseDriver (sqlx)
               ▼
┌──────────────────────────────────────────────────────────┐
│ Target DB (PostgreSQL / MySQL)                           │
└──────────────────────────────────────────────────────────┘

               ┌────────────────────────────┐
               │ Identity Provider (IdP)    │
               │ Google / Okta / Auth0 /    │
               │ Keycloak / K8s SA          │
               └────────────────────────────┘
```

## Crate Dependency Graph

```
dbward-cli (binary)
├── dbward-domain      (types, RBAC, audit, config, token verification)
├── dbward-migrate   (migration file I/O)
│     └── dbward-domain
├── dbward-server    (axum HTTP, auth, policy, SQLite, Ed25519, webhooks, result relay)
│     └── dbward-domain
└── dbward-agent     (DatabaseDriver, polls server, executes operations)
      ├── dbward-domain
      └── dbward-migrate
```

## Request Flow (On-Demand Execution)

All DB operations go through: client → server → agent → DB. The agent only executes when the client resumes — not on approval.

```
Client                              Server                              Agent
  │                                   │                                   │
  ├─① POST /api/requests ───────────▶│ auth + policy check               │
  │                                   │ → pending / auto_approved /       │
  │                                   │   break_glass                     │
  │                                   │                                   │
  │  (if pending)                     │                                   │
  │  CLI prints request ID and exits  │                                   │
  │                                   │                                   │
  │    (human approves via CLI)       │                                   │
  │                                   │◀── POST /api/requests/{id}/approve│
  │                                   │     → status = approved           │
  │                                   │     → webhook notification        │
  │                                   │                                   │
  ├─② POST /api/requests/{id}/resume ▶│ creates ResultSlot in memory   │
  │  (dbward request resume {id})     │ → status = dispatched             │
  │                                   │                                   │
  ├─③ GET /api/requests/{id}/result/stream ▶│ long-poll (up to 5 min)    │
  │                                   │                                   │
  │                                   │  ④ Agent polls for dispatched jobs│
  │                                   │◀──── POST /api/agent/poll ────────┤
  │                                   │                                   │
  │                                   │  ⑤ Agent claims job               │
  │                                   │◀── POST /api/agent/jobs/{id}/claim│
  │                                   │     → returns execution_token     │
  │                                   │     → status = running            │
  │                                   │                                   │
  │                                   │  ⑥ Agent verifies token,          │
  │                                   │     executes on DB                │
  │                                   │                                   │
  │                                   │  ⑦ Agent returns result           │
  │                                   │◀── POST /api/agent/jobs/{id}/result│
  │                                   │     → audit_log + status update   │
  │                                   │     → writes to ResultSlot        │
  │                                   │     → notifies waiting client     │
  │                                   │                                   │
  │◀─────────── ⑧ result streamed ───│                                   │
  │  CLI saves to ~/.dbward/results/  │                                   │
```

For auto-approved requests, the CLI combines steps ①②③ in a single `resume_and_wait` call.

### Result Relay

The server never persists results to disk. Results flow through in-memory `ResultSlot` channels:

1. Client resumes → server creates `ResultSlot` (Notify + Mutex)
2. Agent submits result → server writes to slot, notifies waiters
3. Client receives result via long-poll → slot is removed
4. Slots expire after 10 minutes (cleanup on insert/get)

The client saves results locally to `~/.dbward/results/<request_id>.json` and can view them later with `dbward result <id>`.

## Policy Engine

Four policy types, all scoped to database × environment. Defined in TOML (synced to SQLite on server startup) or managed via CRUD REST API (admin only). API-created policies have `source = "api"`, TOML-synced have `source = "toml"`.

### Workflows

Determine whether an operation requires approval:

```toml
[[workflows]]
database = "primary"
environment = "production"
operations = ["execute_select", "execute_dml", "migrate_up", "migrate_down"]

[[workflows.steps]]
type = "approval"
min_approvals = 1
allowed_roles = ["admin"]
require_distinct_actors = true
```

Evaluation: server checks workflows table for matching (database, environment, operation). If a workflow with steps exists, approval is required. Wildcard `*` matches any database.

### Execution Policies

Control re-execution and retry:

| Field | Default | Description |
|---|---|---|
| `max_executions` | 1 | Max times a request can be dispatched |
| `execution_window_secs` | 86400 | Window after resolution for re-dispatch |
| `retry_on_failure` | false | Allow re-dispatch of failed requests |

### Result Policies

Control result access:

| Field | Default | Description |
|---|---|---|
| `delivery_mode` | `direct` | How results are delivered |
| `access` | `["requester", "admin"]` | Roles that can access results |

### Notification Policies

Route webhooks per database × environment (overrides global `[[webhooks]]`):

```toml
[[notification_policies]]
database = "primary"
environment = "production"

[[notification_policies.webhooks]]
url = "https://hooks.slack.com/services/..."
format = "slack"
```

## Authentication

Two methods coexist. Server distinguishes by Bearer token prefix:

```
Bearer dbw_xxx   → API token (SHA-256 prefix lookup)
Bearer eyJxxx    → JWT (OIDC verification)
```

Both resolve to `AuthUser { token_id, user, role }`.

### OIDC (for humans)

```
dbward login     → Browser → IdP → Authorization Code Flow + PKCE
dbward login --device → Device Code Flow (headless)
dbward whoami    → Show identity, role, expiry
dbward logout    → Revoke at IdP + delete ~/.dbward/credentials.json
```

Auto-refresh: before each command, if token expires within 5 minutes.

### API Tokens (for CI/CD, MCP agents)

Managed via `dbward token create/list/revoke (via API)`. Used when OIDC is not practical.

### Server Auth Configuration

```toml
[auth]
mode = "both"  # "oidc", "token", "both"

[auth.oidc]
issuer = "https://accounts.google.com"
client_id = "xxx.apps.googleusercontent.com"
client_secret_env = "DBWARD_OIDC_CLIENT_SECRET"
jwks_uri = "..."  # optional override for Docker environments
default_role = "readonly"

[[auth.oidc.role_mappings]]
subject = "alice@example.com"
role = "admin"

[[auth.oidc.role_mappings]]
claim = "groups"
value = "dbward-developers"
role = "developer"
```

Role mapping fallback: subject match → claim match → default_role.

### JWT Verification

| Check | Detail |
|---|---|
| iss | Must match configured issuer |
| aud | Must contain configured client_id |
| exp | Current time + 30s leeway |
| iat | Must be within 24 hours |
| kid → key | Lookup in cached JWKS |
| signature | RS256 or ES256 |

JWKS cache: 1-hour TTL, re-fetch on unknown kid (min 60s interval).

## Execution Token (Ed25519)

```json
{
  "request_id": "abc",
  "operation": "migrate_up",
  "environment": "production",
  "database": "primary",
  "detail_hash": "sha256(SQL)",
  "expires_at": "2026-05-01T14:00:00Z",
  "signature": "ed25519_sign(message)"
}
```

- Server holds **private key** (signs on approve/auto_approve/break_glass/claim)
- Agent holds **public key** (verifies before executing)
- `detail_hash` = SHA-256 of SQL — prevents approve-one-execute-another
- `database` in signature — prevents executing against wrong database
- Token replay prevention: executed/failed requests don't issue new tokens
- Public key available via `GET /api/public-key`

## Agent

### Configuration

```toml
agent_id = "agent-prod"
poll_interval_ms = 1000
lease_duration_secs = 300
max_concurrent_tasks = 2

[server]
url = "https://dbward.internal:3000"
agent_token = "dbw_agent_xxx"

[capabilities]
environments = ["development", "staging", "production"]
databases = ["primary", "analytics"]
operations = ["execute_select", "execute_dml", "migrate_up", "migrate_down", "migrate_status"]

[databases.primary]
url = "postgres://user:pass@db-primary:5432/app"
migrations_dir = "/data/migrations/primary"

[databases.analytics]
url = "mysql://user:pass@db-analytics:3306/warehouse"
```

### Capabilities Matching

Agent registers which databases, environments, and operations it supports. Server filters poll results to match. Multiple agents can run simultaneously (e.g., one per DB or network zone).

### Lease/Claim

- Agent claims a job → server creates `agent_executions` record with lease expiry
- Status transitions: dispatched → running (on claim) → executed/failed (on result)
- Only the claiming agent can submit the result (agent_id verified)

## DatabaseDriver Trait

Lives in the agent only. URL scheme selects the driver:

```rust
#[async_trait]
pub trait DatabaseDriver: Send + Sync {
    async fn query(&self, sql: &str) -> Result<Vec<Value>, Error>;
    async fn execute(&self, sql: &str) -> Result<u64, Error>;
    async fn apply_migration(&self, sql: &str, version: &str) -> Result<(), Error>;
    async fn revert_migration(&self, down_sql: &str, version: &str) -> Result<(), Error>;
    async fn ensure_migrations_table(&self) -> Result<(), Error>;
    async fn applied_versions(&self) -> Result<Vec<String>, Error>;
}

// postgres:// → PostgresDriver (PgPool)
// mysql://    → MysqlDriver (MySqlPool)
```

## Webhook Notifications

```toml
[[webhooks]]
url = "https://hooks.slack.com/services/..."
events = ["request_created", "request_approved", "request_rejected", "request_completed", "break_glass"]
format = "slack"

[[webhooks]]
url = "https://internal.example.com/dbward"
events = ["break_glass"]
format = "generic"
secret = "whsec_xxxx"  # HMAC-SHA256 in X-Dbward-Signature header
```

- Fire-and-forget (tokio::spawn)
- 3 retries with exponential backoff (1s → 4s → 16s)
- Failure is warn log only (never blocks request processing)

## Break-Glass (Emergency Bypass)

```bash
dbward execute "SELECT pg_terminate_backend(12345)" \
  --emergency --reason "connection pool exhausted at 3am"
```

- Server issues token immediately (status = `break_glass`)
- Agent picks up and executes when dispatched
- Webhook fires `break_glass` event (🚨 in Slack)
- Reason recorded in audit log
- Admin + Developer only (Readonly cannot)

## MCP Async Approval

MCP client never connects to DB. All operations go through server → agent.

1. `dbward_execute_query` → creates request → returns result (if auto-approved and agent completes) or request ID (if pending)
2. Human approves via CLI: `dbward request approve {id}`
3. AI calls `dbward_wait_request` → waits for approval and returns result

MCP agents authenticate via API tokens (OIDC browser flow not available in stdio mode).

## SQLite Schema (Server)

```sql
PRAGMA journal_mode=WAL;

-- API tokens
CREATE TABLE tokens (
    id TEXT PRIMARY KEY, user TEXT NOT NULL, role TEXT NOT NULL,
    hash TEXT NOT NULL, prefix TEXT NOT NULL,
    created_at TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0
);

-- Requests
CREATE TABLE requests (
    id TEXT PRIMARY KEY, created_by TEXT NOT NULL,
    operation TEXT NOT NULL, environment TEXT NOT NULL,
    database_name TEXT NOT NULL, detail TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL, resolved_at TEXT,
    emergency INTEGER NOT NULL DEFAULT 0, reason TEXT
);

-- Approval records
CREATE TABLE approvals (
    id TEXT PRIMARY KEY, request_id TEXT NOT NULL,
    action TEXT NOT NULL, actor_id TEXT NOT NULL,
    comment TEXT, created_at TEXT NOT NULL
);

-- Agent execution tracking
CREATE TABLE agent_executions (
    id TEXT PRIMARY KEY, request_id TEXT NOT NULL,
    agent_id TEXT NOT NULL, status TEXT NOT NULL,
    execution_token_json TEXT, lease_expires_at TEXT,
    started_at TEXT, finished_at TEXT, error_message TEXT,
    created_at TEXT NOT NULL
);

-- Audit log
CREATE TABLE audit_log (
    id TEXT PRIMARY KEY, request_id TEXT, execution_id TEXT,
    actor_id TEXT NOT NULL, operation TEXT NOT NULL,
    environment TEXT NOT NULL, database_name TEXT NOT NULL,
    detail TEXT NOT NULL, status TEXT NOT NULL,
    result_summary TEXT, error_message TEXT,
    created_at TEXT NOT NULL
);

-- Workflows (TOML sync + API CRUD)
CREATE TABLE workflows (
    id TEXT PRIMARY KEY, database_name TEXT NOT NULL,
    environment TEXT NOT NULL, operations_json TEXT NOT NULL,
    steps_json TEXT NOT NULL, source TEXT NOT NULL,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);

-- Execution policies
CREATE TABLE execution_policies (
    id TEXT PRIMARY KEY, database_name TEXT NOT NULL,
    environment TEXT NOT NULL, max_executions INTEGER NOT NULL,
    execution_window_secs INTEGER NOT NULL,
    retry_on_failure INTEGER NOT NULL DEFAULT 0,
    source TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);

-- Result policies
CREATE TABLE result_policies (
    id TEXT PRIMARY KEY, database_name TEXT NOT NULL,
    environment TEXT NOT NULL, delivery_mode TEXT NOT NULL,
    storage_config_json TEXT NOT NULL, access_json TEXT NOT NULL,
    source TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);

-- Notification policies
CREATE TABLE notification_policies (
    id TEXT PRIMARY KEY, database_name TEXT NOT NULL,
    environment TEXT NOT NULL, webhooks_json TEXT NOT NULL,
    source TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
```

## Security

| Attack | Mitigation |
|---|---|
| Forge execution token | Ed25519 asymmetric — agent verifies with public key |
| Approve one SQL, execute another | `detail_hash` in token signature |
| Token replay | Executed/failed requests don't issue tokens |
| SQL injection (multi-statement) | Semicolon check rejects chained statements |
| Writable CTE bypass | WITH clause DML detection |
| Self-approve | Server enforces requester ≠ approver |
| Unauthorized reject | Only admin or requester can reject |
| DB credential leak | Only agent has credentials |
| Agent result spoofing | Only the claiming agent_id can submit result |
| Auth token leak (OIDC) | Short-lived JWT + PKCE + revocation |
| Auth token leak (API) | `dbward server token revoke` + audit log |
| Webhook secret leak | HMAC-SHA256 signature verification |

## CLI Commands

```
dbward init --preset small-team  # Generate config files for all components
dbward login                    # OIDC login (browser)
dbward login --device           # OIDC login (headless)
dbward whoami                   # Show current identity
dbward logout                   # Revoke + delete tokens
dbward migrate up [--count N]
dbward migrate down [--count N]
dbward migrate status
dbward migrate create <name>
dbward execute <SQL>            # --emergency --reason for break-glass
                                # --output <path> / --no-save
dbward request approve <ID>
dbward request reject <ID>
dbward request list             # Show requests
dbward request resume <ID>     # Resume + wait for result
                                # --output <path> / --no-save
dbward result <ID>              # Show locally saved result
dbward mcp                      # MCP stdio server
dbward server start             # HTTP server
dbward token create --subject <USER> --subject-type user --role <ROLE>
dbward server token revoke --id <ID> --data <DB>
dbward agent --config <PATH>    # Start agent
```

## Migration File Format (dbmate-compatible)

```sql
-- migrate:up
CREATE TABLE users (id SERIAL PRIMARY KEY, name TEXT NOT NULL);

-- migrate:down
DROP TABLE users;
```
