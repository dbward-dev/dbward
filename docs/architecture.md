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
│ Client (dbward process)                                  │
│   - Runs on a network that can reach the target DB       │
│   - Owns Engine (PgPool → Target DB)                     │
│   - CLI: dbward migrate/execute/approve/mcp              │
│   - MCP: dbward mcp [--server http://...]                │
└──────┬───────────────────────────────────┬───────────────┘
       │ Direct mode                       │ Server mode
       │ (no server needed)                │ (HTTP + API token)
       ▼                                   ▼
┌──────────────┐              ┌────────────────────────────┐
│ Target DB    │              │ Server (dbward server)     │
│ (PostgreSQL) │              │   - Approval state (SQLite)│
└──────────────┘              │   - Audit log (SQLite)     │
                              │   - Auth (API tokens)      │
                              │   - NO DB connection       │
                              └────────────────────────────┘
```

## Crate Dependency Graph

```
dbward-cli (binary)
├── dbward-core      (Engine, types, RBAC, audit, config, query execution)
├── dbward-migrate   (migration file I/O + execution)
│     └── dbward-core
└── dbward-server    (axum HTTP, approval state, SQLite, auth — NO DB connection)
      └── dbward-core (types only)
```

## Core Engine

Runs on the client side. CLI, MCP, and server-mode client all use the same Engine.

```rust
pub struct Engine {
    pool: PgPool,
    config: Config,
}

impl Engine {
    pub async fn migrate_up(&self, ...) -> Result<MigrationResult>;
    pub async fn migrate_down(&self, ...) -> Result<MigrationResult>;
    pub async fn migrate_status(&self) -> Result<Vec<MigrationStatus>>;
    pub async fn migrate_create(&self, name: &str) -> Result<PathBuf>;
    pub async fn execute_query(&self, ..., sql: &str) -> Result<QueryResult>;
}
```

## Two Modes

### Direct Mode (no server)

Client connects directly to target DB. No approval flow.
Audit log to stdout (volatile).

```
Client (dbward CLI / MCP)
  └─ Engine → Target DB
```

### Server Mode (approval flow)

Client talks to server for approval, then executes DB operations locally.
Server never touches the target DB.
Server issues a signed execution token upon approval — client refuses to execute without it.

```
Client                              Server
  │                                   │
  ├─① POST /api/requests ───────────▶│ policy check → pending / auto_approved
  │                                   │   (auto_approved → execution_token included)
  │                                   │
  │    (human approves via CLI)       │
  │                                   │◀── POST /api/requests/{id}/approve
  │                                   │     → generates execution_token
  │                                   │
  ├─② GET /api/requests/{id} ──────▶│ → status: "approved" + execution_token
  │                                   │
  ├─③ verify token → Engine → DB     │
  │                                   │
  ├─④ POST /api/requests/{id}/complete▶│ → audit_log + status: "executed"
  │                                   │
```

## Approval Flow

State machine:
```
pending ──→ approved ──→ executed
   │                       │
   └──→ rejected      failed
```

auto_approved ──→ executed (no human approval needed)

When a request transitions to `approved` or `auto_approved`, the server generates
a signed execution token. The client **must** verify this token before executing.
Without a valid token, the client refuses to run the operation (enforced in code).

MVP constraints:
- Hardcoded policy: production mutating ops require 1 approval
- Requester ≠ approver (enforced by server)
- One pending migration request at a time (ordering safety)

## Execution Token

Server issues a signed token when a request is approved. Client verifies the token
locally before executing any DB operation in server mode.

### Token structure

```json
{
  "request_id": "req_abc",
  "operation": "migrate_up",
  "environment": "production",
  "detail_hash": "sha256(SQL or migration filename)",
  "issued_at": "2026-05-01T13:00:00Z",
  "expires_at": "2026-05-01T14:00:00Z",
  "signature": "ed25519_sign(private_key, request_id + operation + environment + detail_hash + expires_at)"
}
```

### Signing

- Algorithm: **Ed25519** (asymmetric)
- Server holds the **private key** (signs tokens)
- Client holds the **public key** only (verifies tokens, cannot forge)
- Input: `request_id || operation || environment || detail_hash || expires_at`
- `detail_hash`: SHA-256 of the SQL statement or migration filename — prevents
  approving one query and executing another

### Key management

```bash
# Server generates keypair on first run
# Private key: data_dir/signing.key (server only, never shared)
# Public key:  data_dir/signing.pub (distributed to clients)

dbward server start --data /var/lib/dbward
# → generates signing.key + signing.pub if absent

# Client config references the public key
# dbward.toml
server = "http://server:8080"
server_public_key = "/path/to/signing.pub"
```

### Client-side verification

1. Verify Ed25519 signature using server's public key — reject on mismatch
2. Check `expires_at` > now — reject if expired
3. Check `operation` and `environment` match the current request — reject on mismatch
4. Recompute `detail_hash` from the actual SQL/migration — reject if different from token

### Security properties

- **Asymmetric**: client cannot forge tokens (no private key)
- **detail_hash**: approved SQL ≠ executed SQL is detected
- **Time-limited**: default 1 hour expiry
- **Replay-bounded**: request_id uniqueness + expiry
- **OSS circumvention**: detectable via audit log (no `complete` call, or mismatched metadata)

## Security Considerations

### Direct mode limitations

Direct mode (no server) has no approval flow and no persistent audit log.
It is intended for local development only. Document clearly:
- Direct mode should NOT be used for production databases
- AI agents (MCP) should always use `--server` for production environments
- DB-level permissions should restrict what Direct mode can do

### Attack surface

| Attack | Mitigation |
|---|---|
| Forge execution token | Ed25519: client has public key only, cannot sign |
| Approve one SQL, execute another | `detail_hash` in token signature |
| Steal private key from client | Client never has private key (asymmetric) |
| Brute-force API tokens | SHA-256 hash + prefix lookup (not bcrypt O(n) scan) |
| SQL injection via multi-statement | Reject queries containing unquoted semicolons |
| Self-approve | Server enforces requester ≠ approver |
| Reject others' requests maliciously | Only admin or requester can reject |
| Direct mode bypass | Documentation + DB-level permissions |
| Environment spoofing | Server validates environment against its policy config |
| Token replay | request_id uniqueness + expiry + one-time use tracking |

## REST API (7 endpoints)

```
POST   /api/requests              Create approval request
                                    → auto_approved: response includes execution_token
GET    /api/requests              List requests
GET    /api/requests/{id}         Get request status (for polling)
                                    → approved: response includes execution_token
POST   /api/requests/{id}/approve Approve (human) → generates execution_token
POST   /api/requests/{id}/reject  Reject (human)
POST   /api/requests/{id}/complete Client reports execution result
GET    /api/audit                 Search audit log
```

All endpoints require `Authorization: Bearer <token>`.

## Authentication (server mode)

API tokens per user. Server stores bcrypt hash only.

```bash
dbward server token create --user alice --role developer
# → Token: dbw_xxxxxxxxxxxx (shown once, never retrievable)
```

## Config

### Client config (dbward.toml)

```toml
environment = "production"
role = "developer"
migrations_dir = "db/migrations"

[database]
url = "postgres://localhost:5432/myapp"
```

Priority: env vars > config file > defaults.
- `DBWARD_DATABASE_URL`, `DBWARD_ENV`, `DBWARD_ROLE`

### Server config (dbward-server.toml)

```toml
listen = "127.0.0.1:8080"
data_dir = "/var/lib/dbward"  # SQLite files

# Signing keypair auto-generated on first run (Ed25519)
# signing.key (private, server only) + signing.pub (distribute to clients)

# Policy: which environments require approval for mutating operations
[[environments]]
name = "production"
approval_required = true

[[environments]]
name = "staging"
approval_required = false
```

Server does NOT have database URLs — it only knows environment names and policies.
Client needs the server's **public key** (`signing.pub`) to verify execution tokens.

## SQLite Schema (server)

```sql
PRAGMA journal_mode=WAL;

CREATE TABLE tokens (
    id TEXT PRIMARY KEY,
    user TEXT NOT NULL,
    role TEXT NOT NULL,
    hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE requests (
    id TEXT PRIMARY KEY,
    user TEXT NOT NULL,
    operation TEXT NOT NULL,
    environment TEXT NOT NULL,
    detail TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    approved_by TEXT,
    created_at TEXT NOT NULL,
    resolved_at TEXT
);

CREATE TABLE audit_log (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    user TEXT NOT NULL,
    role TEXT NOT NULL,
    operation TEXT NOT NULL,
    environment TEXT NOT NULL,
    detail TEXT NOT NULL,
    success INTEGER NOT NULL,
    error_message TEXT,
    request_id TEXT
);
```

## Data Flows

### Scenario 1: AI Client → MCP → migrate up (approval required)

```
AI Client: "add email_verified column to users"
  │
  ▼ MCP stdio
Client (dbward mcp --server http://server:8080)
  │
  ├─① POST /api/requests
  │   {operation: "migrate_up", environment: "production",
  │    detail: "20260501_add_email_verified.sql"}
  │
Server
  ├─ auth: alice (developer)
  ├─ policy: production + migrate → approval required
  ├─ INSERT INTO requests (status='pending')
  └─ → {id: "req_abc", status: "pending"}
  │
MCP → AI: "Approval required. Request ID: req_abc"

        ~~~ human approves ~~~

bob: dbward approve req_abc --server http://server:8080
  │
Server
  ├─ auth: bob (admin), bob ≠ alice → OK
  ├─ UPDATE requests SET status='approved'
  └─ generate execution_token (HMAC-SHA256 signed, 1h expiry)

        ~~~ AI retries / polls ~~~

Client (dbward mcp)
  ├─② GET /api/requests/req_abc → "approved" + execution_token
  ├─③ verify token → Engine → Target DB (BEGIN → ALTER TABLE → schema_migrations → COMMIT)
  ├─④ POST /api/requests/req_abc/complete {success: true}
  │
Server
  ├─ UPDATE requests SET status='executed'
  └─ INSERT INTO audit_log
  │
MCP → AI: "Migration complete: add_email_verified"
```

### Scenario 2: CLI → execute query (auto-approved)

```
alice: dbward execute "SELECT * FROM users" --server http://server:8080
  │
  ├─① POST /api/requests
  │   {operation: "execute_query", environment: "staging", detail: "SELECT..."}
  │
Server
  ├─ policy: staging + SELECT → auto_approved
  └─ → {id: "req_xyz", status: "auto_approved", execution_token: "..."}
  │
Client
  ├─② verify token → Engine → Target DB → rows
  ├─③ POST /api/requests/req_xyz/complete {success: true}
  │
Server → INSERT INTO audit_log
  │
CLI → print rows
```

### Scenario 3: Direct mode (no server)

```
alice: dbward migrate up
  │
Client
  ├─ load_config()
  ├─ check_permission(role, MigrateUp)
  ├─ Engine → Target DB (execute migrations)
  ├─ AuditLogger → stdout (JSON line)
  └─ print result
```

## MCP Protocol (stdio)

JSON-RPC 2.0 over stdin/stdout. One JSON object per line.

6 tools:
- `dbward_migrate_status` — show applied/pending migrations
- `dbward_migrate_up` — apply pending migrations
- `dbward_migrate_down` — rollback migrations
- `dbward_migrate_create` — create new migration file
- `dbward_execute_query` — execute SQL (SELECT/DML, DDL rejected)
- `dbward_audit_search` — search audit log (server mode only)

## Migration File Format (dbmate-compatible)

```
db/migrations/
  20260501120000_create_users.sql
  20260501120100_add_email_index.sql
```

```sql
-- migrate:up
CREATE TABLE users (id SERIAL PRIMARY KEY, name TEXT NOT NULL);

-- migrate:down
DROP TABLE users;
```

Schema tracking: `schema_migrations` table in target DB.

## Query Classification

Prefix-based (no SQL parser in MVP):
- `SELECT` / `WITH` → Select
- `INSERT` / `UPDATE` / `DELETE` → DML (allowed)
- Everything else → DDL (rejected, must use migrations)

## Module Responsibilities

| Crate | Owns | Does NOT own |
|---|---|---|
| `dbward-core` | Engine, types, RBAC, audit, config, DB pool, query exec | Migration file I/O, HTTP, approval state |
| `dbward-migrate` | Migration file parsing, schema_migrations, up/down | DB connection creation |
| `dbward-server` | axum HTTP, SQLite (approval + audit), auth tokens | DB operations (no DB connection) |
| `dbward-cli` | CLI (clap), MCP stdio, HTTP client, local execution | — |
