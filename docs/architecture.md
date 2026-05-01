# Architecture

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

CLI, MCP, and server all go through the same `Engine`.

```rust
pub struct Engine {
    pool: PgPool,
    config: Config,
}

impl Engine {
    pub async fn migrate_up(&self, user: &str, role: Role) -> Result<MigrationResult>;
    pub async fn migrate_down(&self, user: &str, role: Role) -> Result<MigrationResult>;
    pub async fn migrate_status(&self) -> Result<Vec<MigrationStatus>>;
    pub async fn migrate_create(&self, name: &str) -> Result<PathBuf>;
    pub async fn execute_query(&self, user: &str, role: Role, sql: &str) -> Result<QueryResult>;
}
```

## Two Modes

### Direct Mode (CLI + MCP stdio, no server)

Engine connects directly to target DB.
No approval flow — operations execute immediately.
Audit log to stdout (volatile).

```
dbward-cli / dbward mcp
  └─ Engine (owns PgPool)
       └─ Target DB
```

### Server Mode (approval flow)

`dbward server` runs as a long-lived process.
Server has NO database connection — it only manages approval state and audit log.
Client executes DB operations locally after receiving approval.

```
dbward-cli --server http://localhost:8080
  │ HTTP + API token
  ▼
dbward-server (axum + SQLite)
  ├─ Authentication (API token → user + role)
  ├─ Policy check (approval required?)
  │   ├─ No  → return {status: "auto_approved"}
  │   └─ Yes → create pending request, return {status: "pending"}
  └─ Audit log (SQLite, persistent)

(after approval)
dbward-cli --server http://localhost:8080
  ├─ GET /api/requests/{id} → sees "approved"
  ├─ Engine executes locally (client has DB access)
  └─ POST /api/requests/{id}/complete → reports result to server
```
```

## Approval Flow (server mode)

State machine:
```
pending → approved → executed
        → rejected
```

MVP constraints:
- Hardcoded policy: production mutating ops require 1 approval
- Requester ≠ approver (enforced by server)
- One pending migration request at a time (ordering safety)
- Approval = immediate execution (no scheduled execution)

REST API (7 endpoints):
```
POST   /api/requests              Create approval request
GET    /api/requests              List requests
GET    /api/requests/{id}         Get request status (for polling)
POST   /api/requests/{id}/approve Approve
POST   /api/requests/{id}/reject  Reject
POST   /api/requests/{id}/complete Client reports execution result
GET    /api/audit                 Search audit log
```

## Authentication (server mode)

API tokens per user. Server stores bcrypt hash only.

```bash
dbward server token create --user alice --role developer
# → Token: dbw_xxxxxxxxxxxx (shown once)
```

Client sends: `Authorization: Bearer dbw_xxxxxxxxxxxx`

## SQLite Schema (server internal state)

```sql
PRAGMA journal_mode=WAL;  -- concurrent reads during writes

CREATE TABLE tokens (
    id TEXT PRIMARY KEY,
    user TEXT NOT NULL,
    role TEXT NOT NULL,
    hash TEXT NOT NULL,
    created_at TEXT NOT NULL
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

## Multi-Environment Config

```toml
# dbward.toml (direct mode)
environment = "development"
role = "developer"
migrations_dir = "db/migrations"

[database]
url = "postgres://localhost:5432/myapp"
```

```toml
# dbward-server.toml (server mode)
listen = "127.0.0.1:8080"
data_dir = "/var/lib/dbward"  # SQLite files

[[databases]]
name = "production"
url = "postgres://prod:5432/myapp"
approval_required = true

[[databases]]
name = "staging"
url = "postgres://staging:5432/myapp"
approval_required = false
```

## Data Flows

### 1. Direct: `dbward migrate up`

```
dbward-cli
  ├─ load_config()
  ├─ check_permission(role, MigrateUp)
  ├─ Engine::migrate_up()
  │   ├─ connect to target DB
  │   ├─ read migration files, check schema_migrations
  │   └─ execute pending migrations in transaction
  ├─ AuditLogger::log() → stdout JSON
  └─ print result
```

### 2. Server: `dbward migrate up --server http://...`

```
dbward-cli
  ├─ POST /api/requests {operation: "migrate_up", env: "production"}
  │   (Authorization: Bearer dbw_xxx)
  │
dbward-server
  ├─ authenticate token → alice (developer)
  ├─ policy: production + migrate → approval required
  ├─ INSERT INTO requests (status=pending)
  └─ respond: {"id":"req_abc","status":"pending"}

(later) bob runs: dbward approve req_abc --server http://...
  ├─ POST /api/requests/req_abc/approve
  │
dbward-server
  ├─ authenticate token → bob (admin)
  ├─ check: bob ≠ alice
  ├─ UPDATE requests SET status='approved'
  └─ respond: {"id":"req_abc","status":"approved"}

(client polls or is notified)
dbward-cli
  ├─ GET /api/requests/req_abc → status: "approved"
  ├─ Engine::migrate_up() locally (client has DB access)
  ├─ POST /api/requests/req_abc/complete {success: true, result: "Applied 2 migrations"}
  │
dbward-server
  ├─ UPDATE requests SET status='executed'
  ├─ INSERT INTO audit_log
  └─ respond: {"status":"executed"}
```

### 3. MCP via server: `dbward_migrate_up`

```
AI Client → MCP stdio → dbward mcp --server http://...
  ├─ POST /api/requests → {status: "pending", id: "req_abc"}
  ├─ respond to AI: "Approval required. Request ID: req_abc."

(after human approves via CLI)
AI Client calls dbward_migrate_up again (or polls)
  ├─ GET /api/requests/req_abc → status: "approved"
  ├─ Engine::migrate_up() locally
  ├─ POST /api/requests/req_abc/complete
  └─ respond to AI: "Applied 2 migrations"
```

### 4. Direct: `dbward execute "SELECT * FROM users"`

```
dbward-cli
  ├─ load_config()
  ├─ classify_query(sql) → Select
  ├─ check_permission(role, ExecuteQuery)
  ├─ Engine::execute_query()
  ├─ AuditLogger::log() → stdout JSON
  └─ print rows
```

## MCP Protocol (stdio)

JSON-RPC 2.0 over stdin/stdout. One JSON object per line.

### Initialization

```
→ {"jsonrpc":"2.0","id":0,"method":"initialize",
    "params":{"protocolVersion":"2024-11-05","capabilities":{}}}
← {"jsonrpc":"2.0","id":0,"result":{
    "protocolVersion":"2024-11-05",
    "serverInfo":{"name":"dbward","version":"0.1.0"},
    "capabilities":{"tools":{}}}}
→ {"jsonrpc":"2.0","method":"notifications/initialized"}
```

### Tool Listing

```
→ {"jsonrpc":"2.0","id":1,"method":"tools/list"}
← {"jsonrpc":"2.0","id":1,"result":{"tools":[
    {"name":"dbward_migrate_status","description":"Show migration status",
     "inputSchema":{"type":"object","properties":{}}},
    {"name":"dbward_migrate_up","description":"Run pending migrations",
     "inputSchema":{"type":"object","properties":{
       "count":{"type":"integer","description":"Max migrations to apply"}}}},
    {"name":"dbward_migrate_down","description":"Rollback last migration",
     "inputSchema":{"type":"object","properties":{
       "count":{"type":"integer","description":"Migrations to rollback","default":1}}}},
    {"name":"dbward_migrate_create","description":"Create a new migration file",
     "inputSchema":{"type":"object","properties":{
       "name":{"type":"string","description":"Migration name"}},
      "required":["name"]}},
    {"name":"dbward_execute_query","description":"Execute SQL query",
     "inputSchema":{"type":"object","properties":{
       "sql":{"type":"string","description":"SQL statement"}},
      "required":["sql"]}},
    {"name":"dbward_audit_search","description":"Search audit log",
     "inputSchema":{"type":"object","properties":{
       "user":{"type":"string"},
       "operation":{"type":"string"},
       "limit":{"type":"integer","default":20}}}}
  ]}}
```

## Migration File Format

dbmate-compatible:

```
db/migrations/
  20260501120000_create_users.sql
  20260501120100_add_email_index.sql
```

```sql
-- migrate:up
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL
);

-- migrate:down
DROP TABLE users;
```

### Schema Tracking

```sql
CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY
);
```

## Query Classification

Prefix-based (no SQL parser in MVP):

```rust
fn classify_query(sql: &str) -> Result<QueryType, Error> {
    let trimmed = sql.trim_start().to_uppercase();
    if trimmed.starts_with("SELECT") || trimmed.starts_with("WITH") {
        Ok(QueryType::Select)
    } else if trimmed.starts_with("INSERT") {
        Ok(QueryType::Insert)
    } else if trimmed.starts_with("UPDATE") {
        Ok(QueryType::Update)
    } else if trimmed.starts_with("DELETE") {
        Ok(QueryType::Delete)
    } else {
        Err(Error::DdlNotAllowed)
    }
}
```

## Module Responsibilities

| Crate | Owns | Does NOT own |
|---|---|---|
| `dbward-core` | Engine, types, RBAC, audit, config, DB pool, query exec | Migration file I/O, HTTP, approval state |
| `dbward-migrate` | Migration file parsing, schema_migrations, up/down | DB connection creation |
| `dbward-server` | axum HTTP, SQLite (approval + audit), auth tokens | DB operations (server has no DB connection) |
| `dbward-cli` | CLI parsing (clap), MCP stdio, HTTP client to server, local DB execution after approval | — |
