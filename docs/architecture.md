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
│   - Owns Engine (DatabaseDriver → Target DB)             │
│   - CLI: dbward migrate/execute/approve/reject/mcp       │
│   - MCP: dbward mcp [--server http://...]                │
└──────┬───────────────────────────────────┬───────────────┘
       │ Direct mode                       │ Server mode
       │ (no server needed)                │ (HTTP + API token)
       ▼                                   ▼
┌──────────────────┐          ┌────────────────────────────┐
│ Target DB        │          │ Server (dbward server)     │
│ (PostgreSQL /    │          │   - Approval state (SQLite)│
│  MySQL)          │          │   - Audit log (SQLite)     │
└──────────────────┘          │   - Auth (API tokens)      │
                              │   - Ed25519 token signing  │
                              │   - NO DB connection       │
                              └────────────────────────────┘
```

## Crate Dependency Graph

```
dbward-cli (binary)
├── dbward-core      (Engine, DatabaseDriver trait, types, RBAC, audit, config, token verification)
├── dbward-migrate   (migration file I/O + execution via DatabaseDriver)
│     └── dbward-core
└── dbward-server    (axum HTTP, approval state, SQLite, auth, Ed25519 signing)
      └── dbward-core (types + token)
```

## DatabaseDriver Trait

Abstracts over database backends. URL scheme selects the driver automatically.

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

// Auto-selection:
//   postgres:// → PostgresDriver (PgPool)
//   mysql://    → MysqlDriver (MySqlPool)
pub async fn connect(url: &str) -> Result<Arc<dyn DatabaseDriver>, Error>;
```

Engine and Migrator take `Arc<dyn DatabaseDriver>` — no direct sqlx dependency outside core.

## Two Modes

### Direct Mode

Client connects directly to target DB. No approval flow. Audit log to stdout.

### Server Mode

Client talks to server for approval, then executes locally.

```
Client                              Server
  │                                   │
  ├─① POST /api/requests ───────────▶│ policy check → pending / auto_approved
  │                                   │
  │    (human approves via CLI)       │
  │                                   │◀── POST /api/requests/{id}/approve
  │                                   │     → generates Ed25519 execution_token
  │                                   │
  ├─② GET /api/requests/{id} ──────▶│ → status + execution_token
  │                                   │
  ├─③ verify token → Engine → DB     │
  │                                   │
  ├─④ POST /api/requests/{id}/complete▶│ → audit_log + status: "executed"
```

## Execution Token (Ed25519)

```json
{
  "request_id": "req_abc",
  "operation": "migrate_up",
  "environment": "production",
  "detail_hash": "sha256(SQL)",
  "expires_at": "2026-05-01T14:00:00Z",
  "signature": "ed25519_sign(message)"
}
```

- Server holds **private key** (signs). Client holds **public key** only (verifies).
- `detail_hash` = SHA-256 of SQL — prevents approve-one-execute-another.
- Token replay prevention: executed/failed requests don't issue new tokens.
- Public key available via `GET /api/public-key`.

## MCP Async Approval (Server Mode)

MCP tools don't block on approval. Instead:

1. `dbward_execute_query` → returns `"Request {id} requires approval"` immediately
2. Human approves via CLI: `dbward approve {id}`
3. AI calls `dbward_check_request` → returns status
4. AI calls `dbward_resume_execution` → verifies token, executes, reports completion

8 MCP tools total (6 base + `check_request` + `resume_execution`).

## REST API (9 endpoints)

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | No | Health check |
| GET | `/api/public-key` | No | Ed25519 public key (32 bytes) |
| GET | `/api/requests` | Yes | List requests |
| POST | `/api/requests` | Yes | Create request |
| GET | `/api/requests/:id` | Yes | Get request + token if approved |
| POST | `/api/requests/:id/approve` | Yes | Approve (requester ≠ approver) |
| POST | `/api/requests/:id/reject` | Yes | Reject (admin or requester) |
| POST | `/api/requests/:id/complete` | Yes | Report execution result |
| GET | `/api/audit` | Yes | Audit log |

## Security

| Attack | Mitigation |
|---|---|
| Forge execution token | Ed25519 asymmetric — client has public key only |
| Approve one SQL, execute another | `detail_hash` in signature |
| Token replay | Executed requests don't issue tokens |
| Brute-force API tokens | SHA-256 + prefix O(1) lookup |
| SQL injection (multi-statement) | Semicolon check rejects chained statements |
| Self-approve | Server enforces requester ≠ approver |
| Unauthorized reject | Only admin or requester can reject |
| Direct mode bypass | Documentation + DB-level permissions |

## SQLite Schema (Server)

```sql
PRAGMA journal_mode=WAL;

CREATE TABLE tokens (
    id TEXT PRIMARY KEY, user TEXT NOT NULL, role TEXT NOT NULL,
    hash TEXT NOT NULL, prefix TEXT NOT NULL,
    created_at TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE requests (
    id TEXT PRIMARY KEY, user TEXT NOT NULL,
    operation TEXT NOT NULL, environment TEXT NOT NULL, detail TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    approved_by TEXT, created_at TEXT NOT NULL, resolved_at TEXT
);

CREATE TABLE audit_log (
    id TEXT PRIMARY KEY, timestamp TEXT NOT NULL,
    user TEXT NOT NULL, role TEXT NOT NULL,
    operation TEXT NOT NULL, environment TEXT NOT NULL, detail TEXT NOT NULL,
    success INTEGER NOT NULL, error_message TEXT, request_id TEXT
);
```

## Migration File Format (dbmate-compatible)

```sql
-- migrate:up
CREATE TABLE users (id SERIAL PRIMARY KEY, name TEXT NOT NULL);

-- migrate:down
DROP TABLE users;
```
