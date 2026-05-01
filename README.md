# dbward

DB operations workflow + approval engine. Safe database operations for teams and AI agents.

```
dbward execute "SELECT * FROM users"                    # Direct mode
dbward execute "DELETE FROM old" --server http://...     # Server mode (approval required)
dbward mcp                                              # MCP server for AI agents
```

## Why dbward?

Tools like dbmate and golang-migrate handle migrations but lack **approval workflows, audit logging, and access control**. Enterprise tools like Bytebase require heavy infrastructure. dbward fills the gap:

- **Single binary** — no Docker Compose, no external database for state
- **Approval flow built-in** — production changes require human approval
- **MCP-first** — AI agents operate under the same controls as humans
- **Server never touches your DB** — cryptographic enforcement via signed execution tokens

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    dbward server                         │
│  ┌──────────┐  ┌──────────┐  ┌───────────────────────┐ │
│  │ REST API │  │  SQLite  │  │ Ed25519 Token Signer  │ │
│  │ (axum)   │  │ (state)  │  │ (keypair)             │ │
│  └──────────┘  └──────────┘  └───────────────────────┘ │
│  NO database credentials — manages approvals only       │
└─────────────────────────────────────────────────────────┘
        ▲                              │
        │ HTTP API                     │ Signed execution token
        │                              ▼
┌─────────────────────────────────────────────────────────┐
│                  dbward client (CLI / MCP)               │
│  ┌──────────┐  ┌──────────┐  ┌───────────────────────┐ │
│  │  Engine  │  │ Migrator │  │ Token Verifier        │ │
│  │          │  │          │  │ (public key only)     │ │
│  └────┬─────┘  └────┬─────┘  └───────────────────────┘ │
│       │              │                                   │
│       └──────┬───────┘                                   │
│              ▼                                           │
│     ┌─────────────────┐                                  │
│     │ DatabaseDriver  │ ← trait (Postgres / MySQL)       │
│     └────────┬────────┘                                  │
└──────────────┼──────────────────────────────────────────┘
               ▼
         Target Database
```

**Key principle**: The server decides *what* can run. The client decides *where* it runs. The signed token binds the two — you can't execute anything the server didn't approve.

## Quick Start

### Direct Mode (development)

```bash
# Install
cargo install dbward

# Configure
cat > dbward.toml << EOF
[database]
url = "postgres://user:pass@localhost:5432/mydb"

[environment]
name = "development"

[role]
name = "admin"
EOF

# Migrations
dbward migrate create add_users_table
dbward migrate up
dbward migrate status

# Queries
dbward execute "SELECT * FROM users"
```

### Server Mode (team)

```bash
# 1. Start server
dbward server start --data dbward.db

# 2. Create API tokens
dbward server token create --user alice --role developer --data dbward.db
dbward server token create --user bob --role admin --data dbward.db

# 3. Copy signing.pub to client machines

# 4. Client executes (staging — auto-approved)
dbward execute "SELECT 1" \
  --server http://server:3000 \
  --token "dbw_..." \
  --public-key signing.pub \
  --database-url "postgres://..."

# 5. Client executes (production — requires approval)
dbward execute "DELETE FROM old_data" \
  --server http://server:3000 \
  --token "dbw_..." \
  --public-key signing.pub \
  --database-url "postgres://..." \
  --environment production
# → "Request abc123 requires approval."
# → Polls until approved...

# 6. Another team member approves
dbward approve abc123 \
  --server http://server:3000 \
  --token "dbw_..."
# → Original CLI automatically verifies token and executes
```

### MCP Mode (AI agents)

Add to your MCP client configuration:

```json
{
  "mcpServers": {
    "dbward": {
      "command": "dbward",
      "args": ["mcp"],
      "env": {
        "DBWARD_DATABASE_URL": "postgres://user:pass@localhost:5432/mydb"
      }
    }
  }
}
```

With server mode (production safety):

```json
{
  "mcpServers": {
    "dbward": {
      "command": "dbward",
      "args": [
        "mcp",
        "--server", "http://server:3000",
        "--token", "dbw_...",
        "--public-key", "/path/to/signing.pub"
      ],
      "env": {
        "DBWARD_DATABASE_URL": "postgres://...",
        "DBWARD_ENV": "production"
      }
    }
  }
}
```

**MCP Tools (8 in server mode):**

| Tool | Description |
|---|---|
| `dbward_migrate_status` | Show migration status |
| `dbward_migrate_up` | Apply pending migrations |
| `dbward_migrate_down` | Rollback migrations |
| `dbward_migrate_create` | Create migration file |
| `dbward_execute_query` | Execute SQL (SELECT/DML) |
| `dbward_audit_search` | Search audit log |
| `dbward_check_request` | Check approval status (server mode) |
| `dbward_resume_execution` | Execute after approval (server mode) |

In server mode, mutating operations on production return immediately with a request ID instead of blocking. The AI agent can check status and resume execution after human approval.

## CLI Reference

```
dbward [OPTIONS] <COMMAND>

Commands:
  migrate   Run database migrations (up/down/status/create)
  execute   Execute a SQL query
  mcp       Start MCP stdio server
  server    Start/manage the HTTP server
  approve   Approve a pending request
  reject    Reject a pending request
  audit     Search audit log

Global Options:
  --config <PATH>          Config file [default: dbward.toml]
  --database-url <URL>     Database URL [env: DBWARD_DATABASE_URL]
  --environment <ENV>      Environment [env: DBWARD_ENV]
  --role <ROLE>            Role (admin/developer/readonly) [env: DBWARD_ROLE]
  --server <URL>           Server URL for approval mode [env: DBWARD_SERVER_URL]
  --token <TOKEN>          API token [env: DBWARD_SERVER_TOKEN]
  --public-key <PATH>      Server public key [env: DBWARD_PUBLIC_KEY]
```

## REST API

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | No | Health check |
| GET | `/api/public-key` | No | Ed25519 public key (32 bytes) |
| GET | `/api/requests` | Yes | List requests |
| POST | `/api/requests` | Yes | Create request |
| GET | `/api/requests/:id` | Yes | Get request (includes token if approved) |
| POST | `/api/requests/:id/approve` | Yes | Approve (requester ≠ approver) |
| POST | `/api/requests/:id/reject` | Yes | Reject (admin or requester only) |
| POST | `/api/requests/:id/complete` | Yes | Report execution result |
| GET | `/api/audit` | Yes | Audit log |

## Security

- **Signed execution tokens** — Ed25519 asymmetric keys. Server signs, client verifies. Token includes SHA-256 hash of the approved SQL — you can't approve one query and execute another.
- **Token replay prevention** — Completed requests don't issue new tokens.
- **Multi-statement rejection** — Prevents SQL injection via statement chaining.
- **RBAC** — admin (all), developer (migrate + execute), readonly (SELECT only).
- **Network isolation** — Server has no database credentials. Can run in a separate network zone.
- **API token auth** — SHA-256 hashed with prefix-based O(1) lookup.

## Database Support

| Database | Status |
|---|---|
| PostgreSQL | ✅ Supported |
| MySQL | ✅ Supported |

Database is auto-detected from the URL scheme (`postgres://` or `mysql://`).

## Development

```bash
# Prerequisites: Rust, Docker

# Start dev database
docker compose up -d

# Run tests (requires Docker for testcontainers)
cargo test --workspace

# Build
cargo build --release
```

## License

Apache-2.0 / MIT (dual-licensed)
