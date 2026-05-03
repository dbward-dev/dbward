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
  init      Interactive setup wizard (creates dbward.toml, tests DB connection)
  login     OIDC login via browser (or --device for headless environments)
  logout    Revoke tokens and delete local credentials
  whoami    Show current identity, role, and token expiry
  migrate   Run database migrations (up/down/status/create)
  execute   Execute a SQL query (--emergency --reason for break-glass)
  mcp       Start MCP stdio server
  server    Start/manage the HTTP server (start, token create/revoke)
  approve   Approve a pending request
  reject    Reject a pending request
  list      List pending/recent requests
  resume    Resume execution after approval
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
- **Writable CTE detection** — `WITH x AS (DELETE FROM ...) SELECT ...` is classified as DML, not SELECT. Prevents readonly RBAC bypass.
- **RBAC** — admin (all), developer (migrate + execute), readonly (SELECT only).
- **Network isolation** — Server has no database credentials. Can run in a separate network zone.
- **API token auth** — SHA-256 hashed with prefix+hash composite lookup.
- **OIDC auth** — JWT verification with JWKS caching, RS256/ES256, PKCE for CLI flows.
- **Direct mode restriction** — Only allowed for `development` environment. Staging/production require `--server`.

## Database Support

| Database | Status |
|---|---|
| PostgreSQL | ✅ Supported |
| MySQL | ✅ Supported |

Database is auto-detected from the URL scheme (`postgres://` or `mysql://`).

## OIDC Authentication

For teams using Google, Okta, OneLogin, Auth0, Keycloak, or K8s ServiceAccounts:

```bash
# Login via browser
dbward login

# Login without browser (SSH, containers)
dbward login --device

# Check identity
dbward whoami

# Logout (revokes tokens)
dbward logout
```

Configure in `dbward.toml`:

```toml
[server.oidc]
issuer = "https://accounts.google.com"
client_id = "xxx.apps.googleusercontent.com"
```

Server-side role mapping in `dbward-server.toml`:

```toml
[auth]
mode = "both"  # "oidc", "token", or "both"

[auth.oidc]
issuer = "https://accounts.google.com"
client_id = "xxx.apps.googleusercontent.com"
default_role = "readonly"

[[auth.oidc.role_mappings]]
subject = "alice@example.com"
role = "admin"

[[auth.oidc.role_mappings]]
claim = "groups"
value = "db-developers"
role = "developer"
```

## Webhook Notifications

Server sends webhooks on approval events:

```toml
# dbward-server.toml
[[webhooks]]
url = "https://hooks.slack.com/services/T.../B.../xxx"
format = "slack"

[[webhooks]]
url = "https://internal.example.com/dbward"
format = "generic"
secret = "whsec_xxxx"  # HMAC-SHA256 signature
```

Events: `request_created`, `request_approved`, `request_rejected`, `request_completed`, `break_glass`.

## Break-Glass (Emergency Bypass)

For incidents when no approver is available:

```bash
dbward execute "SELECT pg_terminate_backend(12345)" \
  --emergency --reason "connection pool exhausted at 3am"
```

- Skips approval, issues token immediately
- Fires `break_glass` webhook (🚨 in Slack)
- Reason recorded in audit log
- Admin and Developer only (Readonly cannot use)

## Development

### Docker Compose (recommended)

Starts PostgreSQL, Keycloak (OIDC), and dbward-server:

```bash
# Start all services
docker compose up -d --build

# Create API tokens
docker compose exec dbward-server \
  dbward server token create --user alice --role admin --data /data/dbward.db
docker compose exec dbward-server \
  dbward server token create --user bob --role developer --data /data/dbward.db

# Run CLI commands (as bob)
docker compose run --rm \
  -e DBWARD_SERVER_TOKEN=<bob-token> \
  dbward execute "SELECT version()"

# Approve (as alice)
docker compose run --rm \
  -e DBWARD_SERVER_TOKEN=<alice-token> \
  dbward approve <request-id>

# Resume (as bob)
docker compose run --rm \
  -e DBWARD_SERVER_TOKEN=<bob-token> \
  dbward resume <request-id>

# Tear down
docker compose down -v
```

### Local Development

```bash
# Prerequisites: Rust 1.88+, Docker (for tests)

# Run tests
cargo test --workspace

# Run tests including DB integration (requires Docker)
cargo test --workspace -- --include-ignored

# Build
cargo build --release
```

## License

Apache-2.0 / MIT (dual-licensed)
