# dbward

DB operations workflow + approval engine. Safe database operations for teams and AI agents.

```
dbward execute "SELECT * FROM users"              # Transparent — agent executes
dbward execute "DELETE FROM old" --database prod   # Production requires approval
dbward mcp                                         # MCP server for AI agents
```

## Why dbward?

Tools like dbmate and golang-migrate handle migrations but lack **approval workflows, audit logging, and access control**. Enterprise tools like Bytebase require heavy infrastructure. dbward fills the gap:

- **Zero DB credentials on developer machines** — only the agent touches your database
- **Approval flow built-in** — production changes require human approval
- **MCP-first** — AI agents operate under the same controls as humans
- **Cryptographic enforcement** — Ed25519 signed execution tokens bind approval to exact SQL + database

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│              dbward client (CLI / MCP)                    │
│  No DB credentials — sends requests, receives results    │
└──────────┬───────────────────────────────────────────────┘
           │ REST API
           ▼
┌─────────────────────────────────────────────────────────┐
│                    dbward server                         │
│  Approval state (SQLite) │ Policy engine │ Audit log     │
│  Ed25519 token signing   │ OIDC/API auth │ Webhooks      │
│  NO database credentials                                 │
└──────────┬───────────────────────────────────────────────┘
           │ Agent polls (outbound HTTPS)
           ▼
┌─────────────────────────────────────────────────────────┐
│                    dbward agent                           │
│  DB credentials here only │ Executes approved operations  │
│  Token verification (public key) │ Multiple DB support     │
└──────────┬───────────────────────────────────────────────┘
           │
           ▼
      Target Database (PostgreSQL / MySQL)
```

**Key principle**: The client requests. The server decides. The agent executes. No component has more access than it needs.

## Quick Start

### Local Development

```bash
cargo install dbward

# Configure
cat > dbward.toml << EOF
default_database = "app"
[server]
url = "http://localhost:3000"
EOF

# Start local server + agent
dbward dev up

# In another terminal:
dbward migrate create add_users_table
dbward migrate up
dbward execute "SELECT * FROM users"
```

### Team Setup (Production)

```bash
# 1. Deploy dbward-server (any network)
dbward server start

# 2. Deploy dbward-agent (DB-reachable network)
dbward agent start --config dbward-agent.toml

# 3. Developers just use CLI (no DB access needed)
dbward login
dbward execute "DELETE FROM old_data" --database primary
# → "Request abc123 requires approval."

# 4. Approver
dbward approve abc123
# → Agent automatically executes, result available

# 5. Developer gets result
dbward resume abc123
```

### MCP Mode (AI agents)

Add to your MCP client configuration:

```json
{
  "mcpServers": {
    "dbward": {
      "command": "dbward",
      "args": ["mcp"]
    }
  }
}
```

With server URL configured (team/production):

```json
{
  "mcpServers": {
    "dbward": {
      "command": "dbward",
      "args": [
        "mcp",
        "--server", "http://server:3000",
        "--token", "dbw_..."
      ],
      "env": {
        "DBWARD_ENV": "production"
      }
    }
  }
}
```

**MCP Tools:**

| Tool | Description |
|---|---|
| `dbward_migrate_status` | Show migration status |
| `dbward_migrate_up` | Apply pending migrations |
| `dbward_migrate_down` | Rollback migrations |
| `dbward_migrate_create` | Create migration file |
| `dbward_execute_query` | Execute SQL (SELECT/DML) |
| `dbward_audit_search` | Search audit log |
| `dbward_check_request` | Check approval/execution status |
| `dbward_get_result` | Get execution result |

Mutating operations on production return immediately with a request ID. The AI agent can poll status and retrieve results after the agent executes the approved query.

## CLI Reference

```
dbward [OPTIONS] <COMMAND>

Commands:
  init      Interactive setup wizard (creates dbward.toml, tests server connection)
  login     OIDC login via browser (or --device for headless environments)
  logout    Revoke tokens and delete local credentials
  whoami    Show current identity, role, and token expiry
  migrate   Run database migrations (up/down/status/create)
  execute   Execute a SQL query (--emergency --reason for break-glass)
  mcp       Start MCP stdio server
  server    Start/manage the HTTP server (start, token create/revoke)
  agent     Start the agent (polls server, executes on target DB)
  dev       Development helpers (dev up — local server + agent)
  approve   Approve a pending request
  reject    Reject a pending request
  list      List pending/recent requests
  resume    Resume execution after approval
  audit     Search audit log

Global Options:
  --config <PATH>          Config file [default: dbward.toml]
  --database <NAME>        Named database target [env: DBWARD_DATABASE]
  --environment <ENV>      Environment [env: DBWARD_ENV]
  --role <ROLE>            Role (admin/developer/readonly) [env: DBWARD_ROLE]
  --server <URL>           Server URL [env: DBWARD_SERVER_URL]
  --token <TOKEN>          API token [env: DBWARD_SERVER_TOKEN]
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
| POST | `/api/requests/:id/complete` | Yes | Report execution result (agent) |
| GET | `/api/requests/:id/result` | Yes | Get execution result |
| GET | `/api/agent/poll` | Yes | Agent polls for claimable tasks |
| POST | `/api/agent/claim/:id` | Yes | Agent claims a task |
| GET | `/api/audit` | Yes | Audit log |

## Security

- **Zero-trust client model** — developer machines never have DB credentials. Only the agent connects to databases.
- **Signed execution tokens** — Ed25519 asymmetric keys. Server signs, agent verifies. Token includes SHA-256 hash of the approved SQL + target database — you can't approve one query and execute another.
- **Token replay prevention** — Completed requests don't issue new tokens.
- **Multi-statement rejection** — Prevents SQL injection via statement chaining.
- **Writable CTE detection** — `WITH x AS (DELETE FROM ...) SELECT ...` is classified as DML, not SELECT. Prevents readonly RBAC bypass.
- **RBAC** — admin (all), developer (migrate + execute), readonly (SELECT only).
- **Network isolation** — Server has no database credentials. Agent connects outbound to server (no inbound ports needed).
- **API token auth** — SHA-256 hashed with prefix+hash composite lookup.
- **OIDC auth** — JWT verification with JWKS caching, RS256/ES256, PKCE for CLI flows.

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

- Skips approval, issues token immediately — agent executes without waiting
- Fires `break_glass` webhook (🚨 in Slack)
- Reason recorded in audit log
- Admin and Developer only (Readonly cannot use)

## Development

### Docker Compose (recommended)

Starts PostgreSQL, Keycloak (OIDC), dbward-server, and dbward-agent:

```bash
# Start all services (server + agent + PostgreSQL + Keycloak)
docker compose up -d --build

# Create API tokens
docker compose exec dbward-server \
  dbward server token create --user alice --role admin --data /data/dbward.db
docker compose exec dbward-server \
  dbward server token create --user bob --role developer --data /data/dbward.db

# Run CLI commands (as bob — no DB credentials needed)
docker compose run --rm \
  -e DBWARD_SERVER_TOKEN=<bob-token> \
  dbward-cli execute "SELECT version()"

# Approve (as alice)
docker compose run --rm \
  -e DBWARD_SERVER_TOKEN=<alice-token> \
  dbward-cli approve <request-id>

# Get result (as bob)
docker compose run --rm \
  -e DBWARD_SERVER_TOKEN=<bob-token> \
  dbward-cli resume <request-id>

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
