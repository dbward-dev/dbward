# dbward

**Approval workflows and audit logs for your production database.**

Stop accidents before they hit production. Add approval gates, audit trails, and AI agent guardrails to every database operation — in a single binary with zero external dependencies.

```bash
$ dbward execute "UPDATE users SET active = false WHERE last_login < '2025-01-01'"
⚠ Request req_7f3a created (production × execute_query)
  Requires 1 approval.

$ dbward approve req_7f3a --reason "Confirmed with product team"
✓ Approved. Executing on agent-prod-01...
✓ 3 rows affected (12ms)
```

## Highlights

- 🔐 **Approval workflows** — multi-step, conditional auto-approve, TOML policy engine
- 📋 **Audit logs** — every operation recorded (who, what, when, which DB)
- 🤖 **MCP-native** — AI agents operate safely; no execution without approval
- ⚡ **Single binary** — Rust + embedded SQLite. No Docker, no external DB
- 🔒 **Agent isolation** — DB credentials never leave the agent. CLI/AI never touch your database directly
- 🆓 **Free** — all features included, up to 3 workflow rules. [Apache-2.0 / MIT](LICENSE-APACHE)

## How it compares

| | dbward | Bytebase | dbmate |
|---|---|---|---|
| Approval workflows | ✅ Free | Enterprise only | — |
| Audit logs | ✅ Free | Pro (limited) | — |
| MCP / AI agents | ✅ Native | Add-on | — |
| SSO (OIDC) | ✅ Free | Enterprise | — |
| Deploy | Single binary | Docker + PostgreSQL | Single binary |
| Price | Free (3 rules) | $20/user/mo+ | Free |

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
│  In-memory result relay  │ NO database credentials       │
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

```bash
# Install
curl -fsSL https://dbward.dev/install.sh | sh

# Initialize config
dbward init

# Start local server + agent (development mode)
dbward dev up
```

That's it. You now have approval workflows and audit logs for your local database.

### Docker Compose (team setup)

Starts PostgreSQL, dbward-server, and dbward-agent:

```bash
# Start all services
docker compose up -d --build

# Create API tokens
docker compose exec dbward-server \
  dbward server token create --user alice --role admin --data /data/dbward.db
docker compose exec dbward-server \
  dbward server token create --user bob --role developer --data /data/dbward.db

# Execute a query (as bob)
docker compose run --rm \
  -e DBWARD_SERVER_TOKEN=<bob-token> \
  alice execute "SELECT version()"

# If approval is required, approve (as alice)
docker compose run --rm \
  -e DBWARD_SERVER_TOKEN=<alice-token> \
  alice request approve <request-id>

# Get result (as bob)
docker compose run --rm \
  -e DBWARD_SERVER_TOKEN=<bob-token> \
  alice request resume <request-id>

# Tear down
docker compose down -v
```

### Team Setup

```bash
# 1. Deploy dbward-server (any network)
dbward server start --config dbward-server.toml

# 2. Deploy dbward-agent (DB-reachable network)
dbward agent --config dbward-agent.toml

# 3. Developers use CLI (no DB access needed)
dbward login
dbward execute "DELETE FROM old_data" --database primary
# → "Request abc123 requires approval."

# 4. Approver
dbward request approve abc123

# 5. Developer gets result
dbward request resume abc123
```

### MCP Mode (AI agents)

```json
{
  "mcpServers": {
    "dbward": {
      "command": "dbward",
      "args": ["mcp"],
      "env": {
        "DBWARD_SERVER_URL": "http://localhost:3000",
        "DBWARD_SERVER_TOKEN": "dbw_..."
      }
    }
  }
}
```

**MCP Tools (7):**

| Tool | Description |
|---|---|
| `dbward_execute_query` | Execute SQL (SELECT/DML) via agent |
| `dbward_migrate_status` | Show migration status |
| `dbward_migrate_up` | Apply pending migrations |
| `dbward_migrate_down` | Rollback migrations |
| `dbward_migrate_create` | Create migration file (local only) |
| `dbward_check_request` | Check request status |
| `dbward_get_result` | Get execution result |

Mutating operations on production return a request ID. The AI agent polls status and retrieves results after approval + agent execution.

## On-Demand Execution

dbward uses **on-demand execution**: the agent does not execute on approval. Instead, the client explicitly dispatches the request when ready to receive the result.

```
1. Client creates request → server evaluates policy → pending / auto_approved
2. (If pending) Human approves via CLI
3. Client dispatches (`dbward request resume <id>`) → server marks as "dispatched"
4. Agent polls, claims, executes on DB → returns result to server
5. Server relays result in-memory to waiting client (long poll)
6. Client receives result and saves locally (~/.dbward/results/<id>.json)
```

The server never writes results to disk — it relays them in-memory via Notify+Mutex channels with a 10-minute TTL.

## Policy Engine

Four policy types, all scoped to database × environment. Defined in `dbward-server.toml` (synced to SQLite on startup) or managed via REST API (admin only).

### Workflows

Control whether operations require approval:

```toml
[[workflows]]
database = "*"
environment = "production"

[[workflows.steps]]
type = "approval"
min_approvals = 1
allowed_roles = ["admin"]
```

### Execution Policies

Control re-execution limits:

```toml
[[execution_policies]]
database = "primary"
environment = "production"
max_executions = 1
execution_window_secs = 86400
retry_on_failure = false
```

### Result Policies

Control who can access results:

```toml
[[result_policies]]
database = "primary"
environment = "production"
delivery_mode = "stream"
access = ["requester", "admin"]
```

### Notification Policies

Route webhooks per database × environment:

```toml
[[notification_policies]]
database = "primary"
environment = "production"

[[notification_policies.webhooks]]
url = "https://hooks.slack.com/services/..."
format = "slack"
```

## CLI Reference

```
dbward [OPTIONS] <COMMAND>

Commands:
  init        Interactive setup wizard
  login       OIDC login (browser or --device for headless)
  logout      Revoke tokens and delete credentials
  whoami      Show current identity and role
  migrate     Run migrations (up/down/status/create)
  execute     Execute SQL (--emergency --reason for break-glass)
  approve     Approve a pending request
  reject      Reject a pending request
  list        List requests
  resume      Dispatch and wait for result
  result      Show a previously saved local result
  mcp         Start MCP stdio server
  server      Server management (start, token create/revoke)
  agent       Start the agent

Global Options:
  --config <PATH>          Config file [default: dbward.toml]
  --database <NAME>        Target database [env: DBWARD_DATABASE]
  --environment <ENV>      Environment [env: DBWARD_ENV]
```

## REST API

### Core

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | No | Health check |
| GET | `/api/public-key` | No | Ed25519 public key (32 bytes) |

### Requests

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/requests` | Yes | List requests |
| POST | `/api/requests` | Yes | Create request |
| GET | `/api/requests/:id` | Yes | Get request detail |
| POST | `/api/requests/:id/approve` | Yes | Approve (requester ≠ approver) |
| POST | `/api/requests/:id/reject` | Yes | Reject (admin or requester) |
| POST | `/api/requests/:id/complete` | Yes | Report completion |
| POST | `/api/requests/:id/dispatch` | Yes | Dispatch for on-demand execution |
| GET | `/api/requests/:id/result/stream` | Yes | Long-poll for result |

### Agent

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/api/agent/poll` | Yes | Poll for dispatched jobs |
| POST | `/api/agent/jobs/:id/claim` | Yes | Claim a job (lease) |
| POST | `/api/agent/jobs/:id/result` | Yes | Submit execution result |

### Policies (admin only for mutations)

| Method | Path | Auth | Description |
|---|---|---|---|
| GET/POST | `/api/workflows` | Yes | List / create workflows |
| GET/PUT/DELETE | `/api/workflows/:id` | Yes | Get / update / delete workflow |
| GET/POST | `/api/execution-policies` | Yes | List / create execution policies |
| GET/PUT/DELETE | `/api/execution-policies/:id` | Yes | Get / update / delete |
| GET/POST | `/api/result-policies` | Yes | List / create result policies |
| GET/PUT/DELETE | `/api/result-policies/:id` | Yes | Get / update / delete |
| GET/POST | `/api/notification-policies` | Yes | List / create notification policies |
| GET/PUT/DELETE | `/api/notification-policies/:id` | Yes | Get / update / delete |

### Audit

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/audit` | Yes | Audit log (last 100 entries) |

## Security

- **Zero-trust client** — developer machines never have DB credentials
- **Signed execution tokens** — Ed25519. Token includes SHA-256 hash of SQL + target database
- **Token replay prevention** — executed/failed requests don't issue new tokens
- **Multi-statement rejection** — prevents SQL injection via statement chaining
- **Writable CTE detection** — `WITH x AS (DELETE ...) SELECT ...` classified as DML
- **RBAC** — admin (all), developer (migrate + execute), readonly (SELECT only)
- **Network isolation** — server has no DB credentials; agent connects outbound only
- **API token auth** — SHA-256 hashed, prefix+hash composite lookup
- **OIDC auth** — JWT verification with JWKS caching, RS256/ES256, PKCE for CLI

## Database Support

| Database | Status |
|---|---|
| PostgreSQL | ✅ Supported |
| MySQL | ✅ Supported |

Auto-detected from URL scheme (`postgres://` or `mysql://`).

## OIDC Authentication

```bash
dbward login              # Browser-based
dbward login --device     # Headless (SSH, containers)
dbward whoami             # Check identity
dbward logout             # Revoke + delete tokens
```

Client config (`dbward.toml`):

```toml
[server.oidc]
issuer = "https://accounts.google.com"
client_id = "xxx.apps.googleusercontent.com"
```

Server config (`dbward-server.toml`):

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

```toml
# dbward-server.toml (global)
[[webhooks]]
url = "https://hooks.slack.com/services/T.../B.../xxx"
format = "slack"

[[webhooks]]
url = "https://internal.example.com/dbward"
format = "generic"
secret = "whsec_xxxx"  # HMAC-SHA256 in X-Dbward-Signature header
```

Events: `request_created`, `request_approved`, `request_rejected`, `request_completed`, `break_glass`.

Per-database routing is available via notification policies (see Policy Engine above).

## Break-Glass (Emergency Bypass)

```bash
dbward execute "SELECT pg_terminate_backend(12345)" \
  --emergency --reason "connection pool exhausted at 3am"
```

- Skips approval — agent executes immediately when dispatched
- Fires `break_glass` webhook (🚨 in Slack)
- Reason recorded in audit log
- Admin and Developer only

## Configuration

### Client (`dbward.toml`)

```toml
default_database = "app"
migrations_dir = "db/migrations"

[server]
url = "http://localhost:3000"
token = "dbw_..."

# Or use OIDC instead of token:
# [server.oidc]
# issuer = "https://accounts.google.com"
# client_id = "xxx.apps.googleusercontent.com"

[databases.app]
# migrations_dir = "custom/migrations"  # optional override
```

### Agent (`dbward-agent.toml`)

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
operations = ["execute_query", "migrate_up", "migrate_down", "migrate_status"]

[databases.primary]
url = "postgres://user:pass@db-primary:5432/app"

[databases.analytics]
url = "mysql://user:pass@db-analytics:3306/warehouse"
```

### Server (`dbward-server.toml`)

```toml
listen = "0.0.0.0:3000"
data = "dbward.db"

[auth]
mode = "both"

[auth.oidc]
issuer = "https://accounts.google.com"
client_id = "xxx.apps.googleusercontent.com"
default_role = "readonly"

[[auth.oidc.role_mappings]]
subject = "alice@example.com"
role = "admin"

[[webhooks]]
url = "https://hooks.slack.com/services/..."
format = "slack"

[[workflows]]
database = "*"
environment = "production"

[[workflows.steps]]
type = "approval"
min_approvals = 1

[[execution_policies]]
database = "*"
environment = "production"
max_executions = 1
execution_window_secs = 86400
retry_on_failure = false

[[result_policies]]
database = "*"
environment = "production"
delivery_mode = "stream"
access = ["requester", "admin"]
```

## Migration File Format (dbmate-compatible)

```sql
-- migrate:up
CREATE TABLE users (id SERIAL PRIMARY KEY, name TEXT NOT NULL);

-- migrate:down
DROP TABLE users;
```

## Development

```bash
# Prerequisites: Rust 1.88+, Docker (for integration tests)

cargo test --workspace
cargo test --workspace -- --include-ignored  # includes DB tests
cargo build --release
```

## License

Apache-2.0 / MIT (dual-licensed)
## Metrics

`GET /metrics` exposes Prometheus text format for external scraping.

- Deploy behind an internal network boundary. The endpoint is unauthenticated.
- Recommended scrape interval: `15s` to `60s`

Recommended alerts:

- `dbward_agents_active == 0`: critical
- `dbward_requests_oldest_pending_seconds > 3600`: warning
- `rate(dbward_agent_lease_expirations_total[5m]) > 0`: warning
- Increase in `dbward_break_glass_total`: info
- `rate(dbward_auth_failures_total[5m]) > 10`: warning
- `histogram_quantile(0.99, sum(rate(dbward_http_request_duration_seconds_bucket[5m])) by (le, route, method)) > 5`: warning
- `rate(dbward_webhook_deliveries_total{status="failed"}[5m]) > 0`: warning
