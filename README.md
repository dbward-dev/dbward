# dbward

**Approval workflows and audit logs for your production database.**

Stop accidents before they hit production. Add approval gates, audit trails, and AI agent guardrails to every database operation — in a single binary with zero external dependencies.

```bash
$ dbward execute "UPDATE users SET active = false WHERE last_login < '2025-01-01'"
⚠ Request req_7f3a created (production × execute_query)
  Requires 1 approval.

$ dbward request approve req_7f3a --comment "Confirmed with product team"
✓ Approved. Executing on agent-prod-01...
✓ 3 rows affected (12ms)
```

## Highlights

- 🔐 **Approval workflows** — multi-step, conditional auto-approve, TOML policy engine
- 📋 **Audit logs** — tamper-evident hash chain, 24 event types, SQL redaction
- 🤖 **MCP-native** — 15 tools, 6 prompts, elicitation support. AI agents operate safely
- ⚡ **Single binary** — Rust + embedded SQLite. No Docker, no external DB
- 🔒 **Agent isolation** — DB credentials never leave the agent. CLI/AI never touch your database directly
- 🆓 **Free** — approval, audit, MCP, break-glass all included. [Apache-2.0 / MIT](LICENSE-APACHE)

## How it compares

| | dbward Free | dbward Pro | Bytebase | dbmate |
|---|---|---|---|---|
| Approval workflows | ✅ (5 rules) | Unlimited | Enterprise only | — |
| Audit logs | ✅ (hash chain) | + export | Pro (limited) | — |
| MCP / AI agents | ✅ 15 tools | ✅ | Add-on | — |
| SSO (OIDC) | — | ✅ | Enterprise | — |
| DB connections | 3 | Unlimited | Unlimited | 1 |
| Deploy | Single binary | Single binary | Docker + PostgreSQL | Single binary |
| Price | $0 | $79/mo (waitlist) | $20/user/mo+ | Free |

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│              dbward client (CLI / MCP)                    │
│  No DB credentials — sends requests, receives results    │
└──────────┬───────────────────────────────────────────────┘
           │ REST API
           ▼
┌─────────────────────────────────────────────────────────┐
│                    dbward server                          │
│  Approval engine │ Policy engine │ Audit log (hash chain) │
│  Ed25519 token signing │ OIDC/API auth │ Webhooks        │
│  In-memory result relay │ NO database credentials        │
└──────────┬───────────────────────────────────────────────┘
           │ Agent polls (outbound HTTPS)
           ▼
┌─────────────────────────────────────────────────────────┐
│                    dbward agent                           │
│  DB credentials here only │ Executes approved operations  │
│  Token verification (Ed25519) │ Multiple DB support       │
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
dbward dev --database-url "postgres://localhost/myapp"
```

That's it. You now have approval workflows and audit logs for your local database.

### Team Setup

```bash
# 1. Deploy dbward-server (any network)
dbward server start --config dbward-server.toml

# 2. Deploy dbward-agent (DB-reachable network)
dbward agent --config dbward-agent.toml

# 3. Developers use CLI (no DB access needed)
dbward execute "DELETE FROM old_data" --database primary
# → "Request req_abc123 requires approval."

# 4. Approver
dbward request approve req_abc123

# 5. Developer gets result
dbward request resume req_abc123
```

### MCP Mode (AI agents)

```json
{
  "mcpServers": {
    "dbward": {
      "command": "dbward",
      "args": ["mcp", "--config", "dbward.toml"]
    }
  }
}
```

**MCP Tools (15):**

| Tool | Description |
|---|---|
| `dbward_execute_query` | Execute SQL (SELECT/DML) via approval workflow |
| `dbward_migrate_status` | Show migration status |
| `dbward_migrate_up` | Apply pending migrations |
| `dbward_migrate_down` | Rollback migrations |
| `dbward_migrate_create` | Create migration file (local) |
| `dbward_check_request` | Check request status |
| `dbward_get_result` | Get execution result |
| `dbward_list_pending` | List pending approval requests |
| `dbward_who_can_approve` | Show who can approve a request |
| `dbward_find_similar_requests` | Find similar past requests |
| `dbward_preview_impact` | EXPLAIN query before execution |
| `dbward_explain_policy_failure` | Explain why approval is needed |
| `dbward_list_schemas` | List database schemas/tables |
| `dbward_describe_table` | Describe table columns |
| `dbward_compare_schema` | Show pending migration SQL |

**MCP Prompts (6):** `review_migration`, `explain_request`, `draft_migration`, `draft_rollback`, `summarize_audit_trail`, `prepare_approval_comment`

**Elicitation:** On production operations, dbward asks the AI client for a reason before proceeding (if the client supports MCP elicitation).

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

The server never writes results to disk — it relays them in-memory with a 10-minute TTL.

## Policy Engine

Defined in `dbward-server.toml` (synced to SQLite on startup) or managed via REST API.

### Workflows

Control whether operations require approval:

```toml
[[workflows]]
database = "*"
environment = "production"
operations = ["execute_query", "migrate_up", "migrate_down"]

[[workflows.steps]]
type = "approval"
min_approvals = 1
allowed_roles = ["admin"]
```

### Execution Policies

Control re-execution limits (rate limiting):

```toml
[[execution_policies]]
database = "primary"
environment = "production"
max_executions = 10
execution_window_secs = 3600
retry_on_failure = false
```

### Result Policies (Pro)

Control who can access results and storage:

```toml
[[result_policies]]
database = "primary"
environment = "production"
delivery_mode = "stream"
access = ["requester", "admin"]
```

### Notification Policies (Pro)

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
  init          Interactive setup wizard
  login         OIDC login (browser or --device for headless)
  logout        Revoke tokens and delete credentials
  whoami        Show current identity and role
  migrate       Run migrations (up/down/status/create)
  execute       Execute SQL (--emergency --reason for break-glass)
  audit         Search audit log (--verify for hash chain check)
  mcp           Start MCP stdio server
  server        Server management (start, token create/revoke)
  agent         Start the agent
  dev           Start local dev server + agent
  request       Manage requests:
    list          List requests (--pending-for-me, --status)
    show          Show request detail
    approve       Approve a pending request
    reject        Reject a pending request
    resume        Dispatch and wait for result
    cancel        Cancel a pending request

Global Options:
  --config <PATH>          Config file [default: dbward.toml]
  --database <NAME>        Target database [env: DBWARD_DATABASE]
  --environment <ENV>      Environment [env: DBWARD_ENV]
```

## REST API

### Core

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Health check |
| GET | `/ready` | Readiness check |
| GET | `/metrics` | Prometheus metrics |
| GET | `/api/public-key` | Ed25519 public key |

### Requests

| Method | Path | Description |
|---|---|---|
| GET | `/api/requests` | List requests (filter by status/database/environment/user) |
| POST | `/api/requests` | Create request |
| GET | `/api/requests/:id` | Get request detail |
| POST | `/api/requests/:id/approve` | Approve (requester ≠ approver) |
| POST | `/api/requests/:id/reject` | Reject |
| POST | `/api/requests/:id/dispatch` | Dispatch for on-demand execution |
| POST | `/api/requests/:id/cancel` | Cancel a pending request |
| GET | `/api/requests/:id/result/stream` | Long-poll for result |
| GET | `/api/requests/:id/result/content` | Get stored result content |

### Agent

| Method | Path | Description |
|---|---|---|
| POST | `/api/agent/poll` | Poll for dispatched jobs |
| POST | `/api/agent/jobs/:id/claim` | Claim a job (lease) |
| POST | `/api/agent/jobs/:id/heartbeat` | Extend lease |
| POST | `/api/agent/jobs/:id/result` | Submit execution result |

### Policies (admin)

| Method | Path | Description |
|---|---|---|
| GET/POST | `/api/workflows` | List / create workflows |
| GET/PUT/DELETE | `/api/workflows/:id` | Get / update / delete |
| GET/POST | `/api/execution-policies` | List / create execution policies |
| GET/PUT/DELETE | `/api/execution-policies/:id` | Get / update / delete |
| GET/POST | `/api/result-policies` | List / create result policies (Pro) |
| GET/PUT/DELETE | `/api/result-policies/:id` | Get / update / delete (Pro) |
| GET/POST | `/api/notification-policies` | List / create notification policies (Pro) |
| GET/PUT/DELETE | `/api/notification-policies/:id` | Get / update / delete (Pro) |

### Audit

| Method | Path | Description |
|---|---|---|
| GET | `/api/audit` | Audit log (legacy format) |
| GET | `/api/audit/events` | Audit events (full: category/type/outcome filters) |
| GET | `/api/audit/verify` | Verify hash chain integrity |

### Results

| Method | Path | Description |
|---|---|---|
| GET | `/api/results` | List stored results |
| GET | `/api/storage-config` | Get result storage configuration |

## Security

- **Zero-trust client** — developer machines never have DB credentials
- **Signed execution tokens** — Ed25519. Token includes SHA-256 hash of SQL + target database
- **Token replay prevention** — executed/failed requests don't issue new tokens
- **Multi-statement rejection** — prevents SQL injection via statement chaining
- **Writable CTE detection** — `WITH x AS (DELETE ...) SELECT ...` classified as DML
- **RBAC** — admin (all), developer (migrate + execute), readonly (SELECT only)
- **Network isolation** — server has no DB credentials; agent connects outbound only
- **API token auth** — SHA-256 hashed, prefix+hash composite lookup
- **OIDC auth** — JWT verification with JWKS caching, RS256/ES256, PKCE for CLI (Pro)
- **Audit hash chain** — SHA-256 chain linking all events, tamper-evident

## Database Support

| Database | Status |
|---|---|
| PostgreSQL | ✅ Supported |
| MySQL | ✅ Supported |

Auto-detected from URL scheme (`postgres://` or `mysql://`).

## Authentication

### API Tokens (Free)

```bash
dbward server token create --user alice --role admin --data dbward.db
# → dbw_f9a549aa...
```

### OIDC (Pro)

```bash
dbward login              # Browser-based (PKCE)
dbward login --device     # Headless (SSH, containers)
dbward whoami             # Check identity
dbward logout             # Revoke + delete tokens
```

## Webhook Notifications

```toml
# dbward-server.toml
[[webhooks]]
url = "https://hooks.slack.com/services/T.../B.../xxx"
format = "slack"

[[webhooks]]
url = "https://internal.example.com/dbward"
format = "generic"
secret = "whsec_xxxx"  # HMAC-SHA256 in X-Dbward-Signature header
```

Events: `request_created`, `request_approved`, `request_rejected`, `request_executed`, `break_glass`.

Free: up to 3 webhook destinations (global). Pro: unlimited + per-database routing via notification policies.

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

[databases.app]
# No DB URL here — agent handles connections
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
mode = "token"  # "oidc", "token", or "both"

[[webhooks]]
url = "https://hooks.slack.com/services/..."
format = "slack"

[[workflows]]
database = "*"
environment = "production"
operations = ["execute_query", "migrate_up", "migrate_down"]

[[workflows.steps]]
type = "approval"
min_approvals = 1
allowed_roles = ["admin"]

[[execution_policies]]
database = "*"
environment = "production"
max_executions = 10
execution_window_secs = 3600
```

## Free / Pro

| | Free | Pro |
|---|---|---|
| Workflow rules | 5 | Unlimited |
| Execution policies | 3 | Unlimited |
| DB connections | 3 | Unlimited |
| Agents | 3 | Unlimited |
| Webhooks | 3 | Unlimited |
| Approval + Audit + MCP + Break-glass | ✅ | ✅ |
| OIDC / SSO | — | ✅ |
| Group-based authorization | — | ✅ |
| Result policies (access control) | — | ✅ |
| Notification policies (routing) | — | ✅ |
| Result sharing (share-with) | — | ✅ |
| Audit export (S3/Datadog) | — | ✅ (coming) |

Safety features are always free. You pay for organizational complexity.

**Pro waitlist:** https://dbward.dev/waitlist

## Migration File Format (dbmate-compatible)

```sql
-- migrate:up
CREATE TABLE users (id SERIAL PRIMARY KEY, name TEXT NOT NULL);

-- migrate:down
DROP TABLE users;
```

## Metrics

`GET /metrics` — Prometheus text format, unauthenticated. Deploy behind internal network.

Key alerts:
- `dbward_agents_active == 0` → no agent running
- `dbward_requests_oldest_pending_seconds > 3600` → stuck request
- `rate(dbward_break_glass_total[5m]) > 0` → emergency bypass used

## Development

```bash
# Prerequisites: Rust 1.88+, Docker (for integration tests)
cargo test --workspace
cargo build --release
```

## License

Apache-2.0 / MIT (dual-licensed)
