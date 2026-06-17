# dbward

> **Open-core project** — core components are [Apache-2.0](LICENSE-APACHE). Some features and pre-built binaries include code under the [dbward Commercial License](LICENSE-COMMERCIAL). See [License](#license) for details.

**Approval workflows and audit logs for your production database.**

Stop accidents before they hit production. Add approval gates, audit trails, and AI agent guardrails to every database operation — with standalone binaries and embedded SQLite. No external control-plane DB required.

```bash
$ dbward execute "UPDATE users SET active = false WHERE last_login < '2025-01-01'"
⚠ Request 7f3a2b01 created (production × execute_query)
  Requires 1 approval.

$ dbward request approve 7f3a2b01 --comment "Confirmed with product team"
✓ Approved. Executing on agent-prod-01...
✓ 3 rows affected (12ms)
```

## Highlights

- 🔐 **Approval workflows** — multi-step, conditional auto-approve, TOML policy engine
- 📋 **Audit logs** — tamper-evident hash chain, 24 event types, SQL redaction
- 🤖 **MCP-native** — 12 tools, 6 prompts, elicitation support. AI agents operate safely
- ⚡ **Standalone binaries** — CLI, server, and agent ship as self-contained Rust binaries with embedded SQLite. No external control-plane DB
- 🔒 **Agent isolation** — DB credentials never leave the agent. CLI/AI never touch your database directly
- 🆓 **Core features free** — approval, audit, MCP, break-glass all included under [Apache-2.0](LICENSE-APACHE). Team features (OIDC, group auth) require a [commercial license](LICENSE-COMMERCIAL)

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
└─────────────────────────────────────────────────────────┘
           ▲ Agent polls (outbound HTTPS)
           │
┌──────────┴───────────────────────────────────────────────┐
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

**Try the approval flow in 2 minutes (Docker):**

```bash
git clone https://github.com/dbward-dev/dbward.git && cd dbward/examples/quickstart
docker compose up -d
docker compose run --rm alice execute "SELECT version()" -e development
```

Then submit → approve → execute → audit. Full walkthrough: **[Quickstart with Docker](https://dbward.dev/docs/quickstart-docker/)**

**Quick smoke test (local install):**

```bash
curl -fsSL https://dbward.dev/install.sh | sh
dbward dev --database-url "postgres://user:pass@localhost:5432/mydb"
# In another terminal:
dbward --config ~/.dbward/dev/client.toml --database app execute "SELECT 1"
```

Dev mode auto-approves everything for fast iteration. See [Connect Your Database](https://dbward.dev/docs/quickstart-local/) for details.

## MCP (AI Agents)

> Full reference: [docs/reference/mcp.md](docs/reference/mcp.md)

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

**MCP Tools (12):**

| Tool | Description |
|---|---|
| `dbward_execute_query` | Execute SQL (SELECT/DML) via approval workflow |
| `dbward_migrate_status` | Show migration status |
| `dbward_migrate_up` | Apply pending migrations |
| `dbward_migrate_down` | Rollback migrations |
| `dbward_migrate_create` | Create migration file (local) |
| `dbward_wait_request` | Wait for request completion and return result |
| `dbward_list_pending` | List pending approval requests |
| `dbward_who_can_approve` | Show who can approve a request |
| `dbward_find_similar_requests` | Find similar past requests |
| `dbward_preview_impact` | EXPLAIN query before execution |
| `dbward_explain_policy_failure` | Explain why approval is needed |
| `dbward_inspect_schema` | Inspect database schema (list tables or describe columns) |

**MCP Prompts (6):** `review_migration`, `explain_request`, `draft_migration`, `draft_rollback`, `summarize_audit_trail`, `prepare_approval_comment`

**Elicitation:** On production operations, dbward asks the AI client for a reason before proceeding (if the client supports MCP elicitation).

## On-Demand Execution

dbward uses **on-demand execution**: the agent does not execute on approval. Instead, the client explicitly resumes the request when ready to receive the result.

```
1. Client creates request → server evaluates policy → pending / auto_approved
2. (If pending) Human approves via CLI
3. Client resumes (`dbward request resume <id>`) → server marks as "dispatched"
4. Agent polls, claims, executes on DB → returns result to server
5. Server relays result in-memory to waiting client (long poll)
6. Client receives result and saves locally (~/.dbward/results/<id>.json)
```

Results are persisted locally by default (configurable to S3 or stream-only) — it relays them in-memory with a 10-minute TTL.

## Policy Engine

Defined in `server.toml` and hot-reloaded via SIGHUP. See [Configuration Reference](docs/reference/configuration.md).

### Workflows

Control whether operations require approval:

```toml
[[workflows]]
database = "*"
environment = "production"
operations = ["execute_select", "migrate_up", "migrate_down"]

[[workflows.steps]]
type = "approval"

[[workflows.steps.approvers]]
role = "admin"
min = 1
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

### Result Policies

Control who can access results and storage:

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

> Full reference: [docs/reference/cli.md](docs/reference/cli.md)

```
dbward [OPTIONS] <COMMAND>

Commands:
  init          Interactive setup wizard
  doctor        Diagnose connectivity and configuration
  login         OIDC login (browser or --device for headless)
  logout        Revoke tokens and delete credentials
  whoami        Show current identity and role
  migrate       Run migrations (up/down/status/create)
  execute       Execute SQL (--emergency --reason for break-glass)
  audit         Search audit log (--verify for hash chain check)
  mcp           Start MCP stdio server
  server        Server management (start, token create/revoke, reload)
  agent         Start the agent
  dev           Start local dev server + agent
  self-update   Update dbward to the latest version
  request       Manage requests:
    list          List requests (--pending-for-me, --status)
    show          Show request detail
    approve       Approve a pending request
    reject        Reject a pending request
    resume        Resume and wait for result
    cancel        Cancel a pending request

Global Options:
  --version, -v            Show version and exit
  --config <PATH>          Config file (standalone mode; omit for auto-detect)
  --database <NAME>        Target database [env: DBWARD_DATABASE]
  --environment <ENV>      Environment [env: DBWARD_ENV]
```

## REST API

> Full reference with parameters, permissions, and response formats: [docs/reference/api.md](docs/reference/api.md)

### Core

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Health check |
| GET | `/ready` | Readiness check |
| GET | `/metrics` | Prometheus metrics (admin auth required) |
| GET | `/api/public-key` | Ed25519 public key (for execution token verification) |

### Requests

| Method | Path | Description |
|---|---|---|
| GET | `/api/requests` | List requests (filter by status/database/environment/user) |
| POST | `/api/requests` | Create request |
| GET | `/api/requests/:id` | Get request detail |
| POST | `/api/requests/:id/approve` | Approve (requester ≠ approver) |
| POST | `/api/requests/:id/reject` | Reject |
| POST | `/api/requests/:id/resume` | Resume for on-demand execution |
| POST | `/api/requests/:id/cancel` | Cancel a pending request |
| GET | `/api/requests/:id/result/stream` | Long-poll for result |
| GET | `/api/requests/:id/result/content` | Get stored result content |
| GET | `/api/requests/:id/executions` | List execution attempts |

### Tokens & Users

| Method | Path | Description |
|---|---|---|
| POST | `/api/tokens` | Create API token |
| GET | `/api/tokens` | List tokens |
| DELETE | `/api/tokens/:id` | Revoke token |
| GET | `/api/me` | Current user info |
| GET | `/api/users` | List users |
| POST | `/api/users/:id/suspend` | Suspend user |
| POST | `/api/users/:id/activate` | Activate user |

### Agent

| Method | Path | Description |
|---|---|---|
| POST | `/api/agent/poll` | Poll for dispatched jobs |
| POST | `/api/agent/jobs/:id/claim` | Claim a job (lease) |
| POST | `/api/agent/jobs/:id/heartbeat` | Extend lease |
| POST | `/api/agent/jobs/:id/result` | Submit execution result |
| GET | `/api/agents` | List connected agents |

### Policies (read-only)

| Method | Path | Description |
|---|---|---|
| GET | `/api/workflows` | List workflows |
| GET | `/api/execution-policies` | List execution policies |
| GET | `/api/result-policies` | List result policies |
| GET | `/api/result-policies/:id` | Get result policy detail |
| GET | `/api/notification-policies` | List notification policies |
| GET | `/api/notification-policies/:id` | Get notification policy detail |
| GET | `/api/roles` | List roles |
| GET | `/api/webhooks` | List webhooks |
| GET | `/api/webhooks/:id` | Get webhook detail |
| GET | `/api/webhook-deliveries` | List webhook delivery history |
| GET | `/api/policy-resolution` | Resolve effective policy for a request |

### Databases & Schemas

| Method | Path | Description |
|---|---|---|
| GET | `/api/databases` | List configured databases |
| GET | `/api/schemas/:db` | Get schema for a database |

### Audit

| Method | Path | Description |
|---|---|---|
| GET | `/api/audit/events` | Audit events (category/type/outcome filters) |
| GET | `/api/audit/verify` | Verify hash chain integrity |

### Results

| Method | Path | Description |
|---|---|---|
| GET | `/api/results` | List stored results |
| GET | `/api/storage-config` | Get result storage configuration |

## Security

> Threat model and hardening guide: [docs/security/](docs/security/)

- **Zero-trust client** — developer machines never have DB credentials
- **Signed execution tokens** — Ed25519. Token includes SHA-256 hash of SQL + target database
- **Token replay prevention** — executed/failed requests don't issue new tokens
- **Multi-statement rejection** — prevents SQL injection via statement chaining
- **Writable CTE detection** — `WITH x AS (DELETE ...) SELECT ...` classified as DML
- **RBAC** — admin (all), developer (migrate + execute), readonly (SELECT only)
- **Network isolation** — server has no DB credentials; agent connects outbound only
- **API token auth** — SHA-256 hashed, prefix+hash composite lookup
- **OIDC auth** — JWT verification with JWKS caching, RS256/ES256, PKCE for CLI (Team)
- **Audit hash chain** — SHA-256 chain linking all events, tamper-evident

## Platform Support

| Target | Status |
|---|---|
| Linux x86_64 (glibc) | ✅ Supported |
| Linux aarch64 (glibc) | ✅ Supported |
| macOS Apple Silicon | ✅ Supported |
| macOS Intel | ✅ Supported |
| Windows | ❌ Not supported |

Pre-built binaries are available on [GitHub Releases](https://github.com/dbward-dev/dbward/releases). Docker images are published for `linux/amd64` and `linux/arm64`.

> **Note:** Pre-built binaries and Docker images include commercial-licensed components. They are free to use within Free plan limits. See [LICENSE](LICENSE) for details.

## Database Support

| Database | Status |
|---|---|
| PostgreSQL | ✅ Supported |
| MySQL | ✅ Supported |

Auto-detected from URL scheme (`postgres://` or `mysql://`).

## Authentication

> Full guide: [docs/guides/authentication.md](docs/guides/authentication.md)

### API Tokens (Free)

```bash
# Initial tokens created automatically on first server start:
cat ./data/admin-token     # admin token
cat ./data/agent-token     # agent token

# Additional tokens via API:
dbward token create --subject alice --role admin
```

### OIDC (Team)

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

Events: `request_created`, `request_approved`, `request_rejected`, `request_completed`, `break_glass`.

Free: unlimited webhook destinations. Team: adds OIDC/SSO, group authorization, and audit export.

## Break-Glass (Emergency Bypass)

```bash
dbward execute "SELECT pg_terminate_backend(12345)" \
  --emergency --reason "connection pool exhausted at 3am"
```

- Skips approval — agent executes immediately when dispatched
- Fires `break_glass` webhook (🚨 in Slack)
- Reason recorded in audit log
- **Admin role only** (developer/readonly cannot use)
- **Not available via MCP** (AI agents cannot trigger break-glass)

## Configuration

> Full reference: [docs/reference/configuration.md](docs/reference/configuration.md)

Config is resolved in two layers:
1. **Global** (`~/.config/dbward/config.toml`): server URL, token/OIDC
2. **Project** (`./dbward.toml`): databases, migrations

### Global (`~/.config/dbward/config.toml`)

```toml
[server]
url = "http://localhost:3000"
token = "dbw_..."
```

### Project (`dbward.toml`)

```toml
default_database = "app"
migrations_dir = "db/migrations"

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
operations = ["execute_select", "migrate_up", "migrate_down", "migrate_status"]

[databases.primary]
url = "postgres://user:pass@db-primary:5432/app"

[databases.analytics]
url = "mysql://user:pass@db-analytics:3306/warehouse"
```

### Server (`dbward-server.toml`)

```toml
# Start: dbward-server --config server.toml --listen 0.0.0.0:3000
state_dir = "/data"

[auth]
mode = "token"  # "oidc", "token", or "both"

[[webhooks]]
url = "https://hooks.slack.com/services/..."
format = "slack"

[[workflows]]
database = "*"
environment = "production"
operations = ["execute_select", "migrate_up", "migrate_down"]

[[workflows.steps]]
type = "approval"

[[workflows.steps.approvers]]
role = "admin"
min = 1

[[execution_policies]]
database = "*"
environment = "production"
max_executions = 10
execution_window_secs = 3600

[logging]
output = "stderr"              # "stderr" (default) or "file"
# file_path = "/var/log/dbward/server.log"  # only when output = "file"
# rotation = "daily"           # "daily" (default), "hourly", "never"

# Environment variables:
#   DBWARD_LOG_FORMAT=json     → JSON output (production)
#   RUST_LOG=info              → log level filter (default: info)
```

## Free / Team

| | Free | Team ($149/mo) |
|---|---|---|
| Database connections | 3 | 20 |
| Active users | 10 | 50 |
| Workflow rules | Unlimited | Unlimited |
| Webhooks | Unlimited | Unlimited |
| Agents | Unlimited | Unlimited |
| Approval + Audit + MCP + Break-glass | ✅ | ✅ |
| Slack approval UI | ✅ | ✅ |
| Result policies | ✅ | ✅ |
| Notification policies | ✅ | ✅ |
| OIDC / SSO | — | ✅ |
| Group-based authorization | — | ✅ |
| Audit export (CSV/JSON) | — | ✅ |

Safety features are always free. You pay for scale and organizational complexity.

> **Team plan is not yet available.** [Join the waitlist](https://dbward.dev/pricing/#waitlist) to get notified.

## Migration File Format

Migrations use single-file [dbmate-compatible format](https://github.com/amacneil/dbmate):

```
migrations/
├── 20260501120000_create_users.sql
└── 20260502090000_add_email.sql
```

```sql
-- migrate:up
CREATE TABLE users (id SERIAL PRIMARY KEY, name TEXT NOT NULL);

-- migrate:down
DROP TABLE users;
```

## License

dbward uses an open-core licensing model.

- **Core** (`crates/`): [Apache-2.0](LICENSE-APACHE) — approval workflows, audit logs, MCP,
  SQL review, agent execution, break-glass. Use, modify, and redistribute freely.
- **Commercial** (`commercial/`): [dbward Commercial License](LICENSE-COMMERCIAL) — OIDC/SSO,
  group authorization, Team/Enterprise plan enforcement. Requires a paid subscription for
  production use.

No license key = Free plan. All core features work without restriction.

See [LICENSE](LICENSE) for the full structure.
