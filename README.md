# dbward

> **Open-core project** — core components are [Apache-2.0](LICENSE-APACHE). Some features and pre-built binaries include code under the [dbward Commercial License](LICENSE-COMMERCIAL). See [License](#license) for details.

**Approval workflows and audit logs for your production database.**

Stop accidents before they hit production. Add approval gates, audit trails, and AI agent guardrails to every database operation — with standalone binaries and embedded SQLite. No external control-plane DB required.

<p align="center">
  <img src="demo/combined.gif" alt="dbward approval flow demo" width="100%">
</p>

## Highlights

- 🔐 **Approval workflows** — multi-step, conditional auto-approve, TOML policy engine
- 📋 **Audit logs** — tamper-evident hash chain, 24 event types, SQL redaction
- 🤖 **MCP-native** — 12 tools, 6 prompts, elicitation support. AI agents operate safely. Remote HTTP transport for team setups
- ⚡ **Standalone binaries** — CLI, server, and agent ship as self-contained Rust binaries with embedded SQLite. No external control-plane DB
- 🔒 **Agent isolation** — DB credentials never leave the agent. CLI/AI never touch your database directly
- 🛡️ **SQL safety review** — risk classification, DDL detection, `DROP` blocking. Auto-approve safe queries, require approval for risky ones
- 💬 **Slack approvals** — approve/reject from Slack with one click. `dbward slack init` generates the app manifest
- 🚨 **Break-glass** — emergency bypass with mandatory reason and audit. Admin-only, not available via MCP
- 🆓 **Core features free** — approval, audit, MCP, Slack, break-glass all included under [Apache-2.0](LICENSE-APACHE). Team features (OIDC, group auth) require a [commercial license](LICENSE-COMMERCIAL)

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
| `dbward_preflight_sql` | Analyze SQL safety without creating a request |
| `dbward_explain_policy_failure` | Explain why approval is needed |
| `dbward_inspect_schema` | Inspect database schema (list tables or describe columns) |

**MCP Prompts (6):** `review_migration`, `explain_request`, `draft_migration`, `draft_rollback`, `summarize_audit_trail`, `prepare_approval_comment`

**Elicitation:** On production operations, dbward asks the AI client for a reason before proceeding (if the client supports MCP elicitation).

**Remote MCP (HTTP):** For team setups, the server exposes MCP over HTTP — no local binary needed (9 tools, excludes local-only migration tools):

```json
{
  "mcpServers": {
    "dbward": {
      "type": "streamable-http",
      "url": "https://your-server.example.com/mcp"
    }
  }
}
```

## On-Demand Execution

dbward uses **on-demand execution**: the agent does not execute on approval. Instead, the client explicitly resumes the request when ready to receive the result.

```
1. Client creates request → server evaluates policy → pending / auto_approved
2. (If pending) Human approves via CLI
3. Client resumes (`dbward request resume <id>`) → server marks as "dispatched"
4. Agent polls, claims, executes on DB → returns result to server
5. Server relays result in-memory to waiting client (long poll)
6. Client displays result (server persists to local FS or S3)
```

Results are persisted on the server by default (local filesystem or S3, configurable via `[result_storage]`). The in-memory relay has a 10-minute TTL for streaming delivery. Use `--no-result-store` to skip persistence for a single request.

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

# Auto-approve low-risk queries in staging; risky ones still need approval
[[workflows]]
database = "*"
environment = "staging"

[workflows.auto_approve]
mode = "risk_based"
risk = "low"

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
  token         Manage API tokens (create/list/revoke)
  user          Manage users (list/suspend/activate)
  slack         Slack integration:
    init          Generate app manifest and creation URL
  policy        Policy tools:
    resolve       Resolve effective policy for a request

Global Options:
  --version, -v            Show version and exit
  --config <PATH>          Config file (standalone mode; omit for auto-detect)
  --database <NAME>        Target database [env: DBWARD_DATABASE]
  --environment <ENV>      Environment [env: DBWARD_ENV]
```

## REST API

> Full reference: [docs/reference/api.md](docs/reference/api.md)

| Method | Path | Description |
|---|---|---|
| POST | `/api/requests` | Create request |
| POST | `/api/requests/:id/approve` | Approve |
| POST | `/api/requests/:id/resume` | Resume for on-demand execution |
| GET | `/api/requests/:id/result/stream` | Long-poll for result |
| GET | `/api/audit/events` | Audit events |
| GET | `/api/audit/verify` | Verify hash chain integrity |
| POST | `/api/tokens` | Create API token |
| GET | `/api/databases` | List configured databases |
| GET | `/api/agents` | List connected agents |
| POST | `/mcp` | Remote MCP (HTTP) |

See [full API reference](docs/reference/api.md) for all endpoints, parameters, permissions, and response formats.

## Security

> Threat model and hardening guide: [docs/security/](docs/security/)

- **Zero-trust client** — developer machines never have DB credentials
- **Signed execution tokens** — Ed25519. Token includes SHA-256 hash of SQL + target database
- **Token replay prevention** — executed/failed requests don't issue new tokens
- **Multi-statement rejection** — prevents SQL injection via statement chaining
- **Writable CTE detection** — `WITH x AS (DELETE ...) SELECT ...` classified as DML
- **RBAC** — admin (system management), requester (SQL operations), operator (monitoring + break-glass), approver (review)
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

## Notifications

### Slack Approvals

Approve and reject requests directly from Slack with interactive buttons:

```bash
dbward slack init --server-url https://your-server.example.com
# → generates Slack App Manifest, opens creation URL
```

Configure in `server.toml`:

```toml
[slack]
bot_token = "${SLACK_BOT_TOKEN}"
signing_secret = "${SLACK_SIGNING_SECRET}"
channel = "C0123ABC456"
```

See [Notifications Guide](docs/guides/notifications.md) for setup details.

### Webhooks

```toml
[[webhooks]]
url = "https://internal.example.com/dbward"
format = "generic"
secret = "whsec_xxxx"  # HMAC-SHA256 in X-Dbward-Signature header
```

Events: `request.created`, `request.approved`, `request.rejected`, `execution.completed`, `request.break_glass`.

Free: unlimited webhook destinations.

## Break-Glass (Emergency Bypass)

```bash
dbward execute "SELECT pg_terminate_backend(12345)" \
  --emergency --reason "connection pool exhausted at 3am"
```

- Skips approval — agent executes immediately when dispatched
- Fires `request.break_glass` webhook (🚨 in Slack)
- Reason recorded in audit log
- **Operator role only** (requires `request.break_glass_dml` permission)
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
max_concurrent_tasks = 2

[server]
url = "https://dbward.internal:3000"
agent_token = "${DBWARD_AGENT_TOKEN}"

[databases.primary.production]
url = "${DATABASE_URL_PRIMARY}"

[databases.analytics.production]
url = "${DATABASE_URL_ANALYTICS}"
```

### Server (`dbward-server.toml`)

```toml
# Start: dbward-server --config server.toml --listen 0.0.0.0:3000
state_dir = "/data"

[auth]
# OIDC enabled when [auth.oidc] section is present

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
| Active users | 20 | 50 |
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
