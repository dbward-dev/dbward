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
| GET | `/metrics` | Prometheus metrics (admin auth required) |
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

Events: `request_created`, `request_approved`, `request_rejected`, `request_completed`, `break_glass`.

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
# listen address and data path are set via CLI flags:
#   dbward server start --listen 0.0.0.0:3000 --data dbward.db --config dbward-server.toml

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

## Free / Pro

| | Free | Pro (planned) |
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
| Audit export | — | TBD |

Safety features are always free. Pro pricing and availability are not yet determined.

## Migration File Format

Migrations use a directory-per-migration structure:

```
db/migrations/
├── 20260501120000_create_users/
│   ├── up.sql
│   └── down.sql
└── 20260502090000_add_email/
    ├── up.sql
    └── down.sql
```

```sql
-- up.sql
CREATE TABLE users (id SERIAL PRIMARY KEY, name TEXT NOT NULL);
```

```sql
-- down.sql
DROP TABLE users;
```

## Metrics

`GET /metrics` — Prometheus text format, requires admin authentication. Include your admin token in the `Authorization` header.

Key alerts:
- `dbward_agents_active == 0` → no agent running
- `dbward_requests_oldest_pending_seconds > 3600` → stuck request
- `rate(dbward_break_glass_total[5m]) > 0` → emergency bypass used

## Self-Hosted Deployment

### Minimum Requirements

- Linux VM (EC2, GCE, DigitalOcean, etc.)
- Docker + Docker Compose
- S3 bucket (for backup and result storage)

### Quick Deploy

```bash
git clone https://github.com/dbward-dev/dbward.git && cd dbward

# Configure
mkdir -p dev/secrets && echo "your-secure-password" > dev/secrets/db_password.txt

# Start (from dev/ directory)
cd dev
docker compose up -d
cat > .env << 'EOF'
DATABASE_URL=postgres://user:pass@your-rds:5432/mydb
DBWARD_AGENT_TOKEN=<generate after first start>
LITESTREAM_S3_BUCKET=my-dbward-backups
AWS_REGION=ap-northeast-1
EOF
chmod 600 .env

# Create server.toml (minimal)
cat > config/server.toml << 'EOF'
[auth]
mode = "token"

[result_storage]
backend = "s3"
bucket = "my-dbward-results"
region = "ap-northeast-1"

[retention]
result_ttl_days = 90

[[workflows]]
database = "*"
environment = "production"
require_reason = true

[[workflows.steps]]
type = "approval"

[[workflows.steps.approvers]]
role = "admin"
min = 1
EOF

# Start
docker compose up -d

# Generate tokens
docker compose exec dbward-server dbward server token create --user admin --role admin
docker compose exec dbward-server dbward server token create --user agent --role agent
```

### Backup & Recovery

SQLite state is replicated to S3 in real-time via [Litestream](https://litestream.io/) (~1 second RPO).

**Disaster recovery** (EC2 dies):
```bash
# Just start on a new instance — auto-restores from S3
docker compose up -d
```

**Point-in-time restore** (data corruption):
```bash
docker compose down
docker run --rm -v dbward_server-data:/data \
  -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_REGION \
  litestream/litestream:0.5 \
  restore -o /data/dbward.db -timestamp "2026-05-07T10:00:00Z" \
  s3://my-dbward-backups/dbward/prod
docker compose up -d
```

### Without S3 (development / evaluation)

If `LITESTREAM_S3_BUCKET` is not set, Litestream is skipped and dbward runs directly. Use `deploy/scripts/backup.sh` for manual backups.

### TLS

Bind to `127.0.0.1` (default in compose.yml) and put a reverse proxy in front:

```bash
# Example with Caddy (auto-TLS)
caddy reverse-proxy --from dbward.internal.example.com --to localhost:13000
```

### Upgrade

```bash
git pull && docker compose up -d --build
# SQLite migrations run automatically on server start
```

## Development

```bash
# Prerequisites: Rust 1.88+, Docker (for E2E tests)

# Build
cargo build --workspace

# Unit tests
cargo test --workspace

# Dev environment (Docker)
cd dev
mkdir -p secrets && echo "dbward" > secrets/db_password.txt
docker compose up -d
./scripts/dev-init.sh

# E2E tests
./e2e/lifecycle.sh
./e2e/security.sh
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for full development setup.

## Documentation

Detailed documentation is available in the [`docs/`](docs/) directory:

| Path | Description |
|------|-------------|
| [`docs/architecture.md`](docs/architecture.md) | System architecture and design decisions |
| **Deployment** | |
| [`docs/deployment/server.md`](docs/deployment/server.md) | Server configuration and setup |
| [`docs/deployment/agent.md`](docs/deployment/agent.md) | Agent deployment and configuration |
| [`docs/deployment/authentication.md`](docs/deployment/authentication.md) | API tokens, OIDC (Pro), and groups |
| **Guides** | |
| [`docs/guides/workflows.md`](docs/guides/workflows.md) | Workflow and approval policy configuration |
| [`docs/guides/migrations.md`](docs/guides/migrations.md) | Migration management |
| [`docs/guides/mcp-integration.md`](docs/guides/mcp-integration.md) | MCP integration for AI agents |
| [`docs/guides/ci-cd.md`](docs/guides/ci-cd.md) | CI/CD pipeline integration |
| **Reference** | |
| [`docs/reference/api.md`](docs/reference/api.md) | REST API reference |
| [`docs/reference/cli.md`](docs/reference/cli.md) | CLI command reference |
| [`docs/reference/configuration.md`](docs/reference/configuration.md) | Configuration file reference |

## License

- **dbward-server**: [Business Source License 1.1](LICENSE-BSL) (converts to Apache-2.0 on 2029-05-08)
- **All other crates**: [Apache-2.0](LICENSE-APACHE) OR [MIT](LICENSE-MIT) (dual-licensed)
