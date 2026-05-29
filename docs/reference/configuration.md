---
title: Configuration Reference
description: Complete configuration file specification
---

# Configuration Reference

dbward uses TOML configuration files. All config files support environment variable expansion with `${VAR_NAME}` syntax.

## Server Configuration

File: `dbward-server.toml` (passed via `--config`)

```toml
# --- State Directory (required) ---
# All server state lives here: SQLite DB, signing keys, agent-token file.
# Relative paths resolve against the config file's parent directory.
state_dir = "/data"

# --- Databases ---
# Register databases that agents can connect to.
# Requests for unregistered database×environment pairs are rejected with:
#   "database 'X' not registered in environment 'Y'. Available environments: ..."
# Fix: add the environment to the list below, or use --environment to target the correct one.
[[databases]]
name = "app"
environments = ["production", "staging"]

[[databases]]
name = "analytics"
environments = ["production"]

# --- Authentication ---
[auth]
mode = "both"              # "token" | "oidc" | "both" (default: "both")
default_role = "developer" # Role assigned when no binding matches

# Map users/groups to roles
[[auth.role_bindings]]
role = "admin"
subjects = ["alice@example.com"]

[[auth.role_bindings]]
role = "developer"
groups = ["backend-team"]

# OIDC (optional, required when mode = "oidc" or "both")
[auth.oidc]
issuer_url = "https://auth.example.com/realms/myorg"
audience = "dbward"
client_id = "dbward-cli"           # Optional, defaults to audience
jwks_uri = "https://auth.example.com/realms/myorg/protocol/openid-connect/certs"  # Optional
default_role = "readonly"          # Role for authenticated users with no mapping

# Map OIDC claims to roles
[[auth.oidc.role_mappings]]
claim = "groups"
value = "dba-team"
role = "admin"

# --- Workflows ---
# Approval rules. Most specific scope match wins.
# No match = request rejected (fail-closed).
[[workflows]]
database = "app"                   # "*" = all databases (default)
environment = "production"         # "*" = all environments (default)
operations = ["execute_dml"]       # omitted = all operations (default)
require_reason = true
allow_self_approve = false
allow_same_approver_across_steps = true  # default: true
pending_ttl_secs = 86400                 # Request expires if not approved (optional)
statement_timeout_secs = 60              # Override agent timeout (optional)

[[workflows.steps]]
approvers = [{ selector = "role:dba", min = 1 }]

# Auto-approve workflow (empty steps)
[[workflows]]
database = "*"
environment = "staging"

# --- Auto-Approve ---
# Risk-based auto-approval. Scoped by (database, environment).
# Priority: (db, env) > (*, env) > (db, *) > (*, *)
# Unmatched scope = no auto-approve (human approval required).
[[auto_approve]]
database = "*"
environment = "*"
risk = "low"                   # "none" | "low" | "medium" | "high"
allow_read_only = true         # SELECT → Low risk (default: true)
allow_safe_ddl = true          # CREATE TABLE/INDEX/VIEW → Low risk (default: true)
max_estimated_rows = 1000      # Tables above this → risk increase (default: 1000)

[[auto_approve]]
database = "*"
environment = "staging"
risk = "medium"                # Staging: auto-approve up to Medium

[[auto_approve]]
database = "*"
environment = "production"
risk = "none"                  # Production: always require human approval

# --- SQL Review ---
# Block or warn on dangerous SQL patterns.
[sql_review]
no_where_delete = "block"      # "block" | "warn" | "off" (default: "warn")
no_where_update = "block"      # "block" | "warn" | "off" (default: "warn")
drop_table = "warn"            # "block" | "warn" | "off" (default: "warn")
drop_column = "warn"
not_null_without_default = "warn"
create_index_not_concurrently = "warn"
alter_column_type = "warn"
truncate = "warn"
mixed_ddl_dml = "warn"
large_in_list = "warn"

# --- Webhooks ---
[[webhooks]]
url = "https://hooks.slack.com/services/T.../B.../xxx"
events = ["request_approved", "request_rejected", "execution_completed"]
format = "slack"           # "slack" | "generic" (default: "generic")
secret = "${WEBHOOK_SECRET}"  # HMAC-SHA256 signing (optional)

# --- Execution Policies ---
# Controls re-execution limits and statement timeout per database×environment.
# Most specific match wins (exact db+env > wildcard).
# If no policy matches, defaults apply (max_executions=1, timeout=30s).
[[execution_policies]]
database = "*"                     # "*" = all databases (default)
environment = "production"         # "*" = all environments (default)
max_executions = 1                 # Max re-executions per request (default: 1)
execution_window_secs = 3600       # Time window for re-execution (default: 86400)
retry_on_failure = false           # Allow retry after failure (default: false)
statement_timeout_secs = 30        # SQL statement timeout (default: 30)
max_statement_timeout_secs = 300   # Cap for timeout (default: 600)
max_rows = 10000                   # Max rows in result (optional, no limit if unset)

# --- Result Storage ---
[result_storage]
backend = "local"          # "local" | "s3" (default: "local")
root_dir = "./data/results"  # Local backend path (default: "./data/results")
max_persist_bytes = 10485760  # Max result size to store (default: 10MB)
# S3 backend:
# bucket = "my-dbward-results"
# region = "ap-northeast-1"
# endpoint = "https://s3.amazonaws.com"  # Optional (for MinIO etc.)

# --- Result Channel (in-memory streaming) ---
[result_channel]
max_slots = 10000          # Max concurrent result slots (default: 10000)
slot_ttl_secs = 600        # Slot expiry for completed results (default: 600)

# --- Retention ---
[retention]
request_ttl_days = 90      # Delete old requests (default: 90)
audit_ttl_days = 365       # Delete old audit events (default: 365)
result_ttl_days = 30       # Delete stored results (default: 30)
approval_ttl_secs = 86400  # Approved requests expire after this (default: 86400 = 24h)

# --- Audit ---
[audit]
redaction = "literals"     # "literals" | "none" (default: "literals")
```

### Defaults Summary

| Setting | Default |
|---------|---------|
| `auth.mode` | `"both"` |
| `auto_approve.risk` | `"none"` (no auto-approve) |
| `auto_approve.allow_read_only` | `true` |
| `auto_approve.allow_safe_ddl` | `true` |
| `auto_approve.max_estimated_rows` | `1000` |
| `sql_review.*` | `"warn"` |
| `result_storage.backend` | `"local"` |
| `result_storage.root_dir` | `"./data/results"` |
| `result_storage.max_persist_bytes` | 10485760 (10MB) |
| `result_channel.max_slots` | 10000 |
| `result_channel.slot_ttl_secs` | 600 |
| `retention.request_ttl_days` | 90 |
| `retention.audit_ttl_days` | 365 |
| `retention.result_ttl_days` | 30 |
| `retention.approval_ttl_secs` | 86400 |
| `audit.redaction` | `"literals"` |
| `allow_same_approver_across_steps` | `true` |
| `execution_policies[].max_executions` | 1 |
| `execution_policies[].execution_window_secs` | 86400 |
| `execution_policies[].retry_on_failure` | `false` |
| `execution_policies[].statement_timeout_secs` | 30 |
| `execution_policies[].max_statement_timeout_secs` | 600 |

---

## Agent Configuration

File: `dbward-agent.toml` (passed via `--config`)

```toml
# Agent identity (default: hostname)
agent_id = "agent-prod-01"

# Server connection
[server]
url = "https://dbward.internal:3000"
agent_token = "${DBWARD_AGENT_TOKEN}"

# Databases this agent can access.
# Structure: [databases.<name>.<environment>]
[databases.app.production]
url = "postgres://dbward:${DB_PASSWORD}@db.internal:5432/app"

[databases.app.staging]
url = "postgres://dbward:${DB_PASSWORD}@db-staging.internal:5432/app"

[databases.analytics.production]
url = "mysql://dbward:${DB_PASSWORD}@analytics.internal:3306/analytics"

# --- Optional settings ---
poll_interval_ms = 1000        # How often to poll server (default: 1000)
max_concurrent_tasks = 2       # Max parallel executions (default: 2)
drain_timeout_secs = 60        # Graceful shutdown timeout (default: 60)
statement_timeout_secs = 30    # Query timeout in seconds (default: 30)
lease_duration_secs = 300      # Execution lease duration (default: 300)
operations = ["execute_select", "execute_dml", "migrate_up", "migrate_down", "migrate_status"]  # default: all
```

### Defaults Summary

| Setting | Default |
|---------|---------|
| `agent_id` | hostname |
| `poll_interval_ms` | 1000 |
| `max_concurrent_tasks` | 2 |
| `drain_timeout_secs` | 60 |
| `statement_timeout_secs` | 30 |
| `lease_duration_secs` | 300 |
| `operations` | all (select, dml, migrate_up, migrate_down) |

---

## CLI Configuration

Two-layer resolution:
1. Global: `~/.config/dbward/config.toml` (server connection, auth)
2. Project: `dbward.toml` in CWD (databases, migrations)

When `--config` or `DBWARD_CONFIG` is set, only that file is used (standalone mode, no global merge).
Use `--merge-global` to opt into global merge with an explicit config path.

### Global config (`~/.config/dbward/config.toml`)

```toml
[server]
url = "https://dbward.internal:3000"
token = "${DBWARD_TOKEN}"          # API token (mutually exclusive with oidc)

# OIDC login (alternative to token)
[server.oidc]
issuer = "https://auth.example.com/realms/myorg"
client_id = "dbward-cli"
```

### Project config (`dbward.toml`)

```toml
default_database = "app"           # Skip --database flag (optional)
default_environment = "production" # Skip --environment flag (optional)
migrations_dir = "db/migrations"   # Path to migration files (default: "migrations")

# Per-database overrides (optional)
[databases.analytics]
migrations_dir = "analytics/migrations"
```

### Environment Variables

| Variable | Purpose |
|----------|---------|
| `DBWARD_CONFIG` | Path to CLI config file (standalone mode) |
| `DBWARD_GLOBAL_CONFIG` | Path to global config file |
| `DBWARD_SERVER_URL` | Override server URL |
| `DBWARD_TOKEN` | Override API token |
| `DBWARD_DATABASE` | Default database |
| `DBWARD_ENV` | Default environment |

---

## Environment Variable Expansion

All config files support `${VAR_NAME}` syntax:

```toml
[server]
agent_token = "${DBWARD_AGENT_TOKEN}"

[databases.app.production]
url = "postgres://user:${DB_PASSWORD}@host/db"
```

All config files error on undefined variables. Use `${VAR:-default}` to provide a fallback value (e.g., `${PORT:-3000}`). Use `${VAR:-}` for an intentional empty default.

---

## Additional Supported Fields

### Server: `trusted_proxies`

```toml
# CIDR ranges to trust for X-Forwarded-For resolution
trusted_proxies = ["10.0.0.0/8", "172.16.0.0/12"]
```

### Server: `[logging]`

```toml
[logging]
level = "info"      # Log level (debug, info, warn, error)
format = "text"     # "text" or "json"
```

> **Note:** The agent also supports `DBWARD_LOG_FORMAT=json` env var override. The server uses only the config value.

### Server: `[slack]`

```toml
[slack]
bot_token = "${SLACK_BOT_TOKEN}"
signing_secret = "${SLACK_SIGNING_SECRET}"
channel = "#db-approvals"

[slack.channels]
production = "#prod-db-approvals"    # Per-environment channel routing
staging = "#staging-alerts"
```

### Server: Result Storage (S3)

```toml
[result_storage]
backend = "s3"
bucket = "my-bucket"
region = "us-east-1"
endpoint = "https://s3.amazonaws.com"  # Custom endpoint (MinIO)
access_key_id = "${AWS_ACCESS_KEY_ID}"
secret_access_key = "${AWS_SECRET_ACCESS_KEY}"
path_style = false                     # true for MinIO
prefix = "dbward/results"              # S3 key prefix
max_persist_bytes = 10485760           # 10MB max (default)
```

### Workflow: Additional Fields

```toml
[[workflows]]
database = "*"
environment = "production"
explain = true                # Run EXPLAIN on request creation (default: true)
pending_ttl_secs = 86400      # Override pending expiry for this workflow
statement_timeout_secs = 60   # Override statement timeout for this workflow
```

### Agent: Startup Retry

```toml
startup_retry_initial_ms = 1000   # Initial backoff (default: 1000)
startup_retry_max_ms = 15000      # Max backoff (default: 15000)
startup_max_wait_secs = 0         # Startup deadline, 0 = infinite (default: 0)
```

### Agent: Schema Sync

```toml
[schema_sync]
enabled = true          # Collect and push schema to server (default: true)
sync_on_startup = true  # Sync immediately on agent start (default: true)
interval_secs = 0       # Periodic re-sync interval, 0 = disabled (default: 0)
                        # When 0, sync only happens on startup (if sync_on_startup=true)
                        # and after migrations
```

### CLI: `DBWARD_DATABASE` Environment Variable

```bash
export DBWARD_DATABASE=app   # Equivalent to --database app
```
