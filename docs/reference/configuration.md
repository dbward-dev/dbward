# Configuration Reference

dbward uses TOML configuration files. All config files support environment variable expansion with `${VAR_NAME}` syntax.

## Server Configuration

File: `dbward-server.toml` (passed via `--config`)

```toml
# --- Databases ---
# Register databases that agents can connect to.
# Requests for unregistered databases are rejected.
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
# Approval rules. Evaluated in order; most specific match wins.
[[workflows]]
database = "app"                   # "*" = all databases (default)
environment = "production"         # "*" = all environments (default)
operations = ["execute_dml"]       # [] = all operations (default)
require_reason = true
allow_self_approve = false
allow_same_approver_across_steps = true  # default: true
skip_approval_for = ["role:admin"]       # Auto-approve for these selectors
pending_ttl_secs = 86400                 # Request expires if not approved (optional)
statement_timeout_secs = 60              # Override agent timeout (optional)

[[workflows.steps]]
approvers = [{ selector = "role:dba", min = 1 }]

# Auto-approve workflow (empty steps)
[[workflows]]
database = "*"
environment = "staging"

# --- Webhooks ---
[[webhooks]]
url = "https://hooks.slack.com/services/T.../B.../xxx"
events = ["request_approved", "request_rejected", "execution_completed"]
format = "slack"           # "slack" | "generic" (default: "generic")
secret = "${WEBHOOK_SECRET}"  # HMAC-SHA256 signing (optional)

# --- Result Storage ---
[result_storage]
backend = "local"          # "local" | "s3" (default: "local")
root_dir = "./data/results"  # Local backend path (default: "./data/results")
# S3 backend:
# bucket = "my-dbward-results"
# region = "ap-northeast-1"
# endpoint = "https://s3.amazonaws.com"  # Optional (for MinIO etc.)

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
| `result_storage.backend` | `"local"` |
| `result_storage.root_dir` | `"./data/results"` |
| `retention.request_ttl_days` | 90 |
| `retention.audit_ttl_days` | 365 |
| `retention.result_ttl_days` | 30 |
| `retention.approval_ttl_secs` | 86400 |
| `audit.redaction` | `"literals"` |
| `allow_same_approver_across_steps` | `true` |

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

File: `dbward.toml` (auto-detected or `--config` / `DBWARD_CONFIG` env var)

```toml
# Server connection
[server]
url = "https://dbward.internal:3000"
token = "${DBWARD_TOKEN}"          # API token (mutually exclusive with oidc)

# OIDC login (alternative to token)
[server.oidc]
issuer = "https://auth.example.com/realms/myorg"
client_id = "dbward-cli"
browser_url = "https://auth.example.com"  # URL shown to user (optional)

# Defaults
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
| `DBWARD_CONFIG` | Path to CLI config file |
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

Server config errors on undefined variables. Agent and CLI config substitute empty strings for undefined variables.
