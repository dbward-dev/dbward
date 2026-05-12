# Configuration Reference

All configuration files use TOML format. String values support `${ENV_VAR}` expansion.

## Client config (`dbward.toml`)

```toml
default_database = "app"          # Default --database value
migrations_dir = "db/migrations"  # Base migrations directory (default)

[server]
url = "https://dbward.internal:3000"
token = "${DBWARD_TOKEN}"         # API token (mutually exclusive with [server.oidc])

[server.oidc]
issuer = "https://accounts.google.com"
client_id = "123456789.apps.googleusercontent.com"
# discovery_url = "..."           # Override OIDC discovery endpoint
# browser_url = "..."             # Override authorize URL (Docker)
# backchannel_url = "..."         # Override token endpoint (Docker)

[databases.app]
# migrations_dir = "db/migrations/app"  # Override per-database

[databases.analytics]
# migrations_dir = "db/migrations/analytics"
```

## Server config (`dbward-server.toml`)

```toml
# Server bind address and data are set via CLI flags:
#   dbward server start --listen 0.0.0.0:3000 --data /var/lib/dbward/dbward.db

trusted_proxies = ["10.0.0.0/8", "172.16.0.0/12"]

# ─── Authentication ───

[auth]
mode = "both"                     # "token" | "oidc" | "both" (default: "token")
break_glass_roles = ["admin", "developer"]  # (default)

[auth.oidc]
issuer = "https://accounts.google.com"
client_id = "123456789.apps.googleusercontent.com"
# client_secret_env = "OIDC_CLIENT_SECRET"
# jwks_uri = "http://keycloak:8080/..."  # Override for Docker
default_role = "readonly"         # When no role_mapping matches (default: "readonly")

[[auth.oidc.role_mappings]]
claim = "groups"
value = "db-admins"
role = "admin"

[[auth.oidc.role_mappings]]
subject = "alice@example.com"
role = "admin"

# ─── Retention ───

[retention]
request_ttl_days = 90             # (default: 90)
audit_ttl_days = 365              # (default: 365)
result_ttl_days = 30              # (default: 30)
approval_ttl_secs = 86400         # Approval expiry (default: 86400 = 24h)

# ─── Audit ───

[audit]
redaction = "literals"            # "literals" | "none" (default: "literals")
record_ip = true                  # (default: true)
retention_days = 365              # (default: 365)

# ─── Result Storage ───

[result_storage]
backend = "local"                 # "disabled" | "local" | "s3" (default: "disabled")
root_dir = "/var/lib/dbward/results"

# [result_storage]
# backend = "s3"
# bucket = "my-results"
# region = "us-east-1"
# endpoint = "http://minio:9000"  # S3-compatible

# ─── Webhooks ───

[[webhooks]]
url = "${SLACK_WEBHOOK_URL}"
events = ["request_created", "request_approved", "request_rejected", "request_completed", "break_glass"]
format = "slack"                  # "slack" | "generic"
# secret = "${WEBHOOK_SECRET}"    # HMAC-SHA256 signature

# ─── Workflows ───

[[workflows]]
database = "*"
environment = "production"
operations = []                   # Empty = all operations
require_reason = true
allow_self_approve = false        # (default: false)
allow_same_approver_across_steps = false  # (default: false)

[[workflows.steps]]
type = "approval"
mode = "all"                      # "all" | "any" (default: "all")
require_distinct_actors = true    # (default: true)

[[workflows.steps.approvers]]
role = "admin"                    # role or group (pick one)
# group = "dba-team"
min = 1                           # (default: 1)

# ─── Execution Policies ───

[[execution_policies]]
database = "*"
environment = "production"
max_executions = 1                # (default: 1)
execution_window_secs = 3600      # (default: 86400)
retry_on_failure = false          # (default: false)

# ─── Access Policies ───

[[access_policies]]
database = "primary"
environment = "production"
allowed_roles = ["admin", "dba"]
allowed_groups = ["backend-team"]

# ─── Result Policies (Pro) ───

[[result_policies]]
database = "primary"
environment = "production"
delivery_mode = "direct"          # "direct" | "managed" (default: "direct")
access = ["requester", "admin"]   # (default: ["requester", "admin"])

# ─── Notification Policies (Pro) ───

[[notification_policies]]
database = "primary"
environment = "production"

[[notification_policies.webhooks]]
url = "https://hooks.slack.com/..."
events = ["request_created"]
format = "slack"
```

## Agent config (`dbward-agent.toml`)

```toml
agent_id = "prod-agent-1"
poll_interval_ms = 1000           # (default: 1000)
lease_duration_secs = 300         # (default: 300)
drain_timeout_secs = 60           # (default: 60)
max_concurrent_tasks = 2          # (default: 2)

[server]
url = "https://dbward.internal:3000"
agent_token = "${DBWARD_AGENT_TOKEN}"

[capabilities]
databases = ["app"]
environments = ["production", "staging"]
operations = ["*"]                # "*" = all (execute_select, execute_dml, migrate_up, migrate_down, migrate_status)

[databases.app]
url = "${DATABASE_URL}"
# migrations_dir = "db/migrations"

[databases.analytics]
url = "mysql://user:pass@analytics:3306/warehouse"
```

## Environment variable expansion

All string values in TOML configs support `${VAR}` syntax:

```toml
[server]
agent_token = "${DBWARD_AGENT_TOKEN}"

[databases.app]
url = "${DATABASE_URL}"
```

If the variable is not set, the server/agent exits with an error at startup.

## Defaults summary

| Setting | Default |
|---------|---------|
| Server listen | `127.0.0.1:3000` |
| Server data | `dbward.db` |
| Auth mode | `token` |
| Default role (OIDC) | `readonly` |
| Request TTL | 90 days |
| Audit TTL | 365 days |
| Result TTL | 30 days |
| Approval TTL | 86400s (24h) |
| Audit redaction | `literals` |
| Result storage | `disabled` |
| Agent poll interval | 1000ms |
| Agent lease duration | 300s |
| Agent drain timeout | 60s |
| Agent max concurrent | 2 |
| Workflow mode | `all` |
| Approver min | 1 |
| Max executions | 1 |
| Execution window | 86400s (24h) |
| Body size limit | 64MB |
