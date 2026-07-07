---
title: Server Setup
description: Deploy the dbward server
---

# Server Setup

The dbward server manages approval state, audit logs, and coordinates agents. It does **not** connect to your database.

## Configuration reference

> Full configuration reference with all options: [Configuration](../reference/configuration.md)

### Top-level settings

```toml
# Required: directory for server state (SQLite DB, signing keys, agent-token)
state_dir = "/data"

trusted_proxies = ["10.0.0.0/8"]  # Trust X-Forwarded-For from these CIDRs
```

> **Note:** The server has a 64MB request body size limit.

### Authentication

```toml
[auth]
mode = "token"                    # "token" | "oidc" | "both"
# break_glass: any user with --emergency flag  # Roles allowed to use --emergency
```

For OIDC setup, see [Authentication](../guides/authentication.md).

### Retention

```toml
[retention]
request_ttl_days = 90             # Auto-delete completed requests (default: 90)
audit_ttl_days = 365              # Audit log retention (default: 365)
result_ttl_days = 30              # Stored results retention (default: 30)
approval_ttl_secs = 86400         # Approval expiry — re-approval needed after (default: 24h)
```

### Audit

```toml
[audit]
redaction = "literals"            # "literals" (mask SQL values) | "none" (default: literals)
# IP recorded automatically via trusted_proxies                  # Record client IP in audit events (default: true)

```

### Result storage

```toml
# Local (default) — omit root_dir to use {state_dir}/results
[result_storage]
backend = "local"
root_dir = "/data/results"

# S3
[result_storage]
backend = "s3"
bucket = "my-dbward-results"
region = "us-east-1"
# endpoint = "http://minio:9000"  # For S3-compatible storage
```

#### S3 configuration options

| Field | Description | Default |
|---|---|---|
| `bucket` | S3 bucket name | `dbward` |
| `region` | AWS region | `us-east-1` |
| `endpoint` | Custom endpoint (MinIO, LocalStack) | — |
| `access_key_id` | AWS access key (falls back to env/instance role) | — |
| `secret_access_key` | AWS secret key | — |
| `path_style` | Use path-style URLs (required for MinIO) | `false` |
| `prefix` | Key prefix for all objects (e.g. `prod/`) | — |

#### S3 Lifecycle Policy (recommended)

Configure an S3 Lifecycle Rule as a safety net for expired results.
dbward tags each stored result with `dbward-expires` containing the RFC 3339 expiry timestamp.
The background job deletes expired results, but a lifecycle rule provides defense-in-depth:

```json
{
  "Rules": [
    {
      "ID": "dbward-result-expiry",
      "Filter": { "Prefix": "results/" },
      "Status": "Enabled",
      "Expiration": { "Days": 91 }
    }
  ]
}
```

Set `Expiration.Days` to `retention_days + 1` (default retention is 30 days for Free, configurable via result policies for Team).

### Webhooks

```toml
[[webhooks]]
url = "https://hooks.slack.com/services/T.../B.../xxx"
events = ["request_created", "request_approved", "request_rejected", "request_completed"]
format = "slack"
# secret = "whsec_..."           # HMAC-SHA256 signature (optional)
```

### Workflows

See [Workflows guide](../guides/policies/workflows.md) for full configuration.

```toml
# Production: require admin approval
[[workflows]]
database = "*"
environment = "production"
require_reason = true

[[workflows.steps]]
type = "approval"
[[workflows.steps.approvers]]
role = "admin"
min = 1

# Development: auto-approve (mode = "always")
[[workflows]]
database = "*"
environment = "development"
```

### Auto-Approve

Auto-approve is configured within each workflow:

```toml
# Development: auto-approve everything
[[workflows]]
database = "*"
environment = "development"

[workflows.auto_approve]
mode = "always"

# Staging: auto-approve low-risk only
[[workflows]]
database = "*"
environment = "staging"

[workflows.auto_approve]
mode = "risk_based"
risk = "low"
allow_read_only = true
allow_safe_ddl = true

[[workflows.steps]]
type = "approval"
[[workflows.steps.approvers]]
role = "dba"
min = 1

# Production: no auto-approve (always require human)
[[workflows]]
database = "*"
environment = "production"

[[workflows.steps]]
type = "approval"
[[workflows.steps.approvers]]
role = "dba"
min = 1
```

### Execution policies

```toml
[[execution_policies]]
database = "*"
environment = "production"
max_executions = 1                # One-shot execution (default: 1)
execution_window_secs = 3600     # Must execute within 1 hour of approval (default: 86400)
retry_on_failure = false          # Allow re-execution on failure only (default: false)
```

### Result policies

Result policies are managed via the REST API, not TOML. See [Result Policies](../guides/policies/result-policies.md).

### Notification policies

Notification policies are managed via the REST API, not TOML. See [Notification Policies](../guides/policies/notification-policies.md).

## Validate before starting

After writing your configuration, validate it before starting the server:

```bash
dbward doctor --server /path/to/server.toml
```

This checks workflow validity, role resolution, Slack connectivity, and webhook references — catching misconfigurations before they cause runtime failures.

## Running with systemd

```ini
# /etc/systemd/system/dbward-server.service
[Unit]
Description=dbward server
After=network.target

[Service]
Type=simple
User=dbward
ExecStart=/usr/local/bin/dbward-server \
  --config /etc/dbward/dbward-server.toml \
  --listen 0.0.0.0:3000
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## Running with Docker

```bash
docker run -d \
  --name dbward-server \
  -p 3000:3000 \
  -v dbward-data:/data \
  -v ./dbward-server.toml:/etc/dbward/dbward-server.toml:ro \
  ghcr.io/dbward-dev/dbward-server:latest \
    --config /etc/dbward/dbward-server.toml \
    --listen 0.0.0.0:3000
```

## Token management

Create tokens for users and agents:

```bash
# Initial tokens created automatically on first server start.
# Read them from files:
cat /data/admin-token    # admin token
cat /data/agent-token    # agent token

# Additional tokens via CLI (requires admin token):
dbward token create --subject alice --scope-roles admin
dbward token create --subject bob --scope-roles developer
dbward token create --subject prod-agent --subject-type agent --no-scope-ceiling
```

For API-based token management, see [REST API Reference](../reference/api.md#tokens).

## Health checks

Two endpoints are available without authentication:

| Endpoint | Purpose | Use for |
|----------|---------|---------|
| `GET /health` | Process liveness — always returns 200 if the server is running | Container liveness probes, external uptime monitors |
| `GET /ready` | Service readiness — returns 503 when degraded or draining | Load balancer target health, rollout gating |

```bash
curl http://localhost:3000/health
# → {"status":"ok","version":"0.1.5","min_agent_version":"0.1.5"}

curl http://localhost:3000/ready
# → {"status":"ok","checks":{"sqlite":"ok","result_store":"ok"}}
# → 503 {"status":"degraded",...} when SQLite or result store is unavailable
```

**Choosing between them:** Use `/health` for restart decisions and "is it up at all?" checks. Use `/ready` for load balancer health and traffic routing — it intentionally returns 503 during graceful shutdown and maintenance drains.

For external uptime monitoring (e.g., Route53 Health Check, UptimeRobot), point at `/health`. This avoids false alerts during planned rolling deploys where `/ready` temporarily returns 503.

All responses include an `X-Dbward-Version` header.

### Agent status

The server tracks agent liveness via poll heartbeats. Query the fleet status with:

```bash
curl http://localhost:3000/api/agents -H "Authorization: Bearer $TOKEN"
# Requires metrics.view permission
```

Each agent has a `status` field:

| Status | Meaning |
|--------|---------|
| `healthy` | Polling and has spare capacity |
| `saturated` | Polling but at max concurrency (`in_flight >= max_concurrent`) |
| `offline` | No poll received for 60+ seconds |
| `draining` | Graceful shutdown in progress |

> **Note:** An agent in degraded mode (e.g., lost DB connection) still polls with `limit=0` and appears `healthy` here. Check application logs or the agent's readiness probe for degraded state.

This is the best available fleet-level view. Local probe files (`/tmp/dbward-agent-alive`, `/tmp/dbward-agent-ready`) are for the container runtime only.

## Metrics

```bash
# Requires metrics.view permission
curl http://localhost:3000/metrics -H "Authorization: Bearer $TOKEN"
# → Prometheus text format
```

If you use Prometheus/Grafana, scrape `/metrics` for request queue depth (`dbward_requests_current`) and general activity. Note that `/metrics` does **not** reflect agent offline state — the `dbward_agents_active` gauge counts configured agents regardless of `last_seen`. For offline detection, poll `GET /api/agents` which applies the 60-second heartbeat check.

## Backup

The server stores all state in a single SQLite file. Back it up with:

```bash
# Simple copy (while server is running — SQLite WAL mode is safe)
cp /data/dbward.db /backup/dbward-$(date +%Y%m%d).db

# Or use Litestream for continuous replication to S3
# See: https://litestream.io
```

## Environment variables

All TOML string values support `${ENV_VAR}` expansion:

```toml
[[webhooks]]
url = "${SLACK_WEBHOOK_URL}"
secret = "${WEBHOOK_SECRET}"
```

## See also

- [Agent setup](agent.md) — Connect agents to your databases
- [Authentication](../guides/authentication.md) — Configure OIDC or manage tokens
- [Workflows](../guides/policies/workflows.md) — Set up approval rules
- [Troubleshooting](troubleshooting.md) — Common deployment issues
