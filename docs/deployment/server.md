# Server Setup

The dbward server manages approval state, audit logs, and coordinates agents. It does **not** connect to your database.

## Quick start

```bash
# 1. Create config
cat > dbward-server.toml << 'EOF'
listen = "0.0.0.0:3000"
data = "/var/lib/dbward/dbward.db"

[auth]
mode = "token"

[[workflows]]
database = "*"
environment = "production"

[[workflows.steps]]
type = "approval"

[[workflows.steps.approvers]]
role = "admin"
min = 1
EOF

# 2. Create initial admin token
dbward token create --user admin --role admin --data /var/lib/dbward/dbward.db

# 3. Start
dbward-server --config dbward-server.toml
```

## Configuration reference

### Top-level settings

```toml
# listen and data are set via CLI flags (--listen, --data), not TOML.
# These CLI defaults are: listen = "127.0.0.1:3000", data = "dbward.db"

trusted_proxies = ["10.0.0.0/8"]  # Trust X-Forwarded-For from these CIDRs
```

> **Note:** The server has a 64MB request body size limit.

### Authentication

```toml
[auth]
mode = "token"                    # "token" | "oidc" | "both"
break_glass_roles = ["admin", "developer"]  # Roles allowed to use --emergency
```

For OIDC setup, see [Authentication](authentication.md).

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
record_ip = true                  # Record client IP in audit events (default: true)
retention_days = 365              # Same as retention.audit_ttl_days (default: 365)
```

### Result storage

```toml
# Disabled (default) — results are only relayed in-memory
[result_storage]
backend = "disabled"

# Local filesystem
[result_storage]
backend = "local"
root_dir = "/var/lib/dbward/results"

# S3 (Pro)
[result_storage]
backend = "s3"
bucket = "my-dbward-results"
region = "us-east-1"
# endpoint = "http://minio:9000"  # For S3-compatible storage
```

### Webhooks

```toml
[[webhooks]]
url = "https://hooks.slack.com/services/T.../B.../xxx"
events = ["request_created", "request_approved", "request_rejected", "request_completed"]
format = "slack"
# secret = "whsec_..."           # HMAC-SHA256 signature (optional)
```

### Workflows

See [Workflows guide](../guides/workflows.md) for full configuration.

```toml
# Production: require admin approval
[[workflows]]
database = "*"
environment = "production"
operations = []                   # Empty = all operations (default)
require_reason = true             # Force --reason flag (default: false)
allow_self_approve = false        # Requester cannot approve own request (default)
allow_same_approver_across_steps = false  # Same person can't approve multiple steps (default)

[[workflows.steps]]
type = "approval"
[[workflows.steps.approvers]]
role = "admin"
min = 1

# Development: auto-approve (no steps = no approval needed)
[[workflows]]
database = "*"
environment = "development"
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

### Result policies (Pro)

```toml
[[result_policies]]
database = "primary"
environment = "production"
delivery_mode = "direct"          # "direct" (default) | "managed"
access = ["requester", "admin"]   # Who can view results (default)
```

### Notification policies (Pro)

```toml
[[notification_policies]]
database = "primary"
environment = "production"

[[notification_policies.webhooks]]
url = "https://hooks.slack.com/services/..."
events = ["request_created", "request_approved"]
format = "slack"
```

### Access policies

```toml
[[access_policies]]
database = "primary"
environment = "production"
allowed_roles = ["admin", "dba"]
allowed_groups = ["backend-team"]
```

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
  --data /var/lib/dbward/dbward.db \
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
  ghcr.io/dbward-dev/dbward:latest \
  dbward-server \
    --config /etc/dbward/dbward-server.toml \
    --data /data/dbward.db \
    --listen 0.0.0.0:3000
```

## Token management

Create tokens for users and agents:

```bash
# Admin token (full access)
dbward token create --user alice --role admin --data /var/lib/dbward/dbward.db

# Developer token
dbward token create --user bob --role developer --data /var/lib/dbward/dbward.db

# Agent token (for dbward-agent)
dbward token create --user prod-agent --role admin --agent --data /var/lib/dbward/dbward.db
```

Tokens can also be managed via the REST API:

```bash
# Create with TTL and metadata
curl -X POST http://localhost:3000/api/tokens \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "subject_id": "bob",
    "role": "developer",
    "subject_type": "user",
    "name": "Bob laptop",
    "groups": ["backend-team"],
    "expires_in": 7776000
  }'
# Also supports "expires_at": "2026-08-01T00:00:00Z" (RFC 3339)

# List tokens (shows prefix, status, expires_at — never the raw token)
curl http://localhost:3000/api/tokens -H "Authorization: Bearer $ADMIN_TOKEN"

# Revoke (admin can revoke any token; users can revoke their own)
curl -X DELETE http://localhost:3000/api/tokens/$TOKEN_ID \
  -H "Authorization: Bearer $TOKEN"
```

## Health checks

```bash
# Liveness
curl http://localhost:3000/health
# → {"status": "ok"}

# Readiness (returns 200 or 503, no body)
curl -o /dev/null -w "%{http_code}" http://localhost:3000/ready
# → 200
```

## Metrics

```bash
# Requires admin authentication
curl http://localhost:3000/metrics -H "Authorization: Bearer $ADMIN_TOKEN"
# → Prometheus text format
```

## Backup

The server stores all state in a single SQLite file. Back it up with:

```bash
# Simple copy (while server is running — SQLite WAL mode is safe)
cp /var/lib/dbward/dbward.db /backup/dbward-$(date +%Y%m%d).db

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

## Next steps

- [Agent setup](agent.md) — Connect agents to your databases
- [Authentication](authentication.md) — Configure OIDC or manage tokens
- [Workflows](../guides/workflows.md) — Set up approval rules
