---
title: Agent Setup
description: Deploy the dbward agent
---

# Agent Setup

The dbward agent is the **only component that connects to your database**. It polls the server for approved jobs, executes them, and returns results.

## How the Agent Works

### Polling architecture

The agent uses **outbound HTTP only**. It periodically polls the server for dispatched jobs — no inbound ports or firewall rules required. This simplifies deployment behind NATs, VPNs, and corporate firewalls.

### Capabilities matching

Each agent advertises its capabilities: `scopes` (database/environment pairs) and `operations`. The server uses these to route jobs to the correct agent. Only agents whose capabilities match a job will receive it during polling.

### Multi-agent

Multiple agents can connect to the same server simultaneously. When two agents poll and receive the same job, the `claim` endpoint resolves the race — only one agent wins the claim, the other receives a conflict response and moves on.

### Lease and heartbeat

After claiming a job, the agent has a lease period to complete it (configured via server-side `[[execution_policies]]`). During execution, the agent sends periodic heartbeats to extend the lease. If the agent crashes or loses connectivity, the lease expires and the job is marked `execution_lost`.

### Schema sync

On startup and periodically thereafter, the agent collects schema metadata (tables, columns, row estimates, foreign keys) from each configured database and sends it to the server. This powers risk scoring, SQL review, and `max_estimated_rows` checks.

### Dry-run EXPLAIN

For preview and approval context, the agent can execute `EXPLAIN` (read-only, no side effects) against the target database. The execution plan is attached to the request so approvers can assess impact before approving.

### Degraded mode

If a database connection is lost, the agent skips jobs targeting that database but continues serving other configured databases normally. It retries the failed connection each poll interval and resumes when connectivity is restored.

## Configuration reference

> Full configuration reference with all options: [Configuration](../reference/configuration.md)

### Agent identity

```toml
agent_id = "prod-agent-1"        # Unique identifier (shown in audit logs)
poll_interval_ms = 1000           # How often to poll for jobs (default: 1000)
drain_timeout_secs = 60           # Graceful shutdown timeout (default: 60)
max_concurrent_tasks = 2          # Parallel job execution (default: 2)
statement_timeout_secs = 30       # Default SQL statement timeout (default: 60)
```

> **Note**: `statement_timeout_secs` is the agent-level default. If a server-side `[[execution_policies]]` is configured for the target database/environment, the policy's `statement_timeout_secs` takes precedence.

> **Migration warning**: This timeout also applies to migrations. The default 30 seconds is likely too short for DDL operations on large tables. Configure a longer timeout via `[[execution_policies]]` for environments where migrations run.

### Server connection

```toml
[server]
url = "https://dbward.internal:3000"
agent_token = "${DBWARD_AGENT_TOKEN}"   # Agent token (created with --agent flag)
```

The agent token must be created with `--subject-type agent`:

```bash
dbward token create --subject prod-agent-1 --subject-type agent --no-scope-ceiling
```

### Capabilities

Capabilities determine which jobs this agent can handle. **Scopes (database/environment pairs) are derived automatically** from the `[databases]` section keys. Only `operations` is configurable:

```toml
# Optional: limit which operations this agent handles (default: all)
# operations = ["execute_select", "execute_dml", "migrate_up", "migrate_down", "migrate_status"]
```

For example, if the config has `[databases.app.production]` and `[databases.app.staging]`, the agent advertises scopes `(app, production)` and `(app, staging)`.

### Database connections

```toml
[databases.app.production]
url = "postgres://user:pass@localhost:5432/mydb"
# migrations_dir = "db/migrations"  # Optional: override for this database

[databases.analytics.production]
url = "mysql://user:pass@analytics.internal:3306/warehouse"
```

Supported URL schemes:
- `postgres://` or `postgresql://` — PostgreSQL
- `mysql://` — MySQL

## Multiple agents

Deploy multiple agents for different databases or environments:

```
┌──────────────┐
│ Server       │
└──┬───────┬───┘
   │       │
   ▼       ▼
Agent A   Agent B
(prod)    (staging + analytics)
```

**Agent A** (`prod-agent.toml`):
```toml
agent_id = "prod-agent"

[server]
url = "https://dbward.internal:3000"
agent_token = "${DBWARD_AGENT_TOKEN}"

[databases.app.production]
url = "postgres://...@prod-db:5432/app"
```

**Agent B** (`staging-agent.toml`):
```toml
agent_id = "staging-agent"

[server]
url = "https://dbward.internal:3000"
agent_token = "${DBWARD_AGENT_TOKEN}"

[databases.app.staging]
url = "postgres://...@staging-db:5432/app"

[databases.analytics.staging]
url = "mysql://...@analytics:3306/warehouse"
```

The server automatically routes jobs based on each agent's `[databases]` keys.

## Job execution flow

```
1. Agent polls: POST /api/agent/poll (with capabilities)
2. Server returns a dispatched job (if any match)
3. Agent claims: POST /api/agent/jobs/{id}/claim
4. Agent executes the SQL against the target database
5. Agent returns result: POST /api/agent/jobs/{id}/result
6. Server relays result to the waiting client
```

The agent sends periodic heartbeats during execution to extend the lease. If the agent crashes, the lease expires and the job is marked `execution_lost`.

## Validate before starting

After writing your configuration, validate it before starting the agent:

```bash
dbward doctor --agent /path/to/agent.toml
```

This checks config parsing, environment variables, server reachability, token validity, and database URL scheme — catching issues before the agent attempts to connect.

## Running with systemd

```ini
# /etc/systemd/system/dbward-agent.service
[Unit]
Description=dbward agent
After=network.target

[Service]
Type=simple
User=dbward
Environment=DBWARD_AGENT_TOKEN=dbw_...
Environment=DATABASE_URL=postgres://...
ExecStart=/usr/local/bin/dbward agent --config /etc/dbward/dbward-agent.toml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## Running with Docker

```bash
docker run -d \
  --name dbward-agent \
  --network db-network \
  -e DBWARD_AGENT_TOKEN=dbw_... \
  -e DATABASE_URL=postgres://user:pass@db:5432/app \
  -v ./dbward-agent.toml:/etc/dbward/dbward-agent.toml:ro \
  ghcr.io/dbward-dev/dbward-agent:latest \
  --config /etc/dbward/dbward-agent.toml
```

## Startup and resilience

On startup, the agent:
1. Creates a **liveness probe** immediately (`/tmp/dbward-agent-alive`)
2. Retries connecting to the server (fetch public key + initial poll)
3. Retries connecting to each configured database
4. Once all prerequisites pass, creates a **readiness probe** (`/tmp/dbward-agent-ready`)

If the server or database is temporarily unavailable, the agent retries with exponential backoff (1s → 2s → 4s → 8s → 15s cap) instead of exiting. This prevents CrashLoopBackOff in Kubernetes when services start simultaneously.

**Hard errors** cause immediate exit (no retry):
- Authentication failures (wrong token, wrong DB password)
- Invalid configuration (unsupported URL scheme, 4xx from server)

**Transient errors** are retried:
- Connection refused, timeouts, DNS failures, 5xx responses

### Runtime resilience

During normal operation:
- If the server becomes unreachable, the agent stops accepting new jobs (readiness removed) but stays alive and retries
- If a database connection is lost during job execution, the agent enters **degraded mode**: stops accepting jobs, attempts reconnection every poll interval, and resumes when connectivity is restored
- SIGTERM/SIGINT triggers graceful shutdown at any phase (including during startup retries)

**Server-side visibility:** From the operator's perspective, the server considers an agent offline if no poll is received for 60 seconds — regardless of the cause (process crash, network partition, or host failure). Query `GET /api/agents` (requires `metrics.view` permission) to check. See [Server Health checks](server.md#health-checks).

### Configuration

```toml
startup_retry_initial_ms = 1000   # Initial retry delay (default: 1000)
startup_retry_max_ms = 15000      # Max retry delay cap (default: 15000)
startup_max_wait_secs = 60        # default 60s, 0 = retry forever
```

## Graceful shutdown

On SIGTERM/SIGINT:
1. Stops accepting new jobs
2. Waits for in-flight jobs to complete (up to `drain_timeout_secs`)
3. Exits cleanly

## Security considerations

- **Least privilege:** Create a dedicated database user for the agent with only the permissions needed (e.g., SELECT + DML, no DDL for production)
- **Network isolation:** The agent only needs outbound access to the server and the database. No inbound ports required.
- **Token rotation:** Rotate agent tokens periodically. Create a new token, update the agent config, restart, then revoke the old token.
- **Environment variables:** Use `${ENV_VAR}` in TOML to avoid hardcoding credentials.

## See also

- [Server setup](server.md) — Configure the server
- [Authentication](../guides/authentication.md) — Token management and OIDC
- [Workflows](../guides/policies/workflows.md) — Configure approval rules
- [Troubleshooting](troubleshooting.md) — Common deployment issues
