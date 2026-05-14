# Agent Setup

The dbward agent is the **only component that connects to your database**. It polls the server for approved jobs, executes them, and returns results.

## Quick start

```bash
# 1. Create agent config
cat > dbward-agent.toml << 'EOF'
agent_id = "prod-agent-1"

[server]
url = "https://dbward.internal:3000"
agent_token = "${DBWARD_AGENT_TOKEN}"

[capabilities]
databases = ["app"]
environments = ["production", "staging"]
operations = ["*"]

[databases.app]
url = "${DATABASE_URL}"
EOF

# 2. Start
export DBWARD_AGENT_TOKEN="dbw_..."
export DATABASE_URL="postgres://dbward:pass@db.internal:5432/app"
dbward agent --config dbward-agent.toml
```

## Configuration reference

### Agent identity

```toml
agent_id = "prod-agent-1"        # Unique identifier (shown in audit logs)
poll_interval_ms = 1000           # How often to poll for jobs (default: 1000)
lease_duration_secs = 300         # Job lease timeout (default: 300)
drain_timeout_secs = 60           # Graceful shutdown timeout (default: 60)
max_concurrent_tasks = 2          # Parallel job execution (default: 2)
```

### Server connection

```toml
[server]
url = "https://dbward.internal:3000"
agent_token = "${DBWARD_AGENT_TOKEN}"   # Agent token (created with --agent flag)
```

The agent token must be created with `--agent` flag:

```bash
dbward token create --user prod-agent-1 --role admin --agent --data dbward.db
```

### Capabilities

Capabilities determine which jobs this agent can handle. The server matches jobs to agents based on these.

```toml
[capabilities]
databases = ["app"]               # Which databases this agent serves
environments = ["production"]     # Which environments ("*" = all)
operations = ["*"]                # Which operations ("*" = all)
```

### Database connections

```toml
[databases.app]
url = "postgres://user:pass@localhost:5432/mydb"
# migrations_dir = "db/migrations"  # Optional: override for this database

[databases.analytics]
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

[capabilities]
databases = ["app"]
environments = ["production"]
operations = ["*"]

[databases.app]
url = "postgres://...@prod-db:5432/app"
```

**Agent B** (`staging-agent.toml`):
```toml
agent_id = "staging-agent"

[capabilities]
databases = ["app", "analytics"]
environments = ["staging", "development"]
operations = ["*"]

[databases.app]
url = "postgres://...@staging-db:5432/app"

[databases.analytics]
url = "mysql://...@analytics:3306/warehouse"
```

The server automatically routes jobs to the correct agent based on capabilities matching.

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
  ghcr.io/dbward-dev/dbward:latest \
  dbward agent --config /etc/dbward/dbward-agent.toml
```

## Startup validation

On startup, the agent:
1. Validates the config file
2. Tests connectivity to each configured database
3. Registers with the server (first poll)

If database connectivity fails, the agent exits with an error. Fix the connection and restart.

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

## Next steps

- [Server setup](server.md) — Configure the server
- [Authentication](authentication.md) — Token management and OIDC
- [Workflows](../guides/workflows.md) — Configure approval rules
