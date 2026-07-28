---
title: Setup Guide
description: Step-by-step guide to deploy dbward server + agent and connect your CLI
---

# Setup Guide

This guide walks you through deploying dbward from scratch: generate config files, start the server, connect an agent, and run your first query through the approval workflow.

**Time:** 10–15 minutes

**Prerequisites:**

- dbward CLI installed (`curl -fsSL https://dbward.dev/install.sh | sh`)
- A PostgreSQL or MySQL database accessible from the agent host
- A host for the server (VM, container, or local machine)

> **Just want a quick smoke test?** See [Quickstart: Connect Your Database](../quickstart-local.md) to try `dbward dev` in 1 minute.

---

## Step 1: Generate configuration files

> **Run on:** your laptop

```bash
mkdir my-dbward && cd my-dbward
dbward init --preset small-team
```

You'll be prompted for:

| Prompt | Default | Description |
|--------|---------|-------------|
| Server URL | `http://localhost:3000` | Where clients will reach the server |
| Database name | `app` | Logical name for your database |

This creates three files:

| File | Purpose |
|------|---------|
| `dbward.toml` | CLI project config (server URL, default database, migrations dir) |
| `server.toml` | Server config (databases, workflows, policies) |
| `agent.toml` | Agent config (server connection, database URLs) |

> **Tip:** Use `--dry-run` to preview without writing files. Use `--non-interactive` for CI/automation.

---

## Step 2: Review server.toml

> **Run on:** your laptop

The generated `server.toml` includes sensible defaults for a small team:

- **Development:** auto-approve all queries
- **Staging:** auto-approve low-risk, require admin approval for others
- **Production:** always require admin approval + reason

Customize as needed. Key sections:

```toml
# Register your database
[[databases]]
name = "app"
environments = ["development", "staging", "production"]

# Workflow rules (who approves what)
[[workflows]]
database = "*"
environment = "production"
require_reason = true

[[workflows.steps]]
type = "approval"

[[workflows.steps.approvers]]
role = "admin"
min = 1

# SQL safety rules
[[sql_review]]
database = "*"
environment = "*"
no_where_delete = "block"
no_where_update = "block"
```

See [Configuration Reference](../reference/configuration.md) for all options.

---

## Step 3: Start the server

> **Run on:** server host (VM, container, or local machine)

Copy `server.toml` to your server host and start the server:

```bash
dbward-server validate --config server.toml   # validate config before starting
dbward-server --config server.toml --listen 0.0.0.0:3000
```

On first start, the server:

1. Creates the SQLite state database in `state_dir`
2. Generates an Ed25519 signing key pair
3. Creates bootstrap tokens and writes them to files:
   - `/data/admin-token` — full admin access
   - `/data/agent-token` — for agent authentication

```
[INFO] Server listening on 0.0.0.0:3000
[INFO] First run — bootstrap tokens created
[INFO]   admin-token: /data/admin-token
[INFO]   agent-token: /data/agent-token
```

> **Docker/ECS:** The tokens are written to `state_dir`. Mount a persistent volume so they survive restarts. See [ECS Deployment](../deployment/ecs.md) or [Docker Deployment](../deployment/docker.md).

---

## Step 4: Configure CLI token

> **Run on:** your laptop

Retrieve the admin token from the server host (it was written to `{state_dir}/admin-token` in Step 3). Then set it in `dbward.toml`:

```toml
[server]
url = "http://your-server:3000"
token = "dbw_a1b2c3..."   # paste your admin token here
```

Alternatively, use an environment variable:

```bash
export DBWARD_TOKEN="dbw_a1b2c3..."
```

Verify the connection:

```bash
dbward whoami
# → Subject: admin (user)
#   Roles:   admin, requester
```

---

## Step 5: Start the agent

> **Run on:** a host with database network access

Copy `agent.toml` and the agent token to this host. The agent needs:

- The server URL (to poll for work)
- An agent token (from `{state_dir}/agent-token` on the server host)
- Database connection URL(s)

Set the required environment variables and start:

```bash
export DBWARD_AGENT_TOKEN="dbw_..."  # agent token from server host
export DATABASE_URL_PRODUCTION="postgres://user:pass@db-host:5432/mydb"

dbward-agent validate --config agent.toml     # validate config before starting
dbward-agent --config agent.toml
```

The agent will connect to the server and register its capabilities:

```
[INFO] Agent "my-host" connected to http://localhost:3000
[INFO] Registered databases: app/production
[INFO] Polling for tasks...
```

> **Network requirement:** The agent must reach both the server (HTTP) and the database (PostgreSQL/MySQL). The server does NOT need to reach the database.

---

## Step 6: Run your first query

> **Run on:** your laptop

```bash
# Development (auto-approved):
dbward execute "SELECT version()" -e development

# Production (requires approval):
dbward execute "SELECT count(*) FROM users" -e production --reason "user count check"
```

For production queries, the workflow kicks in:

```
Request a1b2c3d4-... requires approval.
  Approvers: role:admin
Run: dbward request resume a1b2c3d4-...
```

Approve it (as admin):

```bash
dbward request approve a1b2c3d4
```

Then retrieve the result:

```bash
dbward request resume a1b2c3d4
```

---

## Step 7: Create tokens for your team

> **Run on:** your laptop (admin user)

Don't share the admin token. Create scoped tokens for team members:

```bash
# Requester (can submit queries, cannot approve)
dbward token create --subject alice --scope-roles requester

# Approver (can approve, cannot submit)
dbward token create --subject bob --scope-roles approver

# Admin (full access)
dbward token create --subject carol --scope-roles admin
```

Each user sets their token in their own `~/.config/dbward/config.toml`:

```toml
[server]
url = "http://your-server:3000"
token = "dbw_..."
```

Or they can run `dbward init` and enter the server URL + token interactively.

---

## What's next?

| Topic | Link |
|-------|------|
| Approval workflows | [Workflows Guide](policies/workflows.md) |
| Auto-approve rules | [Auto-Approve](policies/auto-approve.md) |
| OIDC/SSO login | [Authentication](authentication.md) |
| Slack integration | [Slack Guide](slack.md) |
| MCP for AI agents | [MCP Integration](mcp-integration.md) |
| Production deployment | [Deployment Overview](../deployment/overview.md) |
| SQL safety rules | [SQL Safety Reference](../reference/sql-safety.md) |

---

## Troubleshooting

**"connection refused" on dbward doctor:**
Server is not running or URL is wrong. Check `server.toml` and ensure the server process is up.

**"token invalid" or "unauthorized":**
Token doesn't match what the server generated. Re-read from `/data/admin-token`.

**"no agent available":**
Agent is not running, or it registered for a different database/environment. Check agent logs and ensure `[databases]` section matches what the server expects.

**Agent refuses to start with "insecure transport":**
Agent rejects HTTP connections to non-local servers by default. Either use HTTPS (recommended) or set `allow_insecure = true` in agent.toml's `[server]` section.

See [Troubleshooting](../deployment/troubleshooting.md) for more.
