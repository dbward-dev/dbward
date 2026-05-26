# Getting Started

Get dbward running in 5 minutes.

## Prerequisites

- **PostgreSQL** or **MySQL** — a running instance you want to manage
- **Rust toolchain** — stable (for building from source)

## Install

```bash
git clone https://github.com/dbward-dev/dbward.git
cd dbward
cargo build --release
```

The binary is at `target/release/dbward`.

## Quick setup with preset

Generate production-ready config files for a small team (5-50 people):

```bash
dbward init --preset small-team
```

You'll be prompted for:
- **Server URL** (default: `http://localhost:3000`)
- **Database name** (default: `app`)

This creates 3 files:
- `dbward.toml` — CLI config (server URL, default database)
- `server.toml` — Approval workflows, auto-approve rules, SQL review
- `agent.toml` — Database connection placeholders

### Production startup

```bash
# 1. Start the server (auto-initializes on first run)
dbward-server --config server.toml

# First-run output (to stderr):
#   [init] bootstrap tokens written to ./data/admin-token, ./data/agent-token

# 2. Start the server
dbward-server --config server.toml

# 2. Set your CLI token
# Edit dbward.toml → token = "dbw_xxxx"

# 3. Set database URL and start the agent
export DATABASE_URL_APP_PRODUCTION="postgres://user:pass@host:5432/mydb"
export DBWARD_AGENT_TOKEN="dbw_zzzz"
dbward-agent --config agent.toml

# 4. Verify everything works
dbward doctor
dbward execute "SELECT 1"
```

### Generated workflow rules (small-team preset)

| Environment | Approval | Auto-approve |
|-------------|----------|--------------|
| development | None (empty steps) | Everything (unconditional, no risk check) |
| staging | 1 admin | SELECT + safe DDL only (Low risk) |
| production | 1 admin + reason required | Nothing (all human approval) |

## Start dev environment (alternative)

For quick local experimentation without separate server/agent processes:

```bash
dbward dev --database-url "postgres://user:password@localhost:5432/mydb"
```

For MySQL:

```bash
dbward dev --database-url "mysql://user:password@localhost:3306/mydb"
```

Example output:

```
dbward dev starting...
  Server: http://127.0.0.1:3000
  Database: mydb
  Admin token:     dbw_xxxx
  Developer token: dbw_yyyy
  Config: ~/.dbward/dev/client.toml

Try:
  dbward --config ~/.dbward/dev/client.toml execute "SELECT 1"
```

### What `dbward dev` does

- Starts a local server + agent in a single process
- **Auto-approves** all requests (no approval wait)
- Stores config and state in `~/.dbward/dev/`
- Generates API tokens automatically for admin and developer roles

> **Note:** `--config` points to the dev-mode client config. For production, place `dbward.toml` in your project root instead.

## Run your first query

```bash
dbward --config ~/.dbward/dev/client.toml execute "SELECT now()"
```

## Run a migration

```bash
# Create a new migration
dbward --config ~/.dbward/dev/client.toml migrate create add_users_table

# Edit the generated file (single-file dbmate format)
$EDITOR migrations/20260508120000_add_users_table.sql

# Apply
dbward --config ~/.dbward/dev/client.toml migrate up
```

Migration files use single-file [dbmate-compatible format](https://github.com/amacneil/dbmate):
```sql
-- migrate:up
CREATE TABLE users (id SERIAL PRIMARY KEY, name TEXT);

-- migrate:down
DROP TABLE users;
```

## What approval looks like

In production (when auto-approve is off), a request that requires approval exits with code **2**:

```bash
$ dbward execute "DELETE FROM orders WHERE created_at < '2025-01-01'"
Request abc12345-def6-7890-abcd-ef1234567890 is pending approval.
Approvers: @dba-team

# Check details (risk, EXPLAIN plan, etc.)
$ dbward request show abc12345-def6-7890-abcd-ef1234567890
Request abc12345-def6-7890-abcd-ef1234567890
  Status:      pending
  Detail:      DELETE FROM orders WHERE created_at < '2025-01-01'
  Risk:        Medium (LargeTable { rows: 50000 })
  SQL Review:  passed
  Tables:      orders
  Explain:     ModifyTable on orders via Seq Scan (rows=12000, cost=890)

# After someone approves:
$ dbward request resume abc12345-def6-7890-abcd-ef1234567890
```

dbward automatically assesses risk, runs EXPLAIN (read-only), and shows this context to approvers.

## What's next

- [Deployment Overview](deployment/overview.md) — architecture and deployment models
- [Workflows Guide](guides/workflows.md) — approval policies and conditions
- [MCP Integration](guides/mcp-integration.md) — use dbward as an MCP server for AI tools
- [Configuration Reference](reference/configuration.md) — all config options

## Key concepts

| Concept | Description |
|---------|-------------|
| **Request** | A unit of work (query or migration) submitted for execution |
| **Workflow** | Approval policy that determines whether a request needs human sign-off |
| **Agent** | Process that connects to the database and executes approved requests |
| **Server** | Central coordinator for approval state, audit logs, and request routing |
| **Break-glass** | Emergency bypass mechanism to skip approval in critical situations |
