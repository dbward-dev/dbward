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

This creates 3 files:
- `dbward.toml` — CLI config (server URL, default database)
- `server.toml` — Approval workflows, auto-approve rules, SQL review
- `agent.toml` — Database connection placeholders

See the guided output for next steps, or continue below for a simplified dev environment.

## Start dev environment

For PostgreSQL:

```bash
dbward dev --database-url "postgres://user:password@localhost:5432/mydb"
```

For MySQL:

```bash
dbward dev --database-url "mysql://user:password@localhost:3306/mydb"
```

Example output:

```
[dbward] Server listening on http://127.0.0.1:3000
[dbward] Agent connected to database "mydb"
[dbward] Dev tokens generated:
           admin:     dbw_admin_xxxx
           developer: dbw_developer_xxxx
[dbward] Config written to ~/.dbward/dev/client.toml

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
