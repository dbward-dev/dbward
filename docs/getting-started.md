# Getting Started

Get dbward running in 5 minutes.

## Prerequisites

- **PostgreSQL** or **MySQL** — a running instance you want to manage
- **Rust toolchain** — stable (for building from source)

## Install

```bash
git clone https://github.com/metapox/dbward.git
cd dbward
cargo build --release
```

The binary is at `target/release/dbward`.

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
[dbward] Server listening on http://127.0.0.1:7890
[dbward] Agent connected to database "mydb"
[dbward] Dev tokens generated:
           admin:     dw_dev_admin_xxxx
           developer: dw_dev_developer_xxxx
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

# Edit the generated files
$EDITOR db/migrations/20260508_add_users_table/up.sql
$EDITOR db/migrations/20260508_add_users_table/down.sql

# Apply
dbward --config ~/.dbward/dev/client.toml migrate up
```

Migration files are created as a directory under `./db/migrations/` with `up.sql` and `down.sql` inside.

## What approval looks like

In production (when auto-approve is off), a request that requires approval exits with code **2**:

```bash
$ dbward execute "DROP TABLE old_data"
Request rq_abc123 is pending approval.
Approvers: @dba-team

# After someone approves:
$ dbward resume rq_abc123
```

Exit code 2 signals "pending" — useful for CI/CD pipelines that need to wait for human approval.

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
