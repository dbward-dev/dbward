---
title: "Quickstart: Connect Your Database"
description: Verify dbward works with your PostgreSQL or MySQL in 1 minute
---

# Quickstart: Connect Your Database

Connect dbward to your existing database and run a query. Dev mode auto-approves everything — perfect for a quick smoke test.

**Prerequisites:** PostgreSQL or MySQL running and accessible.

## 1. Install

```bash
curl -fsSL https://dbward.dev/install.sh | sh
```

## 2. Start dev mode

```bash
dbward dev --database-url "postgres://user:password@localhost:5432/mydb"
```

For MySQL:
```bash
dbward dev --database-url "mysql://user:password@localhost:3306/mydb"
```

Expected output:
```
dbward dev starting...
  Server: http://127.0.0.1:3000
  Database: postgres://user:***@localhost:5432/mydb

  Admin token:     dbw_a1b2c3...
  Developer token: dbw_d4e5f6...

  Config: ~/.dbward/dev/client.toml
  Try: dbward --config ~/.dbward/dev/client.toml --database app execute "SELECT 1"

Press Ctrl-C to stop.
```

This starts a local server + agent in one process. All queries are auto-approved.

## 3. Run a query

In another terminal:

```bash
dbward --config ~/.dbward/dev/client.toml --database app execute "SELECT version()"
```

Expected output:
```
 version
──────────────────────────
 PostgreSQL 17.2 ...
(1 row)

Completed in 45ms
```

If you see the result, dbward is correctly connected to your database.

## 4. Try the CLI

```bash
# List requests
dbward --config ~/.dbward/dev/client.toml request list

# View audit trail
dbward --config ~/.dbward/dev/client.toml audit
```

---

## Adding approval to your setup

Dev mode auto-approves everything. To require approval for production queries, create a config file (`dbward-server.toml`):

```toml
state_dir = "./data"

[[databases]]
name = "app"
environments = ["development", "production"]

# Development: auto-approve
[[workflows]]
environment = "development"
steps = []

# Production: require admin approval
[[workflows]]
environment = "production"

[[workflows.steps]]
type = "approval"

[[workflows.steps.approvers]]
role = "admin"
min = 1
```

Then run the server and agent separately instead of `dbward dev`. See the [Deployment Overview](deployment/overview.md) for production options.

---

## About `dbward dev`

`dbward dev` is a convenience shortcut that:
1. Writes a minimal server config to `~/.dbward/dev/server.toml`
2. Starts `dbward-server` with auto-approve for all environments
3. Waits for bootstrap tokens
4. Starts `dbward-agent` connected to your database
5. Prints a `client.toml` path for the CLI

In production, you run the server and agent as separate processes (or containers). See the [Deployment Overview](deployment/overview.md) for details.

---

## Next steps

- [Try with Docker](quickstart-docker.md) — full approval flow demo with submit → approve → execute
- [Deploy to production](deployment/overview.md) — choose a deployment method for your team
- [MCP Integration](guides/mcp-integration.md) — connect AI agents (Claude, Cursor)
