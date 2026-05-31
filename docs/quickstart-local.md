---
title: "Quickstart: Connect Your Database"
description: Connect dbward to your existing PostgreSQL or MySQL in 1 minute
---

# Quickstart: Connect Your Database

Verify dbward works with your database. In dev mode, queries execute immediately (no approval required) — perfect for a quick smoke test.

**Prerequisites:** PostgreSQL or MySQL running and accessible.

## 1. Install

```bash
curl -fsSL https://dbward.dev/install.sh | sh
```

Installs `dbward`, `dbward-server`, and `dbward-agent` to `/usr/local/bin` (or `~/.dbward/bin`).

## 2. Start dev mode

```bash
dbward dev --database-url "postgres://user:password@localhost:5432/mydb"
```

For MySQL:
```bash
dbward dev --database-url "mysql://user:password@localhost:3306/mydb"
```

This starts a local server + agent in one process. All queries are auto-approved.

## 3. Run a query

In another terminal:

```bash
dbward --config ~/.dbward/dev/client.toml --database app execute "SELECT version()"
```

You should see the result immediately.

## 4. Experience the approval flow

Dev mode auto-approves everything by design (no workflow steps). To experience the full approval workflow with submit → approve → execute → audit:

👉 **[Try with Docker](quickstart-docker.md)** — a self-contained demo with staging approval enabled.

## Next steps

- [Try with Docker](quickstart-docker.md) — full approval flow demo
- [Team Setup](deployment/overview.md) — separate server + agent for your team
- [MCP Integration](guides/mcp-integration.md) — connect AI agents
