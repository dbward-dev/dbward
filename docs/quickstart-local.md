---
title: "Quickstart: Connect Your Database"
description: Connect dbward to your existing PostgreSQL or MySQL in 3 minutes
---

# Quickstart: Connect Your Database

Connect dbward to an existing database and run your first query through the approval engine.

**Prerequisites:** PostgreSQL or MySQL running and accessible.

## 1. Install

The install script downloads `dbward`, `dbward-server`, and `dbward-agent`:

```bash
curl -fsSL https://dbward.dev/install.sh | sh
```

Installs to `/usr/local/bin` (or `~/.dbward/bin` if no write access).

## 2. Start dev mode

```bash
dbward dev --database-url "postgres://user:password@localhost:5432/mydb"
```

For MySQL:
```bash
dbward dev --database-url "mysql://user:password@localhost:3306/mydb"
```

Output:
```
dbward dev starting...
  Server: http://127.0.0.1:3000
  Database: postgres://user:password@localhost:5432/mydb
  Admin token:     dbw_xxxx
  Developer token: dbw_yyyy
  Config: ~/.dbward/dev/client.toml

Try: dbward --config ~/.dbward/dev/client.toml --database app execute "SELECT 1"
```

## 3. Run a query

In another terminal:

```bash
dbward --config ~/.dbward/dev/client.toml --database app execute "SELECT now()"
```

In dev mode, requests are auto-approved and executed immediately.

## 4. Next steps

- [Team Setup](deployment/overview.md) — separate server + agent for production
- [MCP Integration](guides/mcp-integration.md) — connect AI agents
- [Try with Docker](quickstart-docker.md) — full demo with approval flow
