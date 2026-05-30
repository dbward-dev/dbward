---
title: "Quickstart: Connect Your Database"
description: Connect dbward to your existing PostgreSQL or MySQL in 3 minutes
---

# Quickstart: Connect Your Database

Connect dbward to an existing database and run your first query through the approval engine.

**Prerequisites:** PostgreSQL or MySQL running and accessible.

## 1. Download binaries

`dbward dev` runs server + agent internally, so all 3 binaries must be in the same directory.

Download from [GitHub Releases](https://github.com/dbward-dev/dbward/releases/latest) and extract. For example (macOS Apple Silicon, replace version as needed):

```bash
VERSION=0.1.3
TARGET=aarch64-apple-darwin

# Linux x86_64: TARGET=x86_64-unknown-linux-gnu
# Linux ARM64:  TARGET=aarch64-unknown-linux-gnu
# macOS Intel:  TARGET=x86_64-apple-darwin

for bin in dbward dbward-server dbward-agent; do
  curl -sL "https://github.com/dbward-dev/dbward/releases/download/v${VERSION}/${bin}-v${VERSION}-${TARGET}.tar.gz" | tar xz
done
```

## 2. Start dev mode

```bash
./dbward dev --database-url "postgres://user:password@localhost:5432/mydb"
```

For MySQL:
```bash
./dbward dev --database-url "mysql://user:password@localhost:3306/mydb"
```

Output:
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

## 3. Run a query

In another terminal:

```bash
./dbward --config ~/.dbward/dev/client.toml --database app execute "SELECT now()"
```

In dev mode, requests are auto-approved and executed immediately.

## 4. Next steps

- [Team Setup](deployment/overview) — separate server + agent for production
- [MCP Integration](guides/mcp-integration) — connect AI agents
- [Try with Docker](quickstart-docker) — full demo with approval flow
