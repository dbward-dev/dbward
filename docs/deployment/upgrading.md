---
title: Upgrading
description: Upgrade dbward safely
---

# Upgrading dbward

## Update order

Always update in this order:

1. **Server** (holds state, runs schema migrations)
2. **Agent** (stateless, reconnects automatically)
3. **CLI** (each user, at their own pace)

## Docker Compose

```bash
docker compose pull
docker compose up -d
```

The server container stops gracefully (drains active requests), restarts with the new image, and applies any pending SQLite schema migrations. The agent waits for the server healthcheck before starting, ensuring correct update order automatically.

**Image registries:**
- `ghcr.io/dbward-dev/dbward-server`
- `ghcr.io/dbward-dev/dbward-agent`

**Tag options:**
- `v0.1.5` — pinned to a specific release (recommended for production)
- `latest` — latest release (for development)

```yaml
# compose.yml example
services:
  dbward-server:
    image: ghcr.io/dbward-dev/dbward-server:v0.1.5
    # ...
```

## Binary (systemd)

```bash
# 1. Stop services (agent first to drain in-flight jobs, then server)
systemctl stop dbward-agent
systemctl stop dbward-server

# 2. Update binaries (specify version, or omit for latest)
DBWARD_VERSION=0.2.0 curl -fsSL https://dbward.dev/install.sh | sh

# 3. Start services (server first — applies SQLite migrations on startup)
systemctl start dbward-server
systemctl start dbward-agent
```

> **Do not update binaries while services are running.** The install script overwrites files in place, which can corrupt a running process.

**Install script options:**

| Variable | Default | Description |
|----------|---------|-------------|
| `DBWARD_VERSION` | latest | Pin to a specific version |
| `DBWARD_INSTALL_DIR` | `/usr/local/bin` | Installation directory |
| `DBWARD_COMPONENTS` | `all` | `all`, `cli`, or comma-separated list (`dbward-server,dbward-agent`) |

**Update CLI on developer machines** (independent of server/agent):

```bash
dbward self-update
```

## Checking for updates

Check installed versions:

```bash
dbward --version          # CLI
dbward-server --version   # Server
dbward-agent --version    # Agent
```

Check the running server version and minimum supported agent version:

```bash
curl http://localhost:3000/health
# {"status":"ok","version":"0.1.5","min_agent_version":"0.1.5"}
```

The CLI displays a warning when the server version differs from the CLI version.

## SQLite backup

Before applying schema migrations, the server creates a backup:

```
dbward.db.bak.v7    ← backup of schema version 7 before migrating to 8
```

If an upgrade causes issues, restore the backup and use the previous binary:

```bash
cp dbward.db.bak.v7 dbward.db
# Use previous binary version
```

## Version compatibility

- All components within the same minor version (0.1.x) are compatible
- The server rejects poll requests from agents with a version older than `min_agent_version`
- The CLI shows a one-time warning when the server's minor version differs
- SQLite schema changes are forward-compatible within a minor version
- Downgrade is not supported for SQLite schema; use Litestream PITR or file backup

## Rollback

```bash
# 1. Stop services
systemctl stop dbward-server dbward-agent

# 2. Restore previous binary
cp /usr/local/bin/dbward.bak /usr/local/bin/dbward

# 3. Restore SQLite (only if schema changed)
cp dbward.db.bak.v7 dbward.db

# 4. Restart
systemctl start dbward-server dbward-agent
```
