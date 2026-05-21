# Upgrading dbward

## Update order

Always update in this order:

1. **Server** (holds state, runs schema migrations)
2. **Agent** (stateless, reconnects automatically)
3. **CLI** (each developer, at their own pace)

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
- `v0.1.2` — pinned to a specific release (recommended for production)
- `0.1` — tracks the latest patch within a minor version
- `latest` — latest release (for development)

```yaml
# compose.yml example
services:
  dbward-server:
    image: ghcr.io/dbward-dev/dbward-server:0.1
    # ...
```

## Binary

```bash
# Update CLI
dbward self-update

# Restart server (applies SQLite migrations on startup)
systemctl restart dbward-server

# Restart agent (gracefully drains in-flight jobs)
systemctl restart dbward-agent
```

## Checking for updates

Check the running server version and minimum supported agent version:

```bash
curl http://localhost:3000/health
# {"status":"ok","version":"0.1.2","min_agent_version":"0.1.2"}
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

### Breaking changes in v0.1.3

- `skip_approval_for` and `require_approval` workflow fields have been removed. If present in your config, the server will refuse to start with a clear error message explaining the migration.
- Auto-approve configuration moved from `[auto_approve]` (single global) to `[[auto_approve]]` (scoped array). See [Configuration Reference](../reference/configuration.md).
- SQLite schema V8 drops two columns from the `workflows` table. This migration runs automatically on startup. **Downgrade to v0.1.2 after this migration is not possible** without a backup.

## Rollback

```bash
# 1. Stop services
systemctl stop dbward-server dbward-agent

# 2. Restore previous binary
cp /usr/local/bin/dbward.bak /usr/local/bin/dbward
# Or: docker compose pull dbward-dev/dbward:v0.1.0

# 3. Restore SQLite (only if schema changed)
cp dbward.db.bak.v7 dbward.db

# 4. Restart
systemctl start dbward-server dbward-agent
```

## v0.1.2 Breaking Changes

### Helm chart: image values restructured

The single `image.*` block has been replaced with per-component image configuration:

```yaml
# Before (v0.1.1)
image:
  repository: ghcr.io/dbward-dev/dbward
  tag: "0.1.1"

# After (v0.1.2+)
server:
  image:
    repository: ghcr.io/dbward-dev/dbward-server
    tag: "0.1.2"
agent:
  image:
    repository: ghcr.io/dbward-dev/dbward-agent
    tag: "0.1.2"
```
