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

The server automatically migrates the SQLite database on startup. A backup is created before any schema migration (`dbward.db.bak.v{N}`).

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

The server periodically checks GitHub Releases for new versions (when `update_check = true` in server config). The result is visible in:

```bash
curl http://localhost:3000/health
# {"status":"ok","version":"0.1.0","api_version":1,"schema_version":7,"update_available":"0.1.2"}
```

The CLI also displays a notification when a newer version is available.

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

- Minor versions (0.1.x) maintain API compatibility
- Feature versions (0.x.0) may introduce breaking changes (documented in CHANGELOG)
- SQLite schema changes are always forward-compatible (columns are added, never removed)
- Existing config files continue to work (new fields always have defaults)

## Rollback

```bash
# 1. Stop services
systemctl stop dbward-server dbward-agent

# 2. Restore previous binary
cp /usr/local/bin/dbward.bak /usr/local/bin/dbward
# Or: docker compose pull metapox/dbward:v0.1.0

# 3. Restore SQLite (only if schema changed)
cp dbward.db.bak.v7 dbward.db

# 4. Restart
systemctl start dbward-server dbward-agent
```
