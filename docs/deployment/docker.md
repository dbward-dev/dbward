---
title: Docker Compose Deployment
description: Deploy dbward with Docker Compose
---

# Docker Compose Deployment

Deploy dbward server and agent as a single Compose stack. For running individual containers without Compose, see [server.md](server.md) and [agent.md](agent.md).

**Template:** [`deploy/docker/compose.yml`](../../deploy/docker/compose.yml)

## Prerequisites

- Docker Engine 24+ and Docker Compose v2
- A PostgreSQL or MySQL database accessible from the Docker network

## Deploy

### 1. Create configuration files

**server.toml:**

```toml
state_dir = "/data"

[auth]
mode = "token"

[[databases]]
name = "app"
environments = ["production"]

[[workflows]]
database = "*"
environment = "production"

[[workflows.steps]]
type = "approval"

[[workflows.steps.approvers]]
role = "admin"
min = 1
```

**agent.toml:**

```toml
agent_id = "prod-agent"
poll_interval_ms = 1000

[server]
url = "http://server:3000"
agent_token = "${DBWARD_AGENT_TOKEN}"

[databases.app.production]
url = "${DATABASE_URL}"
```

### 2. Start the stack

```bash
cp deploy/docker/compose.yml .
docker compose up -d server
```

Start only the server first — you need its bootstrap tokens for the agent.

### 3. Get bootstrap tokens

```bash
docker compose exec server cat /data/admin-token
docker compose exec server cat /data/agent-token
```

### 4. Start the agent

```bash
export DBWARD_AGENT_TOKEN=dbw_...   # agent-token from step 3
export DATABASE_URL=postgres://user:pass@db-host:5432/app
docker compose up -d agent
```

## Volumes

| Volume | Mount | Purpose |
|--------|-------|---------|
| `server-data` | `/data` | SQLite state, signing keys, bootstrap tokens. **Must be persistent.** |

The agent is stateless — no persistent volume needed.

## TLS termination

The Compose template exposes port 3000 without TLS. For production, place a reverse proxy (nginx, Caddy, Traefik) in front:

```yaml
services:
  caddy:
    image: caddy:2
    ports:
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
    depends_on:
      - server
```

## Backup

The server stores all state in a single SQLite file at `/data/dbward.db`. Options:

- **Litestream** (continuous replication to S3) — see `deploy/scripts/litestream.yml`
- **Cron backup** — see `deploy/scripts/backup.sh`

Both scripts are designed to run alongside the server container.

## Upgrade

```bash
docker compose pull
docker compose up -d
```

The server applies SQLite migrations automatically on startup.

## Logging

The template uses `json-file` driver with 10MB rotation (3 files). Adjust in compose.yml if you use a centralized log collector.

## Next steps

- [Server configuration](server.md) — full configuration reference
- [Agent configuration](agent.md) — capabilities, resilience, multi-agent
- [Troubleshooting](troubleshooting.md) — common deployment issues
