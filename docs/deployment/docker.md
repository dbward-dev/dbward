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

Create `server.toml` and `agent.toml` in the same directory as `compose.yml`. See [server configuration](server.md) and [agent configuration](agent.md) for all options, or use the [full configuration reference](../reference/configuration.md).

Minimal example for `agent.toml`:

```toml
agent_id = "prod-agent"
poll_interval_ms = 1000

[server]
url = "http://server:3000"
agent_token = "${DBWARD_AGENT_TOKEN}"

[databases.app.production]
url = "${DATABASE_URL}"
```

> **Note:** The agent's `[server].url` must be `http://server:3000` (the Compose service name). This is a bare hostname (no dots), which is recognized as cluster-internal — HTTPS is not required for intra-Compose communication.

### 2. Start the stack

```bash
cp deploy/docker/compose.yml deploy/docker/Caddyfile .
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

The Compose template binds the server to `127.0.0.1:3000` (localhost only). For external HTTPS access, enable the built-in Caddy profile:

```bash
DOMAIN=dbward.example.com docker compose --profile tls up -d
```

This starts a [Caddy](https://caddyserver.com/) reverse proxy that automatically obtains a Let's Encrypt certificate for your domain.

| Environment variable | Default | Description |
|---|---|---|
| `DOMAIN` | `localhost` | Domain for TLS certificate. Set to your public domain for production. |

**How it works:**
- Caddy listens on ports 443 (HTTPS) and 80 (HTTP-01 challenge + redirect).
- Traffic is proxied to `server:3000` over the internal Docker network.
- Certificates are persisted in the `caddy-data` volume and auto-renewed.

**Required: `trusted_proxies` configuration.** When running behind Caddy, add the Docker network subnet to `server.toml` so the server honors `X-Forwarded-For` headers for audit logging:

```bash
# Find the actual subnet assigned to the Compose default network:
docker compose exec server cat /proc/net/fib_trie | grep -B1 '/16\|/24' | head -5
# Or inspect the network directly (name depends on your project directory):
docker network inspect $(docker compose config --format json | jq -r '.networks.default.name') --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}'
```

```toml
[server]
trusted_proxies = ["172.18.0.0/16"]  # use the subnet from the command above
```

Without this, audit logs will record the Caddy container IP instead of the real client IP.

**Local development:** With `DOMAIN=localhost` (default), Caddy issues a certificate from its internal CA. The browser will show a certificate warning. To suppress it, extract and trust the Caddy root CA on your host:

```bash
docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt /tmp/caddy-root.crt
# macOS:
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain /tmp/caddy-root.crt
# Linux:
sudo cp /tmp/caddy-root.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates
```

**Operational notes:**
- Port 80 and 443 must be free on the host. If another reverse proxy is already bound, disable it or use that proxy instead.
- The `DOMAIN` must resolve to the host and port 80 must be internet-reachable for Let's Encrypt HTTP-01 issuance and renewal.
- Back up the `caddy-data` volume. Losing it is recoverable but triggers certificate re-issuance, which may hit Let's Encrypt [rate limits](https://letsencrypt.org/docs/rate-limits/).
- `127.0.0.1:3000` remains accessible from the host for debugging. This is intentional — the security boundary is remote network access, not host-local isolation.

> **Internal vs external:** Agent↔Server communication within Compose uses the `server` service name (bare hostname), which is treated as internal — no TLS required. CLI access from outside the Compose network should go through the Caddy reverse proxy (HTTPS).

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

## See also

- [Server configuration](server.md) — full configuration reference
- [Agent configuration](agent.md) — capabilities, resilience, multi-agent
- [Troubleshooting](troubleshooting.md) — common deployment issues
