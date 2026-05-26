# Deployment Overview

## Architecture

```
┌─────────────┐       ┌─────────────┐       ┌─────────────┐       ┌──────────┐
│   Clients   │──────▶│   Server    │◀──────│    Agent    │──────▶│ Database │
│ (CLI / MCP) │ HTTP  │ (REST API)  │ poll  │ (executor)  │  SQL  │(PG / MY) │
└─────────────┘       └─────────────┘       └─────────────┘       └──────────┘
```

## Key design decisions

- **Clients never touch the database.** They submit requests to the server and retrieve results.
- **Server never touches the database.** It manages approval state, audit logs, and routes requests.
- **Agent polls the server.** It runs in a network that can reach the database and fetches approved work via outbound HTTP.

## Deployment models

### Single machine

All three components in one process. Ideal for development and small teams.

```bash
dbward dev --database-url "postgres://..."
```

### Separated

Server on a central host, agent on a host with database access, CLI on developer machines.

```
Developer laptop  ──▶  Server (cloud VM)  ◀──  Agent (DB subnet)  ──▶  PostgreSQL
```

### Multi-agent

One server, multiple agents for different databases or environments.

```
                        ┌── Agent (staging) ──▶ Staging DB
Server ◀────────────────┤
                        └── Agent (prod)    ──▶ Production DB
```

Agents register with capabilities; the server matches requests to the appropriate agent.

## Quick start with Docker Compose

Generate config files first:

```bash
dbward init --preset small-team
```

Then use Docker Compose:

```yaml
services:
  server:
    image: dbward-server (built from source or Docker)
    ports:
      - "3000:3000"
    volumes:
      - ./server.toml:/etc/dbward/server.toml
      - server-data:/var/lib/dbward

  agent:
    image: dbward-agent (built from source or Docker)
    volumes:
      - ./agent.toml:/etc/dbward/agent.toml
    depends_on:
      - server

volumes:
  server-data:
```

## Configuration files

| Component | File | Purpose |
|-----------|------|---------|
| Server | `server.toml` | Listen address, auth keys, workflow policies, webhook config |
| Agent | `agent.toml` | Server URL, database connection, capabilities |
| Client | `client.toml` | Server URL, API token, default options |

## Network requirements

| From | To | Port | Protocol | Purpose |
|------|----|------|----------|---------|
| Client | Server | 3000 | HTTP/HTTPS | Submit requests, get results |
| Agent | Server | 3000 | HTTP/HTTPS | Poll for work, report results |
| Agent | Database | 5432/3306 | PostgreSQL/MySQL | Execute queries |

> The server needs no inbound access from the agent's network — the agent initiates all connections outbound.

## Security model

1. **No DB credentials on clients** — credentials exist only in the agent's config
2. **Signed execution tokens** — Ed25519 signatures prevent request tampering
3. **RBAC** — admin, developer, readonly roles enforced by the server
4. **Audit log** — every operation recorded with hash-chain integrity
5. **Fail-closed workflows** — if policy evaluation fails, the request is denied (not auto-approved)

## Next steps

- [Getting Started](../getting-started.md) — run dbward locally in 5 minutes
- [Workflows Guide](../guides/workflows.md) — configure approval policies
- [MCP Integration](../guides/mcp-integration.md) — connect AI tools via MCP
- [Configuration Reference](../reference/configuration.md) — full config options
