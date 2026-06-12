---
title: Deployment Overview
description: Production deployment architecture and method selection
---

# Deployment Overview

## Architecture

```
┌─────────────┐       ┌─────────────┐       ┌─────────────┐       ┌──────────┐
│   Clients   │──────▶│   Server    │◀──────│    Agent    │──────▶│ Database │
│ (CLI / MCP) │ HTTP  │ (REST API)  │ poll  │ (executor)  │  SQL  │(PG / MY) │
└─────────────┘       └─────────────┘       └─────────────┘       └──────────┘
```

- **Clients never touch the database.** They submit requests to the server and retrieve results.
- **Server never touches the database.** It manages approval state, audit logs, and routes requests.
- **Agent polls the server.** It runs in a network that can reach the database and fetches approved work via outbound HTTP.

## Deployment models

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

## Choose a deployment method

| Method | Page | Best for |
|--------|------|----------|
| Binary / systemd | [server.md](server.md) + [agent.md](agent.md) | Bare metal / VM |
| Docker Compose | [docker.md](docker.md) | Small teams, single host |
| ECS Fargate | [ecs.md](ecs.md) | AWS native |
| Kubernetes | [kubernetes.md](kubernetes.md) | K8s clusters |
| Helm | [helm.md](helm.md) | GitOps / Helm-managed clusters |

**Binary / systemd:** Deploy the server first, obtain bootstrap tokens, then deploy the agent.

**server.md and agent.md** are component references. All platform-specific pages (Docker, ECS, K8s, Helm) link back to them for configuration details.

## Network requirements

| From | To | Port | Protocol | Purpose |
|------|----|------|----------|---------|
| Client | Server | 3000 | HTTP/HTTPS | Submit requests, get results |
| Agent | Server | 3000 | HTTP/HTTPS | Poll for work, report results |
| Agent | Database | 5432/3306 | PostgreSQL/MySQL | Execute queries |

> The server needs no inbound access from the agent's network — the agent initiates all connections outbound.

> **Transport security:** The agent refuses to start if its `[server].url` is external HTTP (non-private IP, non-localhost). Use HTTPS for the agent→server connection, or set `allow_insecure = true` if TLS is handled at a network layer not visible in the URL.

## Security model

1. **No DB credentials on clients** — credentials exist only in the agent's config
2. **Signed execution tokens** — Ed25519 signatures prevent request tampering
3. **RBAC** — admin, developer, readonly roles enforced by the server
4. **Audit log** — every operation recorded with hash-chain integrity
5. **Fail-closed workflows** — if policy evaluation fails, the request is denied (not auto-approved)

## See also

- [Server configuration](server.md) — all server settings and operations
- [Agent configuration](agent.md) — agent settings, capabilities, resilience
- [Troubleshooting](troubleshooting.md) — common deployment issues
