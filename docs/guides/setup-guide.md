---
title: Setup Guide
description: Understand the architecture and set up dbward for your team
---

# Setup Guide

This guide explains how dbward works and walks you through a manual setup — no Docker required.
After this, you'll know exactly what each component does and how to configure it for production.

## Architecture

dbward has three components:

```
┌─────────┐         ┌──────────────┐         ┌─────────┐         ┌────┐
│  CLI /  │  HTTP   │    Server    │  poll    │  Agent  │  SQL    │ DB │
│  MCP    ├────────►│  (approval   │◄─────────┤  (exec) ├────────►│    │
│         │         │   + audit)   │          │         │         │    │
└─────────┘         └──────────────┘          └─────────┘         └────┘
```

| Component | Role | Touches the database? |
|-----------|------|:---------------------:|
| **Server** (`dbward-server`) | Approval engine, audit log, request routing | No |
| **Agent** (`dbward-agent`) | Executes approved queries on the target DB | Yes |
| **CLI** (`dbward`) | User interface for submitting/approving requests | No |

**Key design:** Only the agent has database credentials. The server and CLI never connect to your database.

---

## 1. Install

```bash
curl -fsSL https://dbward.dev/install.sh | sh
```

This installs `dbward`, `dbward-server`, and `dbward-agent` to `~/.dbward/bin` (or `/usr/local/bin`).

## 2. Server configuration

Create `dbward-server.toml`:

```toml
state_dir = "./data"              # SQLite state + bootstrap tokens

[[databases]]
name = "app"                      # logical name (referenced in agent config)
environments = ["staging", "production"]

# Staging: 1 admin approval required
[[workflows]]
database = "app"
environment = "staging"

[[workflows.steps]]
type = "approval"

[[workflows.steps.approvers]]
role = "admin"
min = 1

# Production: 2-step approval (developer review, then DBA)
[[workflows]]
database = "app"
environment = "production"

[[workflows.steps]]
type = "approval"

[[workflows.steps.approvers]]
role = "developer"
min = 1

[[workflows.steps]]
type = "approval"

[[workflows.steps.approvers]]
role = "dba"
min = 1
```

The `[[workflows]]` section is what controls approval behavior:
- No `steps` (or `steps = []`) → auto-approve (development mode)
- One step → single approval gate
- Multiple steps → sequential approval chain

→ Full reference: [Configuration](../reference/configuration.md)

## 3. Start the server

```bash
dbward-server --config dbward-server.toml --listen 127.0.0.1:3000
```

On first start, the server creates bootstrap tokens and writes them to `state_dir`:

```
[init] bootstrap tokens written to ./data/admin-token, ./data/agent-token
```

These files contain:
- `admin-token` — full admin access (create tokens, approve requests)
- `developer-token` — submit queries, view results
- `agent-token` — agent authentication (passed to agent config)

Token format: `dbw_` followed by 32 random characters (e.g. `dbw_k8f2m9...`).

## 4. Agent configuration

Create `dbward-agent.toml`:

```toml
agent_id = "agent-1"
poll_interval_ms = 1000

[server]
url = "http://127.0.0.1:3000"
agent_token = "${DBWARD_AGENT_TOKEN}"    # reads from environment variable

[databases.app.staging]
url = "postgres://user:password@db-host:5432/mydb"

[databases.app.production]
url = "postgres://user:password@db-host:5432/mydb"
```

The `[databases.<name>.<environment>]` mapping must match what the server declares in `[[databases]]`.

## 5. Start the agent

```bash
export DBWARD_AGENT_TOKEN=$(cat ./data/agent-token)
dbward-agent --config dbward-agent.toml
```

The agent connects to the server and polls for approved requests. When a request is approved, the agent:
1. Picks it up
2. Executes the SQL on the configured database
3. Reports the result back to the server

## 6. Create user tokens

Using the admin token, create tokens for your team:

```bash
# Create a developer token
curl -s -X POST http://127.0.0.1:3000/api/tokens \
  -H "Authorization: Bearer $(cat ./data/admin-token)" \
  -H "Content-Type: application/json" \
  -d '{"subject_id":"alice","roles":["developer"],"subject_type":"user"}' | jq .token

# Create an admin token (for approvals)
curl -s -X POST http://127.0.0.1:3000/api/tokens \
  -H "Authorization: Bearer $(cat ./data/admin-token)" \
  -H "Content-Type: application/json" \
  -d '{"subject_id":"bob","roles":["admin"],"subject_type":"user"}' | jq .token
```

## 7. Submit and approve a request

```bash
# Alice submits (developer token)
curl -s -X POST http://127.0.0.1:3000/api/requests \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"operation":"execute_select","environment":"staging","database":"app","detail":"SELECT count(*) FROM users"}'
```

```json
{"id": "req_xyz789", "status": "pending", "operation": "execute_select", "approvers": ["role:admin"]}
```

```bash
# Bob approves (admin token)
curl -s -X POST http://127.0.0.1:3000/api/requests/req_xyz789/approve \
  -H "Authorization: Bearer $BOB_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"comment":"Verified - safe read query"}'
```

```json
{"id": "req_xyz789", "status": "approved", "step_completed": true, "current_step": 1, "total_steps": 1}
```

```bash
# Alice dispatches (sends to agent for execution)
curl -s -X POST http://127.0.0.1:3000/api/requests/req_xyz789/resume \
  -H "Authorization: Bearer $ALICE_TOKEN"
```

```json
{"id": "req_xyz789", "status": "dispatched"}
```

The agent picks up the dispatched request, executes it on the database, and the result becomes available at `GET /api/requests/req_xyz789/result`.

---

## Troubleshooting

### Agent shows "unauthorized"

The agent token is invalid or expired. Check:
```bash
cat ./data/agent-token   # Does this file exist?
echo $DBWARD_AGENT_TOKEN # Does it match?
```

Fix: Restart the server with `--force-bootstrap` to regenerate tokens, then restart the agent.

### Request stuck in "pending_approval"

No user with the required role has approved it. Check the workflow config — the `approvers.role` must match a role assigned to the approving user's token.

```bash
# Check which role is needed:
curl -s http://127.0.0.1:3000/api/requests/req_xyz789 \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq .workflow
```

### "no matching workflow" error

The `database` + `environment` combination in the request doesn't match any `[[workflows]]` entry. dbward is fail-closed: if no workflow matches, the request is rejected.

Fix: Add a `[[workflows]]` section for the target database/environment pair.

---

## Next steps

- [Quickstart: Docker](../quickstart-docker.md) — see the approval flow in a self-contained demo
- [Deployment Overview](../deployment/overview.md) — production architecture with Docker/Kubernetes
- [Authentication](authentication.md) — set up OIDC for team login
- [Workflows](policies/workflows.md) — advanced approval policies
