---
title: "Quickstart: Try with Docker"
description: Experience the approval workflow in 2 minutes with Docker
---

# Quickstart: Try with Docker

See the full approval workflow in action: submit → approve → execute → audit.

**Prerequisites:** Docker, Docker Compose v2.

## 1. Start the stack

```bash
git clone https://github.com/dbward-dev/dbward.git && cd dbward/docs/examples/quickstart
docker compose up -d
```

This starts three services:
- **PostgreSQL** — target database
- **dbward-server** — approval engine (port 13000)
- **dbward-agent** — executes approved queries on PostgreSQL

Wait for all services to become healthy (~15 seconds):

```bash
docker compose ps   # all should show "healthy"
```

## 2. Get your tokens

The server creates bootstrap tokens on first startup. Retrieve them:

```bash
export ADMIN_TOKEN=$(docker compose exec -T server cat /data/admin-token)
export DEV_TOKEN=$(docker compose exec -T server cat /data/developer-token)
echo "Admin:     $ADMIN_TOKEN"
echo "Developer: $DEV_TOKEN"
```

Tokens look like `dbw_k8f2m9a3...` — a `dbw_` prefix followed by random characters.

## 3. Run a query (auto-approved)

The `development` environment has no approval steps — queries are dispatched to the agent immediately:

```bash
curl -s -X POST http://localhost:13000/api/requests \
  -H "Authorization: Bearer $DEV_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"operation":"execute_select","environment":"development","database":"app","detail":"SELECT version()"}' | jq .
```

Response:
```json
{
  "id": "a1b2c3d4-...",
  "status": "dispatched",
  "operation": "execute_select",
  "approvers": [],
  "idempotent": false,
  "expires_at": null
}
```

The agent picks this up and executes it within 1-2 seconds. Fetch the result:

```bash
REQ_ID=$(curl -s -X POST http://localhost:13000/api/requests \
  -H "Authorization: Bearer $DEV_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"operation":"execute_select","environment":"development","database":"app","detail":"SELECT version()"}' | jq -r .id)

# Wait for the agent to execute, then fetch the result:
sleep 2
curl -s http://localhost:13000/api/requests/$REQ_ID/result \
  -H "Authorization: Bearer $DEV_TOKEN" | jq .
```

```json
{
  "execution_id": "...",
  "success": true,
  "rows_affected": 1,
  "result_data": "version\n─────────────────\nPostgreSQL 17.2 ...\n(1 row)"
}
```

**That's the 30-second check** — dbward is working.

## 4. Submit a query that needs approval

Now target `staging` — this environment requires admin approval:

```bash
STAGING_REQ=$(curl -s -X POST http://localhost:13000/api/requests \
  -H "Authorization: Bearer $DEV_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"operation":"execute_select","environment":"staging","database":"app","detail":"SELECT current_timestamp"}' | jq -r .id)

echo "Request ID: $STAGING_REQ"
```

Response:
```json
{
  "id": "e5f6g7h8-...",
  "status": "pending",
  "operation": "execute_select",
  "approvers": ["role:admin"],
  "idempotent": false,
  "expires_at": null
}
```

The request is **pending** — it will not execute until an admin approves it.

## 5. Approve the request

```bash
curl -s -X POST http://localhost:13000/api/requests/$STAGING_REQ/approve \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"comment":"LGTM"}' | jq .
```

Response:
```json
{
  "id": "e5f6g7h8-...",
  "status": "approved",
  "approved_by": "admin",
  "step_completed": true,
  "current_step": 1,
  "total_steps": 1
}
```

## 6. Dispatch and get the result

After approval, the requester dispatches the request to the agent:

```bash
curl -s -X POST http://localhost:13000/api/requests/$STAGING_REQ/resume \
  -H "Authorization: Bearer $DEV_TOKEN" | jq .
```

```json
{"id": "e5f6g7h8-...", "status": "dispatched"}
```

Wait 1-2 seconds for the agent to execute, then fetch:

```bash
sleep 2
curl -s http://localhost:13000/api/requests/$STAGING_REQ/result \
  -H "Authorization: Bearer $DEV_TOKEN" | jq .result_data
```

```
"current_timestamp\n───────────────────────────────\n2026-06-07 23:30:00.123456+00\n(1 row)"
```

## 7. Check the audit trail

```bash
curl -s "http://localhost:13000/api/audit/events?limit=5" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq '.events[:4]'
```

```json
[
  {"event_type": "request_executed",   "actor_id": "agent",     "timestamp": "..."},
  {"event_type": "request_dispatched", "actor_id": "developer", "timestamp": "..."},
  {"event_type": "request_approved",   "actor_id": "admin",     "timestamp": "..."},
  {"event_type": "request_created",    "actor_id": "developer", "timestamp": "..."}
]
```

Every action is recorded in a tamper-evident hash chain.

## 8. Stop

```bash
docker compose down -v
```

---

## What just happened?

```
Developer                    Server                      Agent
    │                           │                          │
    ├─ POST /requests ─────────►│                          │
    │  (staging → pending)      │                          │
    │                           │                          │
Admin ─ POST /approve ────────►│                          │
    │  (→ approved)             │                          │
    │                           │                          │
Developer ─ POST /resume ─────►│─── dispatch ────────────►│
    │                           │                          ├─ execute on DB
    │                           │◄──── result ─────────────┤
    │                           │                          │
Developer ─ GET /result ──────►│                          │
    │  (current_timestamp)      │                          │
    │                           │                          │
    └────────── every step recorded in audit trail ────────┘
```

### Why did staging need approval?

The server config (`server.toml`) defines the rules:

```toml
# Development: no approval needed
[[workflows]]
environment = "development"
steps = []

# Staging: 1 admin must approve
[[workflows]]
environment = "staging"

[[workflows.steps]]
type = "approval"

[[workflows.steps.approvers]]
role = "admin"
min = 1
```

Change the config, change the rules.

### How did the agent get its token?

The server writes a bootstrap `agent-token` file to `/data/` on first start. The agent's entrypoint script waits for this file, reads it, and uses it to authenticate. No manual token management needed.

---

## Troubleshooting

**`docker compose ps` shows "unhealthy":**
```bash
docker compose logs server  # check for startup errors
```
Most common cause: the server needs a few more seconds. Wait and retry.

**Request stuck in "pending":**
No user with role `admin` has approved it. Verify you're using the admin token (not the developer token) for the approve call.

**Result returns empty after dispatch:**
The agent needs 1-2 seconds to poll, execute, and report. Increase the `sleep` or poll `GET /api/requests/{id}` until `status` is `"executed"`.

---

## Next steps

- [Connect your own database](quickstart-local.md) — use dbward with your real PostgreSQL or MySQL
- [Setup Guide](guides/setup-guide.md) — understand the full architecture and deploy to your team
- [MCP Integration](guides/mcp-integration.md) — connect AI agents (Claude, Cursor)
