---
title: "Quickstart: Try with Docker"
description: Experience the approval workflow in 2 minutes with Docker
---

# Quickstart: Try with Docker

See the full approval workflow: submit → approve → execute → audit.

**Prerequisites:** Docker, Docker Compose v2.

## 1. Start the stack

```bash
git clone https://github.com/dbward-dev/dbward.git && cd dbward/examples/quickstart
docker compose up -d
```

This starts:
- **PostgreSQL** — target database
- **dbward-server** — approval engine (port 13000)
- **dbward-agent** — executes approved queries on PostgreSQL

Wait for healthy state (~15 seconds):

```bash
docker compose ps   # all should show "healthy"
```

## 2. Run a query (auto-approved)

The `development` environment has no approval steps — queries execute immediately:

```bash
docker compose run --rm alice execute "SELECT version()" -e development
```

```
 version
──────────────────────────────────────
 PostgreSQL 17.2 on x86_64-pc-linux...
(1 row)

Completed in 52ms
```

**That's the 30-second check.** dbward is working. Alice (requester) submitted a query, the agent executed it on PostgreSQL, and the result came back.

## 3. Submit a query that needs approval

Now target `staging` — this environment requires admin approval:

```bash
docker compose run --rm alice execute "SELECT current_timestamp" -e staging
```

```
Request e5f6g7h8-... requires approval.
  Approvers: role:admin
Run: dbward request resume e5f6g7h8-...
```

The request is **pending** — it won't execute until an admin approves.

## 4. Approve (as bob)

Copy the request ID from step 3:

```bash
docker compose run --rm bob request approve e5f6g7h8 --comment "LGTM"
```

```
Approved step 1/1
Request e5f6g7h8 — all steps complete.
```

## 5. Get the result (as alice)

```bash
docker compose run --rm alice request resume e5f6g7h8
```

```
 current_timestamp
──────────────────────────────────
 2026-06-08 08:15:23.456789+00
(1 row)

Completed in 38ms
```

The agent executed the query on PostgreSQL after approval.

## 6. Check the audit trail

```bash
docker compose run --rm bob audit --limit 4
```

```
ID         TIMESTAMP              USER        EVENT              ENV      DATABASE  OUTCOME
96af1a07   2026-06-08T08:15:23    agent       request.executed   staging  app       success
d3e4f5a6   2026-06-08T08:15:22    requester   request_dispatched staging  app       success
c646583f   2026-06-08T08:15:20    admin       request.approved   staging  app       success
8f8c35a4   2026-06-08T08:15:16    requester   request.created    staging  app       success
```

Every action is recorded. Verify the tamper-evident hash chain:

```bash
docker compose run --rm bob audit --verify
```

```
✓ Hash chain intact (6 events verified)
```

## 7. Stop

```bash
docker compose down -v
```

---

## What just happened?

```
alice (requester)          bob (admin)              agent
     │                          │                      │
     ├─ execute (staging) ─────►│                      │
     │  "pending approval"      │                      │
     │                          │                      │
     │                          ├─ approve ───────────►│
     │                          │                      │
     ├─ resume ────────────────►│  dispatch ──────────►│
     │                          │                      ├─ execute on DB
     │  "current_timestamp"  ◄──│◄─────── result ──────┤
     │                          │                      │
     └──────── audit trail records everything ─────────┘
```

### Why did staging need approval?

The server config (`server.toml`) defines the rules:

```toml
# Development: auto-approve all
[[workflows]]
environment = "development"

[workflows.auto_approve]
mode = "always"

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

### How does alice/bob work?

The compose file has two CLI containers with different tokens:
- **alice** uses `requester-token` (can submit queries)
- **bob** uses `admin-token` (can approve requests)

Both read their token from files that the server creates on first startup.

---

## Troubleshooting

**First, run the doctor:**
```bash
docker compose run --rm alice doctor
```
This checks server connectivity, token validity, and agent status in one command.

**`docker compose ps` shows "unhealthy":**
```bash
docker compose logs server  # check for startup errors
```
Most common: the server needs a few more seconds. Wait and retry.

**"requires approval" but you can't approve:**
You're using alice (requester). Switch to bob (admin):
```bash
docker compose run --rm bob request approve <ID>
```

**Result shows "waiting for agent":**
The agent needs 1-2 seconds to poll and execute. Wait a moment, then run `request resume` again.

---

## See also

- [Connect your own database](quickstart-local.md) — use dbward with your real PostgreSQL or MySQL
- [Deploy to production](deployment/overview.md) — choose a deployment method for your team
- [MCP Integration](guides/mcp-integration.md) — connect AI agents (Claude, Cursor)
