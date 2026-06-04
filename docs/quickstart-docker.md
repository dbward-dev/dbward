---
title: "Quickstart: Try with Docker"
description: Experience the full approval workflow in 5 minutes — no install required
---

# Quickstart: Try with Docker

Submit a query, get it approved, see the result, verify the audit trail. All in Docker — nothing to install on your machine.

**Prerequisites:** Docker, Docker Compose v2, and python3 (for the token setup script).

## 1. Clone and set up

```bash
git clone https://github.com/dbward-dev/dbward.git
cd dbward
./dev/scripts/dev-setup.sh
```

## 2. Start the stack

```bash
DBWARD_SERVER_CONFIG=server-quickstart.toml \
  docker compose -f dev/compose.yml -f dev/compose.override.yml up -d
```

This starts PostgreSQL, the dbward server (approval engine), and an agent (connected to PostgreSQL). Wait ~15 seconds for all services to become healthy.

## 3. Create user tokens

```bash
./dev/scripts/quickstart-init.sh
```

This creates two users:
- **alice** — developer (can submit queries)
- **bob** — admin (can approve requests)

## 4. Submit a query (alice)

Alice submits a query to the staging environment:

```bash
docker compose -f dev/compose.yml -f dev/compose.override.yml \
  --profile dev run --rm alice \
  execute "SELECT version()" \
  --database app --environment staging
```

Output:
```
Request a1b2c3d4-... requires approval.
  Approvers: role:admin
Run: dbward request resume a1b2c3d4-...
```

The request is **pending** — it won't execute until approved.

## 5. Approve (bob)

Copy the request ID from the output above, then:

```bash
docker compose -f dev/compose.yml -f dev/compose.override.yml \
  --profile dev run --rm bob \
  request approve <REQUEST_ID> --comment "Looks good"
```

Output:
```
Approved step 1/1
Request: a1b2c3d4
All steps complete. Agent has been dispatched.
```

## 6. Get the result (alice)

```bash
docker compose -f dev/compose.yml -f dev/compose.override.yml \
  --profile dev run --rm alice \
  request resume <REQUEST_ID>
```

Output:
```
Waiting for agent to execute...
 version
---------
 PostgreSQL 17.x ...
(1 row)
```

The agent executed the query on PostgreSQL after approval.

## 7. Check the audit trail (bob)

```bash
docker compose -f dev/compose.yml -f dev/compose.override.yml \
  --profile dev run --rm bob audit
```

Output:
```
ID         TIMESTAMP              USER    EVENT              ENV      DATABASE  OUTCOME
96af1a07   2026-05-31T12:55:30    agent   request_completed  staging  app       success
c646583f   2026-05-31T12:55:25    bob     request_approved   staging  app       success
8f8c35a4   2026-05-31T12:55:16    alice   request_created    staging  app       success
...
```

Every action is recorded. Verify the tamper-evident hash chain:

```bash
docker compose -f dev/compose.yml -f dev/compose.override.yml \
  --profile dev run --rm bob audit --verify
```

```
✓ Hash chain intact (15 events verified)
```

## 8. Stop

```bash
docker compose -f dev/compose.yml -f dev/compose.override.yml down
```

Add `-v` to also remove the database volume.

## What just happened?

```
alice (developer)          bob (admin)              agent
     │                          │                      │
     ├─ execute SELECT ─────────►│                      │
     │  "pending"               │                      │
     │                          ├─ approve ───────────►│
     │                          │                      ├─ execute on DB
     ├─ resume ────────────────►│                      │
     │  "PostgreSQL 17.x ..."   │                      │
     │                          │                      │
     └──────── audit trail records everything ─────────┘
```

- **Development** environment auto-approves everything (for fast iteration)
- **Staging** requires 1 admin approval (what you just tried)
- **Production** can require multi-step approval with distinct approvers

## Next steps

- [Connect your own database](quickstart-local.md) — use dbward with your real PostgreSQL or MySQL
- [Workflows Guide](guides/policies/workflows.md) — customize approval policies
- [MCP Integration](guides/mcp-integration.md) — connect AI agents (Claude, Cursor)
- [Deployment Overview](deployment/overview.md) — production architecture
