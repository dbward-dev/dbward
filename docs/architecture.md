---
title: Architecture
description: System components and data flow
---

# Architecture

## Design Principles

1. **Clients never touch DB** — CLI/MCP has no DB credentials
2. **Server never touches DB** — manages auth, policy, state only
3. **Agent polls** — all connections outbound; no inbound ports needed

## Components

```
┌─────────────────────────────────────────────┐
│ AI Client (Kiro / Cursor / Copilot)         │
└──────────────┬──────────────────────────────┘
               │ MCP (JSON-RPC over stdio)
               ▼
┌─────────────────────────────────────────────┐
│ Client (dbward-cli / dbward mcp)            │
│  NO DB credentials. Creates requests,       │
│  resumes, receives results.                 │
└──────────────┬──────────────────────────────┘
               │ HTTPS (OIDC JWT or API token)
               ▼
┌─────────────────────────────────────────────┐
│ Server (dbward server)                      │
│  Auth, policy engine, approval state,       │
│  audit log, Ed25519 signing, result relay.  │
│  NO DB connection.                          │
└─────────────────────────────────────────────┘
               ▲
               │ Outbound HTTPS polling
┌──────────────┴──────────────────────────────┐
│ Agent (dbward agent)                        │
│  ONLY component with DB credentials.        │
│  Polls server, claims jobs, executes,       │
│  returns results. Multiple agents OK.       │
└──────────────┬──────────────────────────────┘
               │ sqlx
               ▼
┌─────────────────────────────────────────────┐
│ Target DB (PostgreSQL / MySQL)              │
└─────────────────────────────────────────────┘
```

## Request Flow

All DB operations: **client → server → agent → DB**.
Agent executes only when client resumes — not on approval.

```
Client                    Server                    Agent
  │                         │                         │
  ├─① POST /requests ─────▶│ auth + policy           │
  │                         │ → pending/auto/break    │
  │                         │                         │
  │ (if pending: human approves via CLI)              │
  │                         │                         │
  ├─② POST /resume ───────▶│ → dispatched            │
  ├─③ GET /result/stream ──▶│ long-poll               │
  │                         │                         │
  │                         │◀─④ POST /agent/poll ────┤
  │                         │◀─⑤ POST /claim ─────────┤
  │                         │   → running             │
  │                         │                         │
  │                         │   ⑥ execute on DB       │
  │                         │                         │
  │                         │◀─⑦ POST /result ────────┤
  │◀── ⑧ result streamed ──│                         │
```

Auto-approved requests combine ①②③ in a single `resume_and_wait` call.

## RequestStatus Lifecycle

| Status | Description |
|---|---|
| `pending` | Awaiting human approval |
| `approved` | Approved, not yet resumed |
| `auto_approved` | Policy allowed immediate execution |
| `break_glass` | Emergency bypass (reason recorded) |
| `dispatched` | Resumed, waiting for agent |
| `running` | Agent claimed and executing |
| `executed` | Completed successfully |
| `failed` | Execution error |
| `rejected` | Denied by approver |

## Further Reading

- **Policy Engine** — See [Policies Overview](guides/policies/overview.md)
- **Authentication** — See [Authentication Guide](guides/authentication.md)
- **Agent Configuration** — See [Agent Deployment](deployment/agent.md)
- **Webhook Notifications** — See [Notifications Guide](guides/notifications.md)
- **Break-Glass** — See [Break-Glass Guide](guides/break-glass.md)
- **MCP Integration** — See [MCP Integration Guide](guides/mcp-integration.md)
- **CLI Commands** — See [CLI Reference](reference/cli.md)
- **Migration File Format** — See [Migrations Guide](guides/migrations.md)
- **Security** — See [Threat Model](security/threat-model.md) and [Hardening](security/hardening.md)
