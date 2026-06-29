---
title: REST API Reference
description: All dbward REST API endpoints
---

# REST API Reference

Base URL: `http://localhost:3000` (or your server address)

Authentication: `Authorization: Bearer <token>` (API token or OIDC JWT), unless noted otherwise.

All responses include the `x-dbward-version` header.

---

## Error Format

All errors return:

```json
{"error": {"code": "validation_error", "message": "subject_id is required"}}
```

| HTTP Status | Meaning |
|-------------|---------|
| 400 | Validation error |
| 401 | Not authenticated |
| 403 | Not authorized |
| 404 | Resource not found |
| 405 | Method not allowed (config-managed resource) |
| 409 | Conflict (idempotency key race) |
| 422 | Business logic error |

---

## Requests

### POST /api/requests

Create a new SQL execution or migration request.

Permission: `request.execute` | `request.query` | `request.break_glass` (scoped by database/environment)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `database` | string | ✓ | Target database name |
| `environment` | string | ✓ | Target environment |
| `operation` | string | | Operation type (default: `execute_select`) |
| `detail` | string | ✓ | SQL statement or migration detail |
| `reason` | string | | Reason for the request |
| `idempotency_key` | string | | Idempotency key to prevent duplicates |
| `metadata` | object | | Arbitrary JSON metadata |
| `emergency` | bool | | Break-glass mode (default: false) |
| `allow_ddl` | bool | | Allow DDL in execute operations (default: false) |
| `no_result_store` | bool | | Skip persisting result to storage (default: false) |
| `share_with` | string[] | | Subject IDs to share the result with |

### GET /api/requests

List requests with optional filtering.

Permission: `request.view`

| Param | Default | Description |
|-------|---------|-------------|
| `limit` | 50 | Max results |
| `offset` | 0 | Pagination offset |
| `status` | | Filter by request status |
| `user` | | Filter by requester subject ID |
| `pending_for_me` | | Only show requests the caller can approve |

### GET /api/requests/{id}

Get full request details. Supports long-polling with `?wait=<seconds>` (max 120s).

Permission: `request.view` (scoped)

| Param | Default | Description |
|-------|---------|-------------|
| `wait` | | Long-poll timeout in seconds (max 120) |

### POST /api/requests/{id}/approve

Approve a pending request. If multi-step, advances to the next step.

Permission: `request.approve` (scoped)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `comment` | string | | Approval comment |
| `selector` | string | | Step selector for multi-step workflows |

### POST /api/requests/{id}/reject

Reject a pending request.

Permission: `request.approve` (scoped)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `comment` | string | | Rejection reason |

### POST /api/requests/{id}/cancel

Cancel a request. The requester can always cancel their own requests.

Permission: `request.cancel` (scoped)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `reason` | string | | Cancellation reason |

### POST /api/requests/{id}/resume

Resume an approved request, triggering agent dispatch.

Permission: `request.resume` (scoped; requester can always resume own)

### GET /api/requests/{id}/result/stream

Long-poll for execution result. Returns the result when the agent completes.

Permission: `result.view` (scoped)

### GET /api/requests/{id}/result/content

Download the stored result as binary content.

Permission: `result.view` (scoped)

| Param | Default | Description |
|-------|---------|-------------|
| `execution_id` | | Specific execution ID (defaults to latest) |

### GET /api/requests/{id}/executions

List execution history for a request.

Permission: `request.view` (scoped)

| Param | Default | Description |
|-------|---------|-------------|
| `limit` | 20 | Max results (max: 100) |

---

## Results

### GET /api/results

List stored results accessible to the current user (filtered by result policy).

Permission: `result.view`

| Param | Default | Description |
|-------|---------|-------------|
| `limit` | 50 | Max results (max: 100) |

---

## Schemas

### GET /api/schemas/{db}

Get the agent-collected schema snapshot for a database.

Permission: `request.view` (scoped)

| Param | Default | Description |
|-------|---------|-------------|
| `summary` | true | Table names and row counts only |
| `table` | | Filter to a single table (supports `schema.table`) |
| `environment` | | Explicit environment (auto-resolved if omitted) |

---

## Me

### GET /api/me

Get the current user's profile, resolved roles, and group memberships.

Permission: Any authenticated user

---

## Users

### GET /api/users

List all registered users.

Permission: `user.write`

### PATCH /api/users/{id}

Update a user's profile fields.

Permission: `user.write` (or self-update for own profile)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `slack_user_id` | string \| null | ✓ | Set or clear Slack user ID |

### POST /api/users/{id}/suspend

Suspend a user. Revokes all active tokens and cancels pending requests. For config-managed users, status reverts on server restart.

Permission: `user.write`

### POST /api/users/{id}/activate

Reactivate a previously suspended user. For config-managed users, status reverts on server restart.

Permission: `user.write`

---

## Tokens

### POST /api/tokens

Create a new API token. The raw token value is returned only once — store it securely.

Permission: `token.write`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `subject_id` | string | ✓ | Subject the token authenticates as |
| `subject_type` | string | ✓ | `user` or `agent` |
| `name` | string | | Human-readable label |
| `scope_ceiling` | object | user: ✓ | Max effective roles: `{"roles": ["developer"]}` |
| `expires_at` | DateTime | | Expiration time (ISO 8601) |

Notes:
- `scope_ceiling` is required for user tokens. Agent tokens may omit it (unrestricted).
- Effective permissions = resolved roles ∩ scope_ceiling.

### GET /api/tokens

List all tokens with metadata and status.

Permission: `token.write`

### DELETE /api/tokens/{id}

Revoke a token immediately.

Permission: `token.write` or `token.revoke_own` (for own tokens)

### GET /api/tokens/{id}/inspect

Show the token's effective roles and permissions after ceiling application.

Permission: Token owner or `token.write`

---

## Webhooks

Config-managed resource. Define webhooks in `[[webhooks]]` in server.toml. Mutation endpoints return `405`.

### GET /api/webhooks

List all registered webhooks.

Permission: `workflow.read`

### GET /api/webhooks/{id}

Get a webhook's configuration and delivery statistics.

Permission: `workflow.read`

### GET /api/webhook-deliveries

List webhook delivery attempts.

Permission: `metrics.view`

| Param | Default | Description |
|-------|---------|-------------|
| `status` | | Filter: `pending`, `in_progress`, `delivered`, `dead` |
| `limit` | 50 | Max results (max: 100) |
| `offset` | 0 | Pagination offset |

---

## Roles

Config-managed resource. Define roles in `[[auth.roles]]` in server.toml. Mutation endpoints return `405`.

### GET /api/roles

List all roles (built-in and custom) with their permissions.

Permission: `workflow.read`

---

## Policies

Config-managed resources. Define in server.toml (`[[workflows]]`, `[[execution_policies]]`, `[[result_policies]]`, `[[notification_policies]]`, `[[sql_review]]`). Mutation endpoints return `405`.

### GET /api/workflows

List all configured workflows.

Permission: `workflow.read`

### GET /api/execution-policies

List all execution policies.

Permission: `workflow.read`

### GET /api/result-policies

List all result policies.

Permission: `workflow.read`

### GET /api/result-policies/{id}

Get a specific result policy.

Permission: `workflow.read`

### GET /api/notification-policies

List all notification policies.

Permission: `workflow.read`

### GET /api/notification-policies/{id}

Get a specific notification policy.

Permission: `workflow.read`

### GET /api/sql-review-policies

List all active SQL review policies.

Permission: `workflow.read`

### GET /api/policy-resolution

Resolve the effective policy for a database/environment combination.

Permission: `request.view` (scoped)

| Param | Required | Description |
|-------|----------|-------------|
| `database` | ✓ | Database name |
| `environment` | ✓ | Environment name |
| `operation` | | Specific operation (omit for all) |

---

## Audit

### GET /api/audit/events

Search audit log events.

Permission: `audit.read`

| Param | Default | Description |
|-------|---------|-------------|
| `actor_id` | | Filter by user |
| `event_type` | | Filter by event type |
| `event_category` | | Filter by category |
| `outcome` | | Filter by outcome |
| `database` | | Filter by database |
| `environment` | | Filter by environment |
| `since` | | Start time (ISO 8601) |
| `until` | | End time (ISO 8601) |
| `limit` | 50 | Max results (max: 200) |
| `offset` | 0 | Pagination offset |

### GET /api/audit/verify

Verify the audit log hash chain integrity.

Permission: `audit.read`

---

## Agents

### POST /api/agent/poll

Agent reports capabilities and polls for pending jobs.

Permission: `agent.operate` (agent token required)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `capabilities` | object | ✓ | `{databases: string[], environments?: string[], operations?: string[]}` |
| `limit` | u32 | | Max jobs to return |
| `status` | object | | Agent status report (in_flight, max_concurrent, draining, etc.) |
| `agent_version` | string | | Agent binary version |

### POST /api/agent/jobs/{id}/claim

Agent claims a specific job for execution.

Permission: `agent.operate` (agent token required)

### POST /api/agent/jobs/{id}/heartbeat

Agent extends its lease on a running job.

Permission: `agent.operate` (agent token required)

### POST /api/agent/jobs/{id}/result

Agent submits execution result.

Permission: `agent.operate` (agent token required)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `success` | bool | ✓ | Whether execution succeeded |
| `result_data` | string | | Query result data |
| `error_message` | string | | Error message on failure |
| `rows_affected` | u64 | | Number of rows affected |
| `duration_ms` | u64 | | Execution duration |

### GET /api/agents

List connected agents with status and capabilities.

Permission: `metrics.view`

### POST /api/agent/schema-sync

Agent reports a database schema snapshot.

Permission: `agent.operate` (agent token required)

Body limit: 10 MB

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `database` | string | ✓ | Database name |
| `environment` | string | ✓ | Environment name |
| `dialect` | string | ✓ | Database dialect |
| `status` | string | ✓ | Sync status |
| `snapshot` | object | | Schema snapshot JSON |
| `error_message` | string | | Error on failure |

### POST /api/agent/dry-run/{id}/claim

Agent claims a dry-run job for EXPLAIN execution.

Permission: `agent.operate` (agent token required)

### POST /api/agent/dry-run/{id}/result

Agent submits EXPLAIN output.

Permission: `agent.operate` (agent token required)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `claim_token` | string | ✓ | Claim token from claim response |
| `result` | object | | EXPLAIN output |
| `error` | string | | Error message |

---

## Databases

### GET /api/databases

List all registered databases and their environments.

Permission: `request.view`

---

## MCP (Streamable HTTP)

JSON-RPC over HTTP with SSE streaming. Each tool invocation checks its own permission.

### POST /mcp

Send a JSON-RPC message (initialize, tool call, etc.).

Permission: Any authenticated user (tool-level checks apply)

Headers: `Content-Type: application/json`, `Accept: application/json, text/event-stream`

### GET /mcp

Resume or replay SSE stream for an existing session.

Headers: `Accept: text/event-stream`, `Mcp-Session-Id` (required), `Last-Event-Id` (required)

### DELETE /mcp

Terminate an MCP session.

Headers: `Mcp-Session-Id` (required)

---

## Infrastructure (Public)

### GET /health

Health check. Always returns 200 if the server is running.

### GET /ready

Readiness check. Returns 200 when all subsystems are operational, 503 otherwise.

### POST /api/slack/interactions

Slack interaction payloads (button clicks, modal submissions). Verified by Slack signing secret — no Bearer token required.

### POST /api/slack/commands

Slack slash command payloads. Verified by Slack signing secret — no Bearer token required.

---

## Infrastructure (Authenticated)

### GET /metrics

Prometheus metrics in text format.

Permission: `metrics.view`

### GET /api/public-key

Ed25519 public key for execution token verification.

Permission: Agent token required
