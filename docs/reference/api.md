---
title: REST API Reference
description: All dbward REST API endpoints
---

# REST API Reference

Base URL: `http://localhost:3000` (or your server address)

Authentication: `Authorization: Bearer <token>` (API token or OIDC JWT), unless noted otherwise.

---

## Requests

### POST /api/requests

Create a new SQL execution or migration request. The server classifies the SQL, resolves the applicable workflow, and determines approval requirements.

Permission: `request.create` or `request.create_select`

### GET /api/requests

List requests with optional filtering by status, user, or pending-for-me.

| Param | Default | Description |
|-------|---------|-------------|
| `limit` | 50 | Max results |
| `offset` | 0 | Pagination offset |
| `status` | | Filter by request status |
| `user` | | Filter by requester subject ID |
| `pending_for_me` | | Only show requests the caller can approve |

Permission: `request.view`

### GET /api/requests/{id}

Get full request details including approval progress, decision trace, and context. Supports long-polling with `?wait=<seconds>` (max 120s) to wait for status changes.

Permission: `request.view`

### POST /api/requests/{id}/approve

Approve a pending request. If multi-step, advances to the next step. Accepts an optional comment.

Permission: `request.approve`

### POST /api/requests/{id}/reject

Reject a pending request. Accepts an optional comment or reason.

Permission: `request.approve`

### POST /api/requests/{id}/cancel

Cancel a request. Only the requester or an admin can cancel. Accepts an optional reason.

Permission: `request.cancel`

### POST /api/requests/{id}/resume

Resume an approved request, triggering agent dispatch. The client should then call the stream endpoint to receive the result.

Permission: `request.resume`

### GET /api/requests/{id}/result/stream

Long-poll for execution result. Returns the result when the agent completes, or 204 if not yet available.

Permission: `result.view`

### GET /api/requests/{id}/result/content

Download the stored result as binary content. Only available if the result was persisted to storage.

Permission: `result.view` + result policy access check

---

## Results

### GET /api/results

List stored results accessible to the current user (filtered by result policy access rules).

Permission: Any authenticated user

---

## Schemas

### GET /api/schemas/{db}

Get the agent-collected schema snapshot for a database. The server auto-resolves the best available environment unless explicitly specified.

| Param | Default | Description |
|-------|---------|-------------|
| `summary` | true | When true, returns table names and row counts only |
| `table` | | Filter to a single table (supports `schema.table` format) |
| `environment` | | Explicit environment (auto-resolved if omitted) |

Permission: `request.view` (scoped to the resolved database/environment)

---

## Me

### GET /api/me

Get the current authenticated user's profile, resolved roles, and group memberships.

Permission: Any authenticated user

---

## Users

### GET /api/users

List all registered users with their status and roles.

Permission: `user.manage`

### PATCH /api/users/{id}

Update a user's profile fields. Currently only `slack_user_id` can be set or cleared.

Permission: Self-update allowed; otherwise `user.manage`

### POST /api/users/{id}/suspend

Suspend a user. Revokes all active tokens and cancels pending requests.

Permission: `user.manage`

### POST /api/users/{id}/activate

Reactivate a previously suspended user.

Permission: `user.manage`

---

## Tokens

### POST /api/tokens

Create a new API token. The token value is returned only once in the response — store it securely.

Permission: `token.manage`

### GET /api/tokens

List all tokens with their metadata, status, and expiration.

Permission: `token.manage`

### DELETE /api/tokens/{id}

Revoke a token immediately. The token becomes invalid for all future requests.

Permission: `token.manage` or `token.revoke_own` (for own tokens)

---

## Webhooks

> **v0.1.5 Breaking Change**: Webhooks are config-managed. Write endpoints return 405.
> Define webhooks in `[[webhooks]]` in server.toml.

### ~~POST /api/webhooks~~ → 405

### ~~PUT /api/webhooks/{id}~~ → 405

### ~~DELETE /api/webhooks/{id}~~ → 405

### GET /api/webhooks

List all registered webhooks.

Permission: `webhook.manage`

### GET /api/webhooks/{id}

Get a webhook's configuration and delivery statistics.

Permission: `webhook.manage`

### GET /api/webhook-deliveries

List webhook delivery attempts with status and retry information.

| Param | Default | Description |
|-------|---------|-------------|
| `status` | | Filter: `pending`, `in_progress`, `delivered`, `dead` |
| `limit` | 50 | Max results (max: 100) |
| `offset` | 0 | Pagination offset |

Permission: `metrics.view`

---

## Roles

> **v0.1.5 Breaking Change**: Custom roles are config-managed. Write endpoints return 405.
> Define roles in `[[auth.roles]]` in server.toml.

### ~~POST /api/roles~~ → 405

### ~~DELETE /api/roles/{name}~~ → 405

### GET /api/roles

List all roles (built-in and custom) with their permissions.

Permission: `role.manage`

### DELETE /api/roles/{name}

Delete a custom role. Built-in roles (`admin`, `developer`, `readonly`, `agent-default`) cannot be deleted.

Response: 204

Permission: `role.manage`

---

## Policies

> **v0.1.5 Breaking Change**: All policies are config-managed. Write endpoints return 405.
> Define policies in `[[workflows]]`, `[[execution_policies]]`, `[[result_policies]]`, `[[notification_policies]]` in server.toml.

### ~~POST /api/workflows~~ → 405

### ~~DELETE /api/workflows/{id}~~ → 405

### GET /api/workflows

List all configured workflows.

Permission: `workflow.manage`

### ~~POST /api/execution-policies~~ → 405

### ~~DELETE /api/execution-policies/{id}~~ → 405

### GET /api/execution-policies

List all execution policies.

Permission: `policy.manage`

### ~~POST /api/result-policies~~ → 405

### ~~PUT /api/result-policies/{id}~~ → 405

### ~~DELETE /api/result-policies/{id}~~ → 405

### GET /api/result-policies

List all result policies.

Permission: `policy.manage`

### GET /api/result-policies/{id}

Get a specific result policy.

Permission: `policy.manage`

### ~~POST /api/notification-policies~~ → 405

### ~~PUT /api/notification-policies/{id}~~ → 405

### ~~DELETE /api/notification-policies/{id}~~ → 405

### GET /api/notification-policies

List all notification policies.

Permission: `policy.manage`

### GET /api/notification-policies/{id}

Get a specific notification policy.

Permission: `policy.manage`

### GET /api/policy-resolution

Resolve the effective policy for a database/environment. Shows which workflow matches, auto-approve rules, and the predicted decision.

| Param | Required | Description |
|-------|----------|-------------|
| `database` | ✓ | Database name |
| `environment` | ✓ | Environment name |
| `operation` | | Specific operation (omit for all) |

Permission: `request.view` (scoped)

---

## Audit

### GET /api/audit/events

Search audit log events with filtering.

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

Permission: `audit.view`

### GET /api/audit/verify

Verify the audit log hash chain integrity. Returns whether the chain is valid and the first broken event ID if not.

Permission: `audit.view`

---

## Agents

### POST /api/agent/poll

Agent reports capabilities and polls for pending jobs. Returns available jobs and dry-run requests.

Permission: `agent.poll`

### POST /api/agent/jobs/{id}/claim

Agent claims a specific job for execution. Returns the execution token, SQL, timeout, and lease expiry.

Permission: `agent.claim`

### POST /api/agent/jobs/{id}/heartbeat

Agent extends its lease on a running job. Returns whether the job has been cancelled.

Permission: `agent.heartbeat`

### POST /api/agent/jobs/{id}/result

Agent submits execution result (success/failure, data, rows affected, duration).

Body limit: ~12 MB

Permission: `agent.submit_result`

### GET /api/agents

List connected agents with their status, capabilities, and active jobs.

Permission: `metrics.view`

### POST /api/agent/schema-sync

Agent reports a database schema snapshot (tables, columns, row estimates) used for risk scoring.

Body limit: 10 MB

Permission: Agent token required

### POST /api/agent/dry-run/{id}/claim

Agent claims a dry-run job to execute EXPLAIN for impact preview.

Permission: Agent token required

### POST /api/agent/dry-run/{id}/result

Agent submits EXPLAIN output for a dry-run job.

Permission: Agent token required

---

## Databases

### GET /api/databases

List all registered databases and their environments.

Permission: `request.view`

---

## Infrastructure (Public)

### GET /health

Health check. Always returns 200 if the server process is running.

### GET /ready

Readiness check. Returns 200 when all subsystems (SQLite, result store) are operational, 503 otherwise.

### POST /api/slack/interactions

Receives Slack interaction payloads (button clicks, modal submissions). Verified by Slack signing secret — no Bearer token required.

---

## Infrastructure (Authenticated)

### GET /metrics

Prometheus metrics in text format.

Permission: `*` (admin only)

### GET /api/public-key

Ed25519 public key used by agents to verify execution tokens.

Permission: Agent token required

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
| 409 | Conflict (idempotency key race) |
| 422 | Business logic error |
