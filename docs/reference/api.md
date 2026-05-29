---
title: REST API Reference
description: All dbward REST API endpoints
---

# REST API Reference

Base URL: `http://localhost:3000` (or your server address)

Authentication: `Authorization: Bearer <token>` (API token or OIDC JWT)

## Requests

### Create request

```
POST /api/requests
```

```json
{
  "operation": "execute_select",
  "environment": "production",
  "database": "app",
  "detail": "SELECT count(*) FROM users",
  "reason": "Monthly report",
  "ticket": "JIRA-123",
  "idempotency_key": "deploy-abc123"
}
```

**Multi-statement rules for `detail`:**

- Single statements are always allowed: `SELECT * FROM users`
- SET prelude + one query is allowed: `SET statement_timeout = 5000; SELECT * FROM users`
- Multiple result-producing statements are rejected: `SELECT 1; SELECT 2` → 400
- Statements after the query are rejected: `SELECT 1; SET timeout = 5000` → 400

Response (201):
```json
{
  "id": "req_a1b2c3",
  "status": "pending",
  "operation": "execute_select",
  "environment": "production",
  "database": "app",
  "created_at": "2026-05-08T12:00:00Z"
}
```

### List requests

```
GET /api/requests?status=pending&limit=20&user=alice
```

### Get request

```
GET /api/requests/{id}
```

Response includes a `context` field with automatically collected information:

```json
{
  "id": "0da70e0e-...",
  "status": "pending",
  "database": "app",
  "environment": "production",
  "operation": "execute_dml",
  "detail": "DELETE FROM orders WHERE status = 'pending'",
  "reason": "Cleanup",
  "requester": "alice",
  "context": {
    "status": "ready",
    "risk": {
      "level": "High",
      "factors": ["CascadeDelete { targets: [\"users\"] }"]
    },
    "sql_review": {
      "findings": [],
      "blocked": false
    },
    "tables": ["orders"],
    "explain": [
      {
        "sql": "DELETE FROM orders WHERE status = 'pending'",
        "plan": [{"Plan": {"Node Type": "ModifyTable", "..."}}]
      }
    ]
  },
  "approval_progress": {
    "current_step": 0,
    "total_steps": 2,
    "steps": [...]
  }
}
```

Context fields:
| Field | Description |
|-------|-------------|
| `context.status` | `"collecting"`, `"ready"`, `"partial"`, `"unavailable"` |
| `context.risk.level` | `"Low"`, `"Medium"`, `"High"`, `"Critical"`, `"Unknown"` |
| `context.risk.factors` | Array of risk factor descriptions |
| `context.sql_review` | SQL review findings and block status |
| `context.tables` | Affected table names |
| `context.explain` | Per-statement EXPLAIN plans (JSON format, PG/MySQL) |

Decision trace fields (present for requests created after v0.1.3):
| Field | Description |
|-------|-------------|
| `decision_trace.version` | Trace schema version (currently 1) |
| `decision_trace.classification.resolved_operation` | Final classified operation (`execute_select`, `execute_dml`, `migrate_up`, etc.) |
| `decision_trace.sql_review.findings_count` | Number of SQL review warnings |
| `decision_trace.sql_review.parse_failed` | `true` if SQL could not be parsed |
| `decision_trace.risk.level` | `"low"`, `"medium"`, `"high"`, `"critical"`, `"unknown"`, `"unavailable"` |
| `decision_trace.risk.factors` | Array of risk factor descriptions |
| `decision_trace.risk.schema_status` | `"ready"`, `"not_synced"`, `"failed"`, `"unavailable"` |
| `decision_trace.workflow.matched` | Matched workflow info (`null` if none matched) |
| `decision_trace.workflow.matched.id` | Workflow ID |
| `decision_trace.workflow.matched.step_count` | Number of approval steps |
| `decision_trace.decision.outcome` | `"auto_approved"` or `"needs_approval"` |
| `decision_trace.decision.reasons` | Array: `"empty_steps"`, `"risk_below_threshold"`, `"break_glass"`, `"auto_approve_disabled"`, `"risk_above_threshold"`, `"no_auto_approve_rule"`, `"risk_unavailable"` |
| `decision_trace.decision.auto_approve_threshold` | Matched auto-approve rule's max risk level (`null` if no rule) |

### Approve

```
POST /api/requests/{id}/approve
```

```json
{
  "comment": "Looks good",
  "as_role": "dba"
}
```

### Reject

```
POST /api/requests/{id}/reject
```

```json
{
  "reason": "Wrong table"
}
```

### Cancel

```
POST /api/requests/{id}/cancel
```

### Resume

```
POST /api/requests/{id}/resume
```

Resumes execution by an agent. Returns the execution token.

### Stream result

```
GET /api/requests/{id}/result/stream
```

Long-poll endpoint. Blocks until the result is available (timeout: 5 minutes).

### Get stored result

```
GET /api/requests/{id}/result/content
```

Returns the stored result (requires result_storage to be configured).

---

## Results

### List shared results

```
GET /api/results
```

### Get storage config

```
### `GET /api/schemas/{db}`

Returns the agent-collected schema snapshot for a database. The server automatically resolves the best available environment (production > staging > development) from snapshots with `status=ready` that the caller is authorized to view.

**Query parameters:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| `summary` | `true` | When true, returns table names and counts only. Set to `false` for full column/constraint/index details. |
| `table` | — | Filter to a single table. Supports `schema.table` format (e.g., `public.users`). Overrides `summary`. |

**Response (200):**

```json
{
  "database": "app",
  "environment": "production",
  "dialect": "postgresql",
  "status": "ready",
  "collected_at": "2026-05-23T01:00:00Z",
  "tables": [
    { "name": "users", "schema_name": "public", "estimated_rows": 50000, "column_count": 12 }
  ]
}
```

**Errors:**

| Code | Condition |
|------|-----------|
| 404 | Database not registered, no ready snapshot, or table not found |
| 403 | No authorized environment available |

---

## Agents

### Poll for jobs

```
POST /api/agent/poll
```

```json
{
  "agent_id": "prod-agent-1",
  "capabilities": {
    "databases": ["app"],
    "environments": ["production"],
    "operations": ["*"]
  }
}
```

### List agents

```
GET /api/agents
```

### Claim job

```
POST /api/agent/jobs/{id}/claim
```

### Heartbeat

```
POST /api/agent/jobs/{id}/heartbeat
```

### Submit result

```
POST /api/agent/jobs/{id}/result
```

---

## Tokens

### Create token

```
POST /api/tokens
```

```json
{
  "subject_id": "bob",
  "role": "developer",
  "subject_type": "user",
  "name": "Bob laptop",
  "groups": ["backend-team"],
  "expires_in": 7776000
}
```

Response (201):
```json
{
  "id": "tok_abc123",
  "token": "dbw_...",
  "subject_id": "bob",
  "role": "developer",
  "expires_at": "2026-08-06T12:00:00Z",
  "created_at": "2026-05-08T12:00:00Z"
}
```

> The raw `token` value is only returned once at creation time.

### List tokens

```
GET /api/tokens
```

### Revoke token

```
DELETE /api/tokens/{id}
```

Admin can revoke any token. Users can revoke their own.

---

## Webhooks

### List webhooks

```
GET /api/webhooks
```

### Create webhook

```
POST /api/webhooks
```

```json
{
  "url": "https://hooks.slack.com/...",
  "events": ["request_created", "request_approved"],
  "format": "slack",
  "secret": "whsec_..."
}
```

### Get / Update / Delete webhook

```
GET    /api/webhooks/{id}
PUT    /api/webhooks/{id}
DELETE /api/webhooks/{id}
```

---

## Policies

### Workflows

```
GET    /api/workflows
POST   /api/workflows
GET    /api/workflows/{id}
PUT    /api/workflows/{id}
DELETE /api/workflows/{id}
```

### Execution policies

```
GET    /api/execution-policies
POST   /api/execution-policies
GET    /api/execution-policies/{id}
PUT    /api/execution-policies/{id}
DELETE /api/execution-policies/{id}
```

### Result policies (Pro)

```
GET    /api/result-policies
POST   /api/result-policies
GET    /api/result-policies/{id}
PUT    /api/result-policies/{id}
DELETE /api/result-policies/{id}
```

### Notification policies (Pro)

```
GET    /api/notification-policies
POST   /api/notification-policies
GET    /api/notification-policies/{id}
PUT    /api/notification-policies/{id}
DELETE /api/notification-policies/{id}
```

### Policy resolution

Resolve the effective policy for a database/environment combination. Shows which workflow matches, auto-approve rules, execution policy, and predicted decision.

```
GET /api/policy-resolution?database=<name>&environment=<env>[&operation=<op>]
```

Query parameters:
- `database` (required): Database name
- `environment` (required): Environment name  
- `operation` (optional): Specific operation (`execute_select`, `execute_dml`, `migrate_up`, `migrate_down`, `migrate_status`). Omit for all operations.

Auth: scoped `RequestView` permission.

Returns `decision_preview`: `auto_approved`, `needs_approval`, or `deny`.

### Access policies

```
GET    /api/access-policies
POST   /api/access-policies
DELETE /api/access-policies/{id}
```

---

## Audit

### List audit events

```
GET /api/audit/events?limit=50&user=alice&category=auth&since=2026-05-01
```

### Verify hash chain

```
GET /api/audit/verify
```

---

## Infrastructure

### Health check

```
GET /health
```

Response: `{"status": "ok"}`

### Readiness

```
GET /ready
```

Returns 200 (ready) or 503 (not ready). No response body.

### Metrics

```
GET /metrics
```

Requires admin authentication. Returns Prometheus text format.

### Public key

```
GET /api/public-key
```

Returns the Ed25519 public key used for execution token verification.

---

## Error format

All errors return a structured JSON response:

```json
{
  "error": {
    "code": "validation_error",
    "message": "subject_id is required"
  }
}
```

Common HTTP status codes:
| Code | Meaning |
|------|---------|
| 400 | Bad request (validation error) |
| 401 | Unauthorized (invalid/expired token) |
| 402 | Payment required (Pro feature) |
| 403 | Forbidden (insufficient permissions) |
| 404 | Not found |
| 409 | Conflict (e.g., workflow has pending requests) |
| 500 | Internal server error |
