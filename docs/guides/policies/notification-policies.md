---
title: Notification Policies
description: Control which webhooks fire for which events on each database
---

# Notification Policies

Notification policies define which [webhooks](../notifications.md) fire for which events on a given database and environment. They separate "what triggers" from "how to deliver."

## Configuration

Notification policies are managed via the REST API:

```bash
# Create a notification policy
curl -X POST http://localhost:3000/api/notification-policies \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "database": "app",
    "environment": "production",
    "webhooks": ["wh_abc123"],
    "events": ["request_created", "break_glass", "request_completed"]
  }'
```

## Fields

| Field | Type | Description |
|-------|------|-------------|
| `database` | String | Database scope (or `*` for all) |
| `environment` | String | Environment scope (or `*` for all) |
| `webhooks` | String[] | Webhook IDs to fire |
| `events` | String[] | Events that trigger notifications (empty or `["*"]` = all) |

## Event types

| Event | Fires when |
|-------|-----------|
| `request_created` | New request submitted |
| `request_approved` | Request manually approved (all steps complete) |
| `request_auto_approved` | Request auto-approved by risk assessment |
| `step_approved` | One step of a multi-step workflow approved |
| `request_rejected` | Request rejected |
| `request_completed` | Execution completed successfully |
| `request_failed` | Execution failed |
| `break_glass` | Emergency bypass used |

## Scoping

Notification policies follow the same [scoping model](overview.md#scoping-model) as other policies:

```bash
# All events on production → ops-channel webhook
curl -X POST http://localhost:3000/api/notification-policies \
  -d '{
    "database": "*",
    "environment": "production",
    "webhooks": ["wh_ops"],
    "events": ["*"]
  }'

# Break-glass on any DB → security-channel webhook
curl -X POST http://localhost:3000/api/notification-policies \
  -d '{
    "database": "*",
    "environment": "*",
    "webhooks": ["wh_security"],
    "events": ["break_glass"]
  }'
```

## Relationship with webhooks

- **Webhooks** define the delivery mechanism (URL, format, secret)
- **Notification policies** define when those webhooks fire

A webhook without a notification policy never fires. A notification policy referencing a non-existent webhook ID is ignored.

## Legacy: config-based webhooks

You can also define webhooks directly in `server.toml` with an `events` filter. These act as combined webhook + notification policy:

```toml
[[webhooks]]
url = "https://hooks.slack.com/..."
format = "slack"
events = ["request_created", "break_glass"]
```

For finer-grained control (different events per database), use the API-managed notification policies instead.

## See also

- [Notifications](../notifications.md) — webhook setup and Slack integration
- [Policies Overview](overview.md) — how all four policies relate
