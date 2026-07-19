---
title: Notification Policies
description: Control which webhooks fire for which events on each database
---

# Notification Policies

Notification policies define which [webhooks](../notifications.md) fire for which events on a given database and environment. They separate "what triggers" from "how to deliver."

## Configuration

Notification policies are managed via `server.toml` (config-managed since v0.1.5):

```toml
[[notification_policies]]
database = "app"
environment = "production"
webhooks = ["ops-alerts"]
events = ["request.created", "request.break_glass", "execution.completed"]
```

Changes take effect on server restart or `dbward server reload`.

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
| `request.created` | New request submitted |
| `request.approved` | Request manually approved (all steps complete) |
| `request.auto_approved` | Request auto-approved by risk assessment |
| `step.approved` | One step of a multi-step workflow approved |
| `request.rejected` | Request rejected |
| `execution.completed` | Execution completed successfully |
| `execution.failed` | Execution failed |
| `request.break_glass` | Emergency bypass used |

## Scoping

Notification policies follow the same [scoping model](overview.md#scoping-model) as other policies:

```toml
# All events on production → ops-channel webhook
[[notification_policies]]
database = "*"
environment = "production"
webhooks = ["ops-channel"]
events = ["*"]

# Break-glass on any DB → security-channel webhook
[[notification_policies]]
database = "*"
environment = "*"
webhooks = ["security-channel"]
events = ["request.break_glass"]
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
events = ["request.created", "request.break_glass"]
```

For finer-grained control (different events per database), use the API-managed notification policies instead.

## See also

- [Notifications](../notifications.md) — webhook setup
- [Slack Integration](../slack.md) — interactive Slack (buttons, modals, onboarding)
- [Policies Overview](overview.md) — how all four policies relate
