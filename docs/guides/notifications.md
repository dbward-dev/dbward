---
title: Notifications
description: Set up webhook notifications for dbward events
---

# Notifications

dbward can notify external systems when events occur — new requests, approvals, failures, emergency access. This page covers webhook-based delivery. For interactive Slack integration (buttons, modals, onboarding), see [Slack Integration](slack.md).

For controlling *which* events fire on *which* databases, see [Notification Policies](policies/notification-policies.md).

---

## Outbound: Generic Webhooks

### Configuration

```toml
[[webhooks]]
id = "my-receiver"
url = "https://your-service.com/dbward-events"
format = "generic"
secret = "${WEBHOOK_SECRET}"
events = ["request.created", "request.approved", "execution.completed", "request.break_glass"]
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `id` | String | — | Unique identifier for the webhook |
| `url` | String | — | Delivery endpoint (HTTPS required in production) |
| `format` | String | `"generic"` | Payload format: `generic` or `slack` |
| `secret` | String | — | HMAC-SHA256 signing key |
| `events` | String[] | `[]` (all) | Filter events (empty = all events) |

### Available events

| Event | Category | Description |
|-------|----------|-------------|
| `request.created` | approval | New request submitted |
| `request.break_glass` | approval | Emergency request (bypass approval) |
| `request.auto_approved` | approval | Auto-approved by policy |
| `step.approved` | approval | Approval step completed |
| `request.approved` | approval | Fully approved (all steps) |
| `request.rejected` | approval | Request rejected |
| `request.cancelled` | approval | Request cancelled by requester |
| `request.dispatched` | approval | Request dispatched to agent |
| `request.expired` | approval | Request TTL expired |
| `request.dispatch_timeout` | approval | No agent claimed within timeout |
| `execution.started` | execution | Agent started execution |
| `execution.completed` | execution | Execution succeeded |
| `execution.failed` | execution | Execution failed |
| `execution.lost` | agent | Agent connection lost during execution |
| `user.created` | user | New user created |
| `user.updated` | user | User updated |
| `user.deleted` | user | User soft-deleted |
| `user.suspended` | user | User suspended |
| `user.activated` | user | User re-activated |

### Payload format (generic)

```json
{
  "event": "request.created",
  "request_id": "c22932a6-ebc6-4eea-93cb-f2215c8c48eb",
  "database": "app",
  "environment": "production",
  "operation": "execute_select",
  "actor": "alice",
  "requester": "alice",
  "detail": "SELECT * FROM users WHERE ...",
  "matched_selector": "role:dba"
}
```

### Signature verification

When `secret` is set, every delivery includes:

```
x-dbward-signature: sha256=<hex-encoded HMAC-SHA256 of body>
```

Verify in your receiver:

```python
import hmac, hashlib

expected = hmac.new(secret.encode(), request.body, hashlib.sha256).hexdigest()
actual = request.headers["x-dbward-signature"].removeprefix("sha256=")
assert hmac.compare_digest(expected, actual)
```

### Delivery guarantees

- Deliveries are persisted before sending (no lost events on crash)
- Failed deliveries retry up to 10 times with exponential backoff
- Timeout: 10 seconds per attempt
- Redirects are disabled (SSRF protection)
- Internal network addresses are blocked

### SQL redaction

SQL in webhook payloads is automatically redacted — string and numeric literals are replaced with `?`:

```
SELECT * FROM users WHERE email = ? AND age > ?
```

This is applied unconditionally to all webhook deliveries. Full SQL (unredacted) is never sent via webhooks.

---

## Slack Webhook Format

Use `format = "slack"` to send Block Kit-formatted messages via Incoming Webhook:

```toml
[[webhooks]]
url = "https://hooks.slack.com/services/T.../B.../xxx"
format = "slack"
secret = "${WEBHOOK_SECRET}"
```

This is a **passive, outbound-only** integration. For interactive features (approve/reject buttons, modals, slash commands), use the [Slack Integration](slack.md).

### SQL visibility in Slack webhooks

The `format = "slack"` webhook displays redacted SQL (literals replaced with `?`) directly in the channel message. If you don't want SQL visible in Slack:

1. **Use Interactive Slack instead** — SQL is only shown inside the Review Modal
2. **Use `format = "generic"`** — receive raw JSON and format it yourself

| | Webhook (`format = "slack"`) | Interactive (`[slack]`) |
|---|---|---|
| **Setup** | `[[webhooks]]` + Incoming Webhook URL | `[slack]` + Bot Token + Signing Secret |
| **Delivery** | Incoming Webhook (passive) | Bot Token API (chat.postMessage) |
| **Approve/Reject** | ❌ CLI only | ✅ Buttons + Modal |
| **SQL in message** | ✅ Shown directly (redacted) | ❌ Only in Review Modal |
| **Thread replies** | ❌ Single message per event | ✅ Thread + message updates |
| **Mentions** | ❌ | ✅ @user notifications |

Both can be enabled simultaneously.

---

## Troubleshooting

Run `dbward doctor --server server.toml` first — it validates webhook URLs, Slack config, and connectivity.

| Issue | Solution |
|---|---|
| No notifications sent | Check `[[webhooks]]` config, env vars, and `events` filter |
| Signature mismatch | Verify `secret` matches between config and receiver |
| Webhook not delivered | Check endpoint is reachable, returns 2xx within 10s |
| Slack webhook shows raw JSON | Set `format = "slack"` |

For Slack-specific troubleshooting (buttons, slash commands, account linking), see [Slack Integration: Troubleshooting](slack.md#troubleshooting).

---

## See also

- [Slack Integration](slack.md) — interactive Slack setup (buttons, modals, onboarding)
- [Notification Policies](policies/notification-policies.md) — control which events fire per database
- [Security Hardening](../security/hardening.md) — webhook security best practices
