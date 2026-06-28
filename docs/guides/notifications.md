---
title: Notifications
description: Set up webhook notifications and Slack integration for dbward events
---

# Notifications

dbward can notify external systems when events occur — new requests, approvals, failures, emergency access. This page covers how to set up the delivery mechanisms. For controlling *which* events fire on *which* databases, see [Notification Policies](policies/notification-policies.md).

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

SQL in webhook payloads is redacted by default:

```toml
[audit]
redaction = "literals"   # Replace literals with ? (default)
# redaction = "none"     # Send full SQL
# redaction = "full"     # Send hash only
```

---

## Outbound: Slack Notifications

Slack integration uses a dedicated `[slack]` config section for richer formatting and approve/reject buttons.

### 1. Create a Slack App

```bash
dbward slack init --server-url https://your-server.com
```

This generates a Slack App Manifest with all required scopes, Interactivity URL, and Slash Command pre-configured. Open the output URL to create the app in one click.

<details>
<summary>Manual setup (without CLI)</summary>

1. Go to [https://api.slack.com/apps](https://api.slack.com/apps) → **Create New App** → **From scratch**
2. Add **Bot Token Scopes**: `chat:write`, `channels:join`, `channels:read`, `groups:read`, `commands`, `users:read`, `users:read.email`
3. Enable **Interactivity** → Request URL: `https://your-server.com/api/slack/interactions`
4. Add **Slash Command** `/dbward` → URL: `https://your-server.com/api/slack/commands`
5. **Install to Workspace** → copy Bot Token (`xoxb-...`)
6. Copy **Signing Secret** from Basic Information
</details>

### 2. Configure server

```toml
[slack]
bot_token = "xoxb-..."       # Bot User OAuth Token
signing_secret = "abc123..."  # Signing Secret from Basic Information
channel = "C0123ABC456"      # Default channel ID
```

Per-environment channels (optional):

```toml
[slack.channels]
production = "C0123ABC456"
staging = "C0456DEF789"
```

### 3. Invite the bot and verify

```
/invite @dbward
```

Then run:

```bash
dbward doctor --server server.toml
```

This checks token validity, signing secret format, channel existence, and bot membership. Channel validation requires channel IDs (`C...` / `G...`); channels configured by name (e.g. `#general`) are skipped with a hint.

### Message format

Slack messages include:
- Requester, database, environment, operation
- Risk level (🔴 High / 🟡 Medium / 🟢 Low)
- Required approvers (with mentions)
- **Review Request** button

Messages update in-place as the request progresses through its lifecycle.

**Security:** SQL is never shown in channel messages — only in the approval Modal (after authorization check).

---

## Inbound: Slack Interactions

Slack buttons and slash commands are configured automatically by `dbward slack init`. No additional setup is required if you created the app via Manifest.

### Approval flow

1. Approver clicks **Review Request**
2. Modal opens with: full SQL, risk details, EXPLAIN output
3. Approver selects Approve/Reject + adds comment
4. Request state updates, Slack message updates

<p align="center">
  <img src="../../demo/slack-demo.gif" alt="Slack approval flow — requester view" width="100%">
</p>

> The demo above shows the requester's perspective (create → approve → resume → result). Approvers follow the same flow via the **Review Request** button in their notifications.

### Slash command

| Command | Action |
|---|---|
| `/dbward execute` | Open SQL submission modal |
| `/dbward help` | Show usage |

**Authentication:** Both `/api/slack/commands` and `/api/slack/interactions` are verified using the [Slack Signing Secret](https://api.slack.com/authentication/verifying-requests-from-slack) (HMAC-SHA256). Only requests signed by Slack are accepted.

### Account linking

Each user links their Slack account:

```bash
dbward user update --slack-user-id U02CR3TMKKJ
```

Find your Member ID: Profile → **⋮** → **Copy member ID**.

Users without linked accounts can still approve via CLI/API.

---

## Troubleshooting

| Issue | Solution |
|---|---|
| No notifications sent | Check `[[webhooks]]` or `[slack]` config + env vars |
| `not_in_channel` | Invite bot: `/invite @dbward` or add `channels:join` scope |
| Signature mismatch | Verify secret matches between config and receiver |
| Button click error | Check Interactivity URL is correct and publicly accessible |
| "Account not linked" | Run `dbward user update --slack-user-id YOUR_ID` |
| `/dbward` shows "not a valid command" | Register Slash Command in Slack App settings |
| "No databases available" | User needs `request.query` or `request.execute` permission |

---

## Webhook vs Interactive: Choosing the Right Integration

dbward offers two independent Slack notification paths. They can be used alone or together.

| | Webhook (`format = "slack"`) | Interactive (`[slack]`) |
|---|---|---|
| **Setup** | `[[webhooks]]` + Incoming Webhook URL | `[slack]` + Bot Token + Signing Secret |
| **Delivery** | Incoming Webhook (passive) | Bot Token API (chat.postMessage) |
| **Approve/Reject** | ❌ CLI only | ✅ Buttons + Modal |
| **SQL in message** | ✅ Shown directly (redacted) | ❌ Only in Review Modal |
| **Thread replies** | ❌ Single message per event | ✅ Thread + message updates |
| **Mentions** | ❌ | ✅ @user notifications |

**Both enabled?** Both fire simultaneously. This is safe — webhook delivers a passive summary while interactive provides full button support.

### SQL visibility

The `format = "slack"` webhook displays redacted SQL directly in the channel message. This is by design — since Incoming Webhooks don't support buttons, the approver needs to see what they're approving from the notification alone.

If you don't want SQL visible in the Slack channel:

1. **Use Interactive only** — SQL is shown only inside the Review Modal (after authorization check)
2. **Use `format = "generic"`** — receive the raw JSON and format it yourself, omitting `detail`
3. **Set `redaction = "full"`** — replaces SQL with a hash (applies to both formats)

```toml
# Option 3: Hash-only redaction
[audit]
redaction = "full"
```

---

## See also

- [Notification Policies](policies/notification-policies.md) — control which events fire per database
- [Security Hardening](../security/hardening.md) — webhook security best practices
