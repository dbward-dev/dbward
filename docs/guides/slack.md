---
title: Slack Integration
description: Set up interactive Slack integration for approvals, notifications, and user onboarding
---

# Slack Integration

dbward integrates with Slack to provide interactive approval workflows, real-time notifications, and self-service user onboarding — all without leaving your workspace.

## Overview

The `[slack]` configuration enables a **bidirectional** integration:

| Direction | Capability |
|-----------|------------|
| Outbound | Rich notifications with approve/reject buttons, thread replies, @mentions |
| Inbound | Slash commands (`/dbward`), review modals, onboarding flow |

This differs from `[[webhooks]] format = "slack"`, which is **outbound-only** (Incoming Webhook, no buttons or interactions). Both can be enabled simultaneously — see [Notifications](notifications.md) for webhook setup.

## Prerequisites

- A publicly reachable HTTPS URL for your dbward server (Slack requires HTTPS for Request URLs)
- A Slack workspace where you can create apps
- Users must be linked (see [Account Linking](#account-linking)) to use approval and execution features. Onboarding (`/dbward join`) does not require a linked account.

## Setup

### 1. Create a Slack App (recommended: manifest)

The fastest path is `dbward slack init`, which generates a complete App Manifest:

```bash
dbward slack init --server-url https://dbward.example.com
dbward slack init --server-url https://dbward.example.com --open  # opens browser
```

This outputs:
- A pre-filled Slack App creation URL with all required scopes and URLs
- Step-by-step instructions to copy the Bot Token and Signing Secret

### 2. Manual setup

If you prefer to configure the app manually:

1. Go to [api.slack.com/apps](https://api.slack.com/apps) → **Create New App** → From scratch
2. Add **Bot Token Scopes**:
   - `chat:write` — send messages and thread replies
   - `im:write` — send DMs (token delivery, rejection notices)
   - `channels:join` — auto-join public channels
   - `channels:read` — channel info lookup
   - `groups:read` — private channel info lookup
   - `commands` — receive slash commands
   - `users:read` — user info lookup
   - `users:read.email` — resolve email → Slack UID
3. **Interactivity & Shortcuts** → Enable → Request URL: `https://your-server.com/api/slack/interactions`
4. **Slash Commands** → Create: `/dbward` → URL: `https://your-server.com/api/slack/commands`
5. **Install to Workspace** → copy Bot Token (`xoxb-...`)
6. **Basic Information** → copy Signing Secret

> **Note:** Event Subscriptions are not required. dbward uses Request URLs exclusively.

### 3. Configure server.toml

```toml
[slack]
bot_token = "${SLACK_BOT_TOKEN}"
signing_secret = "${SLACK_SIGNING_SECRET}"
channel = "C0123ABC456"
```

Per-environment channel overrides:

```toml
[slack.channels]
production = "C0123ABC456"
staging = "C0456DEF789"
```

See [Configuration Reference: \[slack\]](../reference/configuration.md#slack) for all options.

### 4. Invite the bot and verify

```
/invite @dbward
```

Run diagnostics:

```bash
dbward doctor --server server.toml
```

Doctor checks: bot token format (`xoxb-` prefix), signing secret format, `auth.test` API call, channel existence, and bot membership.

> **Limitation:** Doctor validates token and channel access but cannot verify that Slack has correctly registered the Request URL or slash command. Use the smoke test below to confirm end-to-end.

### 5. Smoke test

After setup, type `/dbward help` in any channel where the bot is present. You should see an ephemeral message listing available commands.

## Account Linking

Interactive features (slash commands, approval buttons) require that each Slack user is linked to a dbward user account.

```bash
dbward user update alice --slack-user-id U02CR3TMKKJ
```

Or via API:

```
PATCH /api/users/alice
{"slack_user_id": "U02CR3TMKKJ"}
```

Users who interact without a linked account receive an ephemeral message with linking instructions.

**Outbound mention resolution** (for notifications) uses a fallback chain:
1. `slack_user_id` from DB
2. Email → `users.lookupByEmail` API
3. Plain-text subject ID (no @mention)

**Inbound authentication** (slash commands except `/dbward join`, button clicks) requires a linked account — there is no email fallback for interactive actions. `/dbward join` is exempt to allow onboarding of new users.

## Slash Commands

All commands are registered under a single `/dbward` slash command with subcommands:

| Command | Action |
|---------|--------|
| `/dbward execute` | Open SQL execution modal (DB/env selection filtered by user permissions) |
| `/dbward join` | Request onboarding — see [Onboarding](#onboarding) |
| `/dbward help` | Show available commands (ephemeral) |

## Notifications

When a request lifecycle event occurs, dbward posts or updates messages in the configured channel.

### Initial messages (new post)

| Event | Trigger |
|-------|---------|
| `request.created` | Request submitted |
| `request.break_glass` | Emergency request (bypass approval) |
| `request.auto_approved` | Auto-approved by policy |

Messages include: requester, database, environment, operation type, risk level (🔴/🟡/🟢), required approvers (@mentioned), and a **Review Request** button (for `request.created`).

### Thread replies and message updates

As the request progresses, dbward adds thread replies and updates the original message in-place:

| Event | Description |
|-------|-------------|
| `step.approved` | Approval step completed — mentions next approver |
| `request.approved` | Fully approved — mentions requester |
| `request.rejected` | Rejected with comment |
| `request.expired` | TTL expired |
| `request.cancelled` | Cancelled by user |
| `execution.completed` | Execution succeeded |
| `execution.failed` | Execution failed |
| `execution.lost` | Agent connection lost during execution |
| `request.dispatch_timeout` | No agent picked up the request |

### Security

SQL content is **never shown in channel messages**. Full SQL is only visible inside the approval modal after clicking Review Request.

## Approval Flow

The interactive approval flow works through Slack modals:

1. Approver clicks **Review Request** in channel
2. Modal opens showing: full SQL, risk analysis, EXPLAIN output (if available)
3. Approver selects **Approve** or **Reject**, adds optional comment
4. Request state updates → channel message updates → thread reply posted

Additional interactions:

| Button | Action |
|--------|--------|
| Resume | Confirm re-dispatch of a stalled request |
| View Result | Show execution results in a modal (truncated; use CLI for full output) |

> ⚠️ SQL content shown in the Review Modal and execution results displayed via View Result are transmitted through Slack's API servers. If your SQL or query results contain sensitive data, consider using CLI-only approval workflows instead.

## Onboarding

Self-service user provisioning via `/dbward join`. Requires `[slack.onboarding]` to be enabled.

### Flow

```
1. User types /dbward join
2. System checks for existing account or pending request
3. Modal opens: role selection, group selection, reason
4. User submits → request stored (status=pending, expires_at calculated)
5. Notification posted to approval channel with Review Request button
6. Admin clicks Review Request (requires user.write permission)
7. Admin modal: all roles (incl. restricted), groups, approve/reject
8a. Approve → user created atomically + API token delivered via DM
8b. Reject → rejection notice sent via DM
```

> ⚠️ The API token is delivered via Slack DM. This means the token passes through Slack's servers. For environments requiring end-to-end confidentiality, consider delivering tokens through a separate secure channel.

### Configuration

```toml
[slack.onboarding]
enabled = true
assignable_roles = ["developer", "dba", "readonly"]
assignable_groups = ["backend-team", "dba-team"]
restricted_roles = ["admin"]
request_ttl_hours = 72
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable `/dbward join` |
| `assignable_roles` | — | Roles shown to applicants |
| `assignable_groups` | `[]` | Groups shown to applicants |
| `restricted_roles` | `[]` | Hidden from applicants, available to admins during review |
| `request_ttl_hours` | `72` | Hours before pending request auto-expires |

### Request expiry

A background worker checks every 60 seconds for expired requests. When a request expires:
- Status set to `expired`
- Applicant receives a DM ("request expired — run `/dbward join` again")
- Channel message updated to "⏰ Expired"

## Troubleshooting

| Issue | Solution |
|-------|----------|
| No notifications sent | Verify `[slack]` is configured, bot token is valid, channel ID is correct |
| `not_in_channel` error | Invite bot: `/invite @dbward` or add `channels:join` scope |
| Signature verification failed | Ensure signing secret matches; check server clock (±5 min tolerance) |
| Button click error | Verify Interactivity URL: `{server}/api/slack/interactions` |
| "Account not linked" | Run `dbward user update <user> --slack-user-id <SLACK_UID>` |
| `/dbward` not recognized | Register slash command in Slack App settings pointing to `{server}/api/slack/commands` |
| "No databases available" | User needs `request.query` or `request.execute` permission |
| Onboarding button does nothing | Ensure `[slack.onboarding] enabled = true` |

Run `dbward doctor --server server.toml` to diagnose configuration issues.

## See also

- [Configuration Reference: \[slack\]](../reference/configuration.md#slack)
- [CLI Reference: dbward slack init](../reference/cli.md#dbward-slack-init)
- [Notifications](notifications.md) — webhook-based notifications
- [Authorization](../reference/authorization.md) — permissions required for approval
