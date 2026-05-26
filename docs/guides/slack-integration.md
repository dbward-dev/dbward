# Slack Integration

Connect dbward to Slack for approval notifications and one-click approve/reject.

## Prerequisites

- dbward server running with a public URL (for Slack callbacks)
- A Slack workspace where you have permission to install apps

## 1. Create a Slack App

1. Go to [https://api.slack.com/apps](https://api.slack.com/apps)
2. Click **Create New App** → **From scratch**
3. Name: `dbward` (or any name), select your workspace

### Bot Token Scopes

Go to **OAuth & Permissions** → **Scopes** → **Bot Token Scopes**, add:

| Scope | Purpose |
|---|---|
| `chat:write` | Send and update messages |
| `channels:join` (recommended) | Auto-join public channels |

### Install to Workspace

Click **Install to Workspace** → **Allow**. Copy the **Bot User OAuth Token** (`xoxb-...`).

### Signing Secret

Go to **Basic Information** → **App Credentials** → copy **Signing Secret**.

## 2. Configure dbward Server

Add to your `server.toml`:

```toml
[slack]
bot_token = "${SLACK_BOT_TOKEN}"
signing_secret = "${SLACK_SIGNING_SECRET}"
channel = "C02C1EUJ0EN"   # Channel ID (not name)
```

Set environment variables:
```bash
export SLACK_BOT_TOKEN="xoxb-..."
export SLACK_SIGNING_SECRET="ceb816..."
```

### Channel ID

Right-click the channel name in Slack → **Copy link** → the `C...` part of the URL is the channel ID.

### Per-environment channels (optional)

```toml
[slack.channels]
production = "C02C1EUJ0EN"
staging = "C03D2FKJ1FO"
```

## 3. Enable Interactivity

In your Slack App settings:

1. Go to **Interactivity & Shortcuts** → Toggle **On**
2. Set **Request URL**: `https://your-server.com/api/slack/interactions`
3. Save

This URL must be publicly accessible. dbward verifies all incoming requests using the signing secret (HMAC-SHA256 + timestamp).

## 4. Invite Bot to Channel

**Public channels** with `channels:join` scope: the bot joins automatically on first message.

**Without `channels:join`** or **private channels**: manually invite the bot:
```
/invite @dbward
```

## 5. Link Your Slack Account

Each user links their Slack account to dbward:

```bash
dbward user update --slack-user-id U02CR3TMKKJ
```

To find your Slack Member ID: click your profile picture → **Profile** → **⋮** → **Copy member ID**.

## How It Works

### Notification Flow

1. User creates a request (via CLI, MCP, or API)
2. dbward posts a summary to the configured Slack channel (per-environment routing)
3. The message mentions designated approvers (`@user` or `@group`)
4. Approvers click **Review Request** button
5. dbward checks the user's linked Slack account and role permissions
6. A Modal opens showing: SQL, risk assessment, EXPLAIN plan, context enrichment
7. Approver selects Approve/Reject, adds a comment, submits
8. The **original message updates** to reflect the new status (approve/reject/executed)
9. A thread reply is posted for each state change (step approved, completed, failed)
10. If configured, the requester receives a DM when their request is resolved

### Message Updates (Canonical State)

The original Slack message always reflects the **current** state of the request:

| State | Message shows |
|-------|--------------|
| Pending | Risk level, approvers needed, "Review Request" button |
| Step approved (multi-step) | ✅ Step 1 complete, next approvers needed |
| Approved | ✅ Approved by @user, waiting for execution |
| Executed | ✅ Completed successfully |
| Failed | ❌ Execution failed + error summary |
| Rejected | ❌ Rejected by @user + reason |
| Expired | ⏰ Expired (approval timeout) |

### Modal Review

The modal shows information that is **not** in the channel message (for security):

- Full SQL statement
- Risk assessment details (factors, level)
- EXPLAIN plan (if available)
- Context: affected tables, estimated rows, FK relationships
- Approval progress (who approved, who's remaining)
- Approve / Reject radio buttons + comment field

### Approver Resolution

dbward maps workflow approver selectors to Slack mentions:

| Workflow selector | Slack mention |
|-------------------|--------------|
| `role:admin` | All users with admin role who have `slack_user_id` set → `<@U123>` |
| `group:dba-team` | All users in group who have `slack_user_id` → `<@U456> <@U789>` |
| `user:alice` | `<@alice_slack_uid>` (if linked) |

Users without `slack_user_id` are silently skipped in mentions (but can still approve via CLI/API).

### What's Shown in the Channel

- Requester, database, environment, operation
- Risk level (🔴 High / 🟡 Medium / 🟢 Low)
- Approvers required (with OR/AND logic)
- Step progress for multi-step workflows

### Security

- SQL is **never** shown in the channel message (only in the Modal after authorization check)
- Only linked users with the correct role can open the review Modal
- Unlinked users get an ephemeral message with linking instructions
- All interactions are verified via Slack's signing secret
- The approval itself goes through the same authorization path as the REST API

## Troubleshooting

| Issue | Solution |
|---|---|
| `not_in_channel` error | Invite bot: `/invite @dbward` or add `channels:join` scope |
| Button click shows error | Check Interactivity URL is correct and server is reachable |
| "Slack account not linked" | Run `dbward user update --slack-user-id YOUR_ID` |
| No notification sent | Verify `[slack]` section in server.toml and env vars are set |
