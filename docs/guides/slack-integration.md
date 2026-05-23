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
2. dbward posts a summary to the configured Slack channel
3. Designated approvers click **Review Request**
4. A Modal shows the full SQL, risk assessment, and context
5. Approver selects Approve/Reject, adds a comment, submits
6. The original message updates to reflect the new status
7. Thread replies track each state change

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
