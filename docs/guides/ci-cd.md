---
title: CI/CD Integration
description: Run dbward in CI/CD pipelines
---

# CI/CD Integration

Run migrations and database operations in CI/CD pipelines with dbward's approval workflow.

## Key features for CI/CD

- **Exit code 2** = approval pending (pipeline can wait or notify)
- **`--idempotency-key`** = prevent duplicate requests on retry
- **`--format json`** = machine-readable JSON envelope on stdout
- **`--format quiet`** = JSON output with zero stderr (log-free)
- **API tokens** = no interactive login needed
- **`--yes`** = skip confirmation prompts (required in non-interactive mode)

## GitHub Actions example

### Migration on deploy

```yaml
name: Deploy
on:
  push:
    branches: [main]

jobs:
  migrate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install dbward
        run: |
          VERSION=$(curl -s https://api.github.com/repos/dbward-dev/dbward/releases/latest | grep -o '"tag_name": "v[^"]*"' | cut -d'"' -f4 | sed 's/^v//')
          curl -sL "https://github.com/dbward-dev/dbward/releases/latest/download/dbward-v${VERSION}-x86_64-unknown-linux-gnu.tar.gz" | tar xz
          chmod +x dbward
          sudo mv dbward /usr/local/bin/

      - name: Run migrations
        env:
          DBWARD_TOKEN: ${{ secrets.DBWARD_TOKEN }}
        run: |
          cat > dbward.toml << EOF
          default_database = "app"
          [server]
          url = "${{ vars.DBWARD_SERVER_URL }}"
          token = "${DBWARD_TOKEN}"
          [databases.app]
          EOF

          dbward --environment production migrate up \
            --idempotency-key "deploy-${{ github.sha }}" \
            --ticket "${{ github.server_url }}/${{ github.repository }}/commit/${{ github.sha }}" \
            --repo "${{ github.repository }}"
```

### Handling pending approval

```yaml
      - name: Run migrations
        id: migrate
        continue-on-error: true
        run: dbward --environment production migrate up --idempotency-key "deploy-${{ github.sha }}"

      - name: Wait for approval if pending
        if: steps.migrate.outcome == 'failure'
        run: |
          # Exit code 2 = pending approval
          REQUEST_ID=$(dbward --format json --environment production migrate status | jq -r '.data.pending_request_id // empty')
          if [ -n "$REQUEST_ID" ]; then
            echo "⏳ Waiting for approval: $REQUEST_ID"
            echo "Approve with: dbward request approve $REQUEST_ID"
            # Optionally: poll until approved (with timeout)
            # dbward request resume $REQUEST_ID
          fi
```

## Token setup for CI

Create a dedicated CI token with appropriate permissions:

```bash
dbward token create \
  --subject "github-actions" \
  --scope-roles requester \
  --expires 90d
```

Store the token as a repository secret (`DBWARD_TOKEN`).

## Exit codes

| Code | Meaning | CI action |
|------|---------|-----------|
| 0 | Success | Continue pipeline |
| 1 | Error (auth failure, network, validation) | Fail pipeline |
| 2 | Pending approval / issues found | Wait or notify |
| 124 | Timeout (agent did not respond) | Retry or alert |
| 130 | Interrupted (SIGINT) | Re-run job |

## Idempotency

Use `--idempotency-key` to safely retry failed CI jobs:

```bash
dbward --environment production migrate up --idempotency-key "deploy-${GITHUB_SHA}"
```

If the request already exists (same key), dbward returns the existing request status instead of creating a duplicate.

## JSON output

Use `--format json` for machine-readable output. All commands produce a consistent JSON envelope on stdout:

```bash
dbward --format json --environment production migrate status
```

```json
{"ok": true, "data": {"migrations": [{"name": "20260501_create_users", "status": "applied"}, {"name": "20260502_add_index", "status": "pending"}]}}
```

Error responses follow the same structure:
```json
{"ok": false, "data": null, "error": {"code": "network_error", "message": "connection refused"}}
```

### Output modes for CI

| Mode | stdout | stderr | Best for |
|------|--------|--------|----------|
| `--format json` | JSON envelope | Error message only | Scripts that parse output with `jq` |
| `--format quiet` | JSON envelope | Nothing (0 bytes) | Log-free pipelines, health checks |

Use `--format quiet` when stderr noise would clutter CI logs:

```bash
RESULT=$(dbward --format quiet -y execute "SELECT version()" 2>/dev/null)
echo "$RESULT" | jq -r '.data.result_data.rows[0]'
```

### Parsing JSON in CI

```bash
# Check success
dbward --format json -y execute "SELECT 1" | jq -e '.ok'

# Extract data field
TOKEN=$(dbward --format json -y token create --scope-roles requester | jq -r '.data.token')

# Handle errors
RESULT=$(dbward --format json -y -e production execute "SELECT 1" 2>/dev/null)
if echo "$RESULT" | jq -e '.ok' > /dev/null 2>&1; then
  echo "Success"
else
  echo "Error: $(echo "$RESULT" | jq -r '.error.message')"
fi
```

## Auto-approve for staging

Configure workflows to auto-approve non-production environments:

```toml
# dbward-server.toml
[[workflows]]
database = "*"
environment = "staging"

[workflows.auto_approve]
mode = "always"
```

This lets CI deploy to staging without waiting, while production still requires human approval.

## Slack notification for approvals

Combine with webhooks so approvers are notified immediately:

```toml
[[webhooks]]
url = "${SLACK_WEBHOOK_URL}"
events = ["request.created"]
format = "slack"
```

When CI creates a migration request, the team gets a Slack message with the SQL and an approve prompt.

## See also

- [Migrations](migrations.md) — Migration file management
- [Workflows](policies/workflows.md) — Configure auto-approve for specific environments
