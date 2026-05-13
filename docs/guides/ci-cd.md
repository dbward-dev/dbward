# CI/CD Integration

Run migrations and database operations in CI/CD pipelines with dbward's approval workflow.

## Key features for CI/CD

- **Exit code 2** = approval pending (pipeline can wait or notify)
- **`--idempotency-key`** = prevent duplicate requests on retry
- **`--format json`** = machine-readable output
- **API tokens** = no interactive login needed

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
          curl -sL https://github.com/dbward-dev/dbward/releases/latest/download/dbward-linux-amd64 -o dbward
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

          dbward -e production migrate up \
            --idempotency-key "deploy-${{ github.sha }}" \
            --ticket "${{ github.server_url }}/${{ github.repository }}/commit/${{ github.sha }}" \
            --repo "${{ github.repository }}"
```

### Handling pending approval

```yaml
      - name: Run migrations
        id: migrate
        continue-on-error: true
        run: dbward -e production migrate up --idempotency-key "deploy-${{ github.sha }}"

      - name: Wait for approval if pending
        if: steps.migrate.outcome == 'failure'
        run: |
          # Exit code 2 = pending approval
          REQUEST_ID=$(dbward -e production migrate status --format json | jq -r '.pending_request_id // empty')
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
dbward server token create \
  --user "github-actions" \
  --role developer \
  --data dbward.db
```

Store the token as a repository secret (`DBWARD_TOKEN`).

## Exit codes

| Code | Meaning | CI action |
|------|---------|-----------|
| 0 | Success | Continue pipeline |
| 1 | Error (auth failure, network, etc.) | Fail pipeline |
| 2 | Pending approval | Wait or notify |

## Idempotency

Use `--idempotency-key` to safely retry failed CI jobs:

```bash
dbward -e production migrate up --idempotency-key "deploy-${GITHUB_SHA}"
```

If the request already exists (same key), dbward returns the existing request status instead of creating a duplicate.

## JSON output

Use `--format json` for machine-readable output:

```bash
dbward --format json -e production migrate status
```

```json
{
  "migrations": [
    {"name": "20260501_create_users", "status": "applied"},
    {"name": "20260502_add_index", "status": "pending"}
  ]
}
```

## Auto-approve for staging

Configure workflows to auto-approve non-production environments:

```toml
# dbward-server.toml
[[workflows]]
database = "*"
environment = "staging"
# No steps = auto-approve
```

This lets CI deploy to staging without waiting, while production still requires human approval.

## Slack notification for approvals

Combine with webhooks so approvers are notified immediately:

```toml
[[webhooks]]
url = "${SLACK_WEBHOOK_URL}"
events = ["request_created"]
format = "slack"
```

When CI creates a migration request, the team gets a Slack message with the SQL and an approve prompt.

## Next steps

- [Migrations](migrations.md) — Migration file management
- [Workflows](workflows.md) — Configure auto-approve for specific environments
