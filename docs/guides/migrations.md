# Migrations

dbward manages database migrations with approval workflows. Migrations go through the same approval process as ad-hoc queries.

## File structure

```
db/migrations/
├── 20260501120000_create_users.sql
├── 20260502090000_add_email_index.sql
└── 20260503140000_create_orders.sql
```

Each migration is a single `.sql` file with a timestamp prefix. The file contains `-- migrate:up` and `-- migrate:down` markers:

```sql
-- migrate:up
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL
);

-- migrate:down
DROP TABLE users;
```

## Commands

### Create a migration

```bash
dbward migrate create add_users_table
# Created: db/migrations/20260508120000_add_users_table.sql
```

This is a local-only operation — no server connection needed. The generated file contains placeholder markers for up and down SQL.

### Check status

```bash
dbward migrate status
```

```
┌────────────────────────────────────────────┬─────────┐
│ Migration                                  │ Status  │
├────────────────────────────────────────────┼─────────┤
│ 20260501120000_create_users                │ applied │
│ 20260502090000_add_email_index             │ applied │
│ 20260503140000_create_orders               │ pending │
└────────────────────────────────────────────┴─────────┘
```

### Apply migrations (up)

```bash
# Apply all pending migrations
dbward migrate up

# Apply only the next N migrations
dbward migrate up --count 1
```

If a workflow is configured for the target environment, the migration requires approval before executing.

### Rollback (down)

```bash
# Roll back the last migration
dbward migrate down

# Roll back the last N migrations
dbward migrate down --count 2
```

## Approval flow

Migrations go through the same workflow as `execute_select`. If your production workflow requires approval:

```bash
$ dbward -e production migrate up
⚠ Request req_m1a2 requires approval.
  Approvers: dba-team
Run: dbward request resume req_m1a2
```

After approval:

```bash
$ dbward request resume req_m1a2
✓ Resuming req_m1a2...
  Applied: 20260503140000_create_orders (up)
```

## Multiple databases

If your project has multiple databases, specify which one:

```bash
# Use --database flag
dbward --database analytics migrate status

# Or set default in dbward.toml
# default_database = "app"
```

Migration files are stored per-database:

```toml
# dbward.toml
[databases.app]
migrations_dir = "db/migrations/app"

[databases.analytics]
migrations_dir = "db/migrations/analytics"
```

## Metadata options

Attach metadata to migration requests for audit trails:

```bash
dbward migrate up \
  --ticket "JIRA-1234" \
  --repo "github.com/myorg/myapp"
```

These values are recorded in the audit log and visible in `dbward request show`.

## Idempotency

Use `--idempotency-key` to prevent duplicate submissions in CI/CD:

```bash
dbward migrate up --idempotency-key "deploy-abc123"
```

If a request with the same key already exists, dbward returns the existing request instead of creating a new one.

## Result sharing

Share migration results with your team (Pro):

```bash
dbward migrate up --share-with "group:backend-team"
```

## Next steps

- [CI/CD](ci-cd.md) — Automate migrations in pipelines
- [Workflows](workflows.md) — Configure approval for migrations
