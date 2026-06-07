---
title: Migrations
description: Manage database migrations with approval workflows
---

# Migrations

dbward manages database migrations with approval workflows. Migrations go through the same approval process as ad-hoc queries.

## File structure

```
migrations/
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
# Created: migrations/20260508120000_add_users_table.sql
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

Migrations go through the their own operations (`migrate_up`, `migrate_down`). If your production workflow requires approval:

```bash
$ dbward -e production migrate up
⚠ Request m1a2 requires approval.
  Approvers: dba-team
Run: dbward request resume m1a2
```

After approval:

```bash
$ dbward request resume m1a2
✓ Dispatching m1a2...
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
migrations_dir = "migrations/app"

[databases.analytics]
migrations_dir = "migrations/analytics"
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

Share migration results with your team:

```bash
dbward migrate up --share-with "group:backend-team"
```

## Next steps

- [CI/CD](ci-cd.md) — Automate migrations in pipelines
- [Workflows](policies/workflows.md) — Configure approval for migrations

---

## Safety features

### Statement timeout

Migrations respect `statement_timeout_secs` from your execution policy or workflow configuration. If a migration SQL exceeds the timeout, it is cancelled:

- **PostgreSQL (transactional)**: `SET LOCAL statement_timeout` cancels the statement and rolls back the implicit transaction (atomicity preserved).
- **PostgreSQL (non-transactional)**: Statement is cancelled but side effects may persist (e.g., `CREATE INDEX CONCURRENTLY` leaves an invalid index). Manual inspection required.
- **MySQL**: `tokio::time::timeout` + `KILL CONNECTION` terminates the session. Schema state is unknown after timeout — manual inspection required.

Default timeout is 30 seconds. Configure longer timeouts for heavy migrations:

> **Important**: The default 30-second timeout applies to migrations as well. Most DDL operations (e.g., `ALTER TABLE` on large tables) take longer than 30 seconds. Always configure an appropriate timeout for environments where migrations run:

```toml
[[execution_policies]]
statement_timeout_secs = 300
max_statement_timeout_secs = 3600
migration_lease_duration_secs = 3600
```

### MySQL DDL warning

MySQL DDL statements (`CREATE`, `ALTER`, `DROP`, `TRUNCATE`, `RENAME`) cause an implicit commit, meaning transaction atomicity is not guaranteed. dbward logs a warning when DDL is detected in a migration.

### Non-transactional migrations

Use `-- migrate:up transaction:false` for statements that cannot run inside a transaction (e.g., `CREATE INDEX CONCURRENTLY` on PostgreSQL):

```sql
-- migrate:up transaction:false
CREATE INDEX CONCURRENTLY idx_users_email ON users(email);

-- migrate:down transaction:false
DROP INDEX CONCURRENTLY idx_users_email;
```

If the SQL succeeds but the version record fails, dbward returns a `PartialMigration` error with a suggested repair command.

### Repairing metadata

If schema_migrations gets out of sync with the actual database state, use `migrate repair`:

```bash
dbward migrate repair --emergency --action mark-applied --version 20240601_add_index --reason "SQL applied but version record failed"
dbward migrate repair --emergency --action remove --version 20240601_add_index --reason "manually rolled back"
```

This command only modifies the `schema_migrations` table — it does not alter the actual database schema. Always verify DB state before using repair.
