---
title: SQL Safety Reference
description: How dbward classifies, reviews, and scores SQL operations
---

# SQL Safety Reference

dbward processes every SQL statement through three safety layers before execution:

1. **Classification** — determines the operation type
2. **Review** — checks for risky patterns
3. **Risk scoring** — calculates overall risk level for auto-approve decisions

---

## SQL Classification

Every statement is classified into one of three categories:

### ExecuteSelect (read-only)

- `SELECT`
- `SHOW`
- `EXPLAIN` (without ANALYZE)
- `EXPLAIN ANALYZE` on SELECT statements
- `SET` (safe session variables only)

### ExecuteDml (write operations)

- `INSERT`, `UPDATE`, `DELETE`, `MERGE`
- `COPY`
- `CALL` (stored procedures)
- `CREATE TABLE`, `CREATE VIEW`, `CREATE INDEX`
- `ALTER TABLE`
- `SELECT` with writable CTE (`WITH ... INSERT/UPDATE/DELETE`)
- `SELECT` with dangerous functions (24 known functions)
- `EXPLAIN ANALYZE` on DML statements (actually executes the inner statement)
- `SELECT INTO`

#### DestructiveDdl (subcategory of ExecuteDml)

These statements are classified as ExecuteDml but flagged as DestructiveDdl. They pass through the classifier and are controlled by [sql_review rules](#sql-review-14-rules):

- `DROP TABLE` ¹
- `DROP VIEW` ¹
- `DROP INDEX` ¹
- `DROP SEQUENCE` ¹
- `TRUNCATE` ¹
- `CREATE SEQUENCE` ¹

¹ Requires `Permission::RequestDdl` (`request.ddl`). Controlled by sql_review rules (default: `block` for `drop_table`/`truncate`, `warn` for others). `--allow-ddl` bypasses sql_review blocks. See [Break-Glass](../guides/break-glass.md).

### Rejected (blocked by default)

- `DROP SCHEMA/DATABASE/FUNCTION/ROLE`
- `CREATE FUNCTION/PROCEDURE/TRIGGER/ROLE/DATABASE`
- `GRANT`, `REVOKE`
- `BEGIN`, `COMMIT`, `ROLLBACK`, `SAVEPOINT`
- `LOCK TABLE`
- `LOAD DATA`
- `SET` (unsafe variables)

### Special rules

| Condition | Result |
|-----------|--------|
| Parse failure | Classified as ExecuteDml (fail-closed: requires approval) |
| Unknown statement type | Classified as ExecuteDml |
| Input > 1 MB | Rejected |
| > 100 statements | Rejected |
| Multiple SELECT statements | Rejected (use single SELECT) |
| `SET` + `SELECT` combo | Allowed |
| NULL bytes in input | Rejected |

---

## SQL Review (14 rules)

Each rule has a configurable severity: `warn`, `block`, or `off`.

- `block` (default for `no_where_delete`, `no_where_update`, `drop_table`, `truncate`) — rejects the request regardless of workflow (DDL rules ² can be bypassed with `--allow-ddl`)
- `warn` (default for `drop_column`, `not_null_without_default`, `create_index_not_concurrently`, `alter_column_type`, `mixed_ddl_dml`, `large_in_list`, `drop_index`, `drop_view`, `drop_sequence`) — adds a finding to the risk assessment
- `off` (default for `create_sequence`) — rule is disabled

```toml
[[sql_review]]
database = "*"
environment = "development"
no_where_delete = "warn"
no_where_update = "warn"
drop_table = "warn"
drop_column = "warn"
not_null_without_default = "warn"
create_index_not_concurrently = "warn"
alter_column_type = "warn"
truncate = "warn"
mixed_ddl_dml = "warn"
large_in_list = "warn"
drop_index = "warn"
drop_view = "warn"
drop_sequence = "warn"
create_sequence = "off"
```

### Rule descriptions

| Rule | Fires when | Risk |
|------|-----------|------|
| `no_where_delete` | `DELETE` without `WHERE` clause | Entire table deletion |
| `no_where_update` | `UPDATE` without `WHERE` clause | Entire table overwrite |
| `drop_table` | `DROP TABLE` detected | Permanent data loss |
| `drop_column` | `ALTER TABLE DROP COLUMN` | Column data loss |
| `not_null_without_default` | `ALTER TABLE ADD COLUMN NOT NULL` without `DEFAULT` | Fails on existing rows |
| `create_index_not_concurrently` | `CREATE INDEX` without `CONCURRENTLY` (PostgreSQL) | Table lock during build |
| `alter_column_type` | `ALTER COLUMN ... TYPE` | Table rewrite, potential data loss |
| `truncate` | `TRUNCATE TABLE` | All data removed |
| `mixed_ddl_dml` | DDL and DML in same request | Complex rollback |
| `large_in_list` | `IN (...)` with > 100 values | Performance concern |
| `drop_index` | `DROP INDEX` detected | Index removal, query performance impact |
| `drop_view` | `DROP VIEW` detected | View removal, dependent queries break |
| `drop_sequence` | `DROP SEQUENCE` detected | Sequence removal, ID generation impact |
| `create_sequence` | `CREATE SEQUENCE` detected | New sequence creation |

² DDL rules (`drop_table`, `drop_column`, `truncate`, `create_index_not_concurrently`, `alter_column_type`, `not_null_without_default`, `drop_index`, `drop_view`, `drop_sequence`, `create_sequence`) can be bypassed with `--allow-ddl`. DML safety rules (`no_where_delete`, `no_where_update`, `large_in_list`) and `mixed_ddl_dml` are never bypassable.

---

## Risk Scoring

Risk scoring determines whether a request qualifies for [auto-approve](../guides/policies/auto-approve.md).

### Levels

| Level | Numeric | Meaning |
|-------|---------|---------|
| Low | 1 | Safe (SELECT, safe DDL, small tables) |
| Medium | 2 | Moderate concern |
| High | 3 | Significant risk |
| Critical | 4 | Reserved |
| Unknown | 5 | Cannot assess (schema not synced) |
| Unavailable | 6 | Parse failure |

### Scoring rules

| Condition | Level |
|-----------|-------|
| SELECT + `allow_read_only` | Low |
| Safe DDL (CREATE TABLE/VIEW/INDEX) + `allow_safe_ddl` | Low |
| Schema not synced | Unknown |
| Multi-statement DML (>1 DML) | High |
| DROP or TRUNCATE detected | High |
| ≥ 3 review warnings | High |
| CASCADE FK + large table (> max_estimated_rows) | High |
| CASCADE FK + small table | Medium |
| Large table without cascade | Medium |
| 1-2 review warnings | Medium |
| None of the above | Low |

### Safe DDL

These CREATE/ALTER statements are considered safe regardless of table size:
- `CREATE TABLE` (new table, no existing data)
- `CREATE VIEW`
- `CREATE INDEX CONCURRENTLY` (PostgreSQL only)
- `ALTER TABLE ... ADD COLUMN` (PostgreSQL only, no lock on existing rows)

---

## Dangerous functions (24)

Functions that promote a `SELECT` to `ExecuteDml`:

`dblink`, `dblink_exec`, `dblink_connect`, `lo_export`, `lo_import`, `lo_unlink`, `pg_read_file`, `pg_read_binary_file`, `pg_ls_dir`, `pg_execute_server_program`, `copy_to`, `copy_from`, `set_config`, `pg_cancel_backend`, `pg_terminate_backend`, `pg_sleep`, `pg_advisory_lock`, `pg_advisory_xact_lock`, `pg_notify`, `sys_exec`, `sys_eval`, `load_file`, `sleep`, `benchmark`

---

## See also

- [Auto-Approve](../guides/policies/auto-approve.md) — how risk scoring drives auto-approve
- [Policies Overview](../guides/policies/overview.md) — fail-closed principle
- [Configuration Reference](configuration.md#sql_review) — full config fields
