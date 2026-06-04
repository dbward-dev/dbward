---
title: MCP Reference
description: Complete reference for dbward's MCP tools, resources, and prompts
---

# MCP Reference

dbward exposes 12 tools, 3 fixed resources, 3 resource templates, and 6 prompts via the Model Context Protocol (MCP). Start the MCP server with `dbward mcp`.

For setup instructions, see [MCP Integration](../guides/mcp-integration.md).

---

## Tools (12)

### dbward_execute_query

Execute a SQL query through the approval workflow.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `sql` | string | ✓ | SQL statement to execute |
| `database` | string | | Target database name |
| `environment` | string | | Environment (development/staging/production) |
| `reason` | string | | Reason for execution (required by some workflows) |

Returns: Query result (rows) or approval status. If approval is needed, uses elicitation to wait.

### dbward_migrate_status

Show migration status (applied/pending).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `database` | string | | Target database name |
| `environment` | string | | Environment |

### dbward_migrate_up

Apply pending database migrations.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `count` | integer | | Max migrations to apply (default: all) |
| `database` | string | | Target database name |
| `environment` | string | | Environment |

### dbward_migrate_down

Rollback database migrations.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `count` | integer | | Migrations to rollback (default: 1) |
| `database` | string | | Target database name |
| `environment` | string | | Environment |

### dbward_migrate_create

Create a new migration file locally (no server needed).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | ✓ | Migration name (e.g., `create_users`) |

Returns: Path to created file with up/down template.

### dbward_wait_request

Check request status or wait for completion.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `request_id` | string | ✓ | Request ID |
| `timeout` | integer | | Max wait seconds (default: 60) |
| `include_result` | boolean | | If true (default), resume and return result. If false, status only. |

### dbward_list_pending

List requests pending approval. No parameters.

### dbward_who_can_approve

Show who can approve a specific request.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `request_id` | string | ✓ | Request ID |

Returns: Roles, groups, and step information for approvers.

### dbward_find_similar_requests

Find past requests similar to the given SQL or operation.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `sql` | string | | SQL to match against |
| `operation` | string | | Operation type filter |
| `limit` | integer | | Max results (default: 5) |

### dbward_preview_impact

Preview the impact of a SQL statement (EXPLAIN output).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `sql` | string | ✓ | SQL statement to explain |
| `database` | string | | Target database name |
| `environment` | string | | Environment |

### dbward_explain_policy_failure

Explain why a request was blocked or requires approval.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `request_id` | string | | Existing request ID |
| `operation` | string | | Operation type |
| `environment` | string | | Environment |
| `database` | string | | Database name |

Provide either `request_id` (for an existing request) or `operation` + `environment` + `database` (for hypothetical check).

### dbward_inspect_schema

Inspect database schema.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `table` | string | | Table name (omit to list all tables) |
| `database` | string | | Target database name |

---

## Resources (3 fixed)

| URI | Name | Description |
|-----|------|-------------|
| `dbward://migrations/status` | Migration Status | Applied and pending migrations |
| `dbward://requests/pending` | Pending Requests | Requests awaiting approval |
| `dbward://audit/recent` | Recent Audit Events | Last 10 audit events |

## Resource Templates (3)

| URI Template | Name | Description |
|--------------|------|-------------|
| `dbward://requests/{request_id}` | Request Details | Details for a specific request |
| `dbward://schema/{database}` | Database Schema | Table list with row counts |
| `dbward://schema/{database}/{table}` | Table Schema | Column, constraint, and index details |

---

## Prompts (6)

### review_migration

Review a migration SQL file for safety issues (locking, data loss, backwards compatibility).

| Argument | Required | Description |
|----------|----------|-------------|
| `file_path` | ✓ | Path to migration file |

### explain_request

Explain what a request will do and its impact.

| Argument | Required | Description |
|----------|----------|-------------|
| `request_id` | ✓ | Request ID |

### draft_migration

Generate migration SQL from a natural language description.

| Argument | Required | Description |
|----------|----------|-------------|
| `description` | ✓ | What the migration should do |

### draft_rollback

Generate rollback SQL for an existing migration.

| Argument | Required | Description |
|----------|----------|-------------|
| `migration_file` | ✓ | Path to migration file to rollback |

### summarize_audit_trail

Summarize recent audit events.

| Argument | Required | Description |
|----------|----------|-------------|
| `since` | | Start date (ISO 8601) |
| `database` | | Filter by database |

### prepare_approval_comment

Draft an approval comment for a request.

| Argument | Required | Description |
|----------|----------|-------------|
| `request_id` | ✓ | Request ID to review |

---

## Environment resolution

Tools that need `environment` resolve it in this order:

1. `environment` parameter in the tool call
2. `DBWARD_ENV` environment variable
3. `default_environment` in CLI config

If none is set, tools that require environment return an error.

## See also

- [MCP Integration Guide](../guides/mcp-integration.md) — IDE setup and usage
- [Executing Queries](../guides/executing-queries.md) — the approval flow
