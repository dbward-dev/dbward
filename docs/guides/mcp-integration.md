# MCP Integration

Use dbward from AI-powered IDEs (Cursor, GitHub Copilot, Kiro) via the [Model Context Protocol](https://modelcontextprotocol.io). The AI can query databases, run migrations, and check request status — all through dbward's approval workflow.

## Why MCP?

- **AI never gets DB credentials** — all operations go through dbward's approval engine
- **Same workflow for humans and AI** — production queries still require human approval
- **Full audit trail** — every AI-initiated operation is logged with the AI tool as actor

## Setup

### 1. Configure dbward client

Ensure you have a working `dbward.toml`:

```toml
[server]
url = "https://dbward.internal:3000"
token = "dbw_..."
```

### 2. Add to your IDE

#### Cursor

Add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "dbward": {
      "command": "dbward",
      "args": ["mcp"],
      "env": {}
    }
  }
}
```

#### GitHub Copilot (VS Code)

Add to `.vscode/mcp.json`:

```json
{
  "servers": {
    "dbward": {
      "command": "dbward",
      "args": ["mcp"]
    }
  }
}
```

#### Kiro

Add to `.kiro/settings/mcp.json`:

```json
{
  "mcpServers": {
    "dbward": {
      "command": "dbward",
      "args": ["mcp"],
      "transportType": "stdio"
    }
  }
}
```

### 3. Verify

Ask your AI assistant: "What tables are in the database?" — it should use `dbward_inspect_schema` to answer.

## Available tools (12)

### Database operations

| Tool | Description |
|------|-------------|
| `dbward_execute_query` | Execute SQL (goes through approval workflow) |
| `dbward_inspect_schema` | Inspect schema (list tables or describe columns) |
| `dbward_preview_impact` | Run EXPLAIN to preview query impact |

### Request management

| Tool | Description |
|------|-------------|
| `dbward_wait_request` | Wait for request completion and return result |
| `dbward_list_pending` | List requests awaiting approval |
| `dbward_who_can_approve` | Show who can approve a request |
| `dbward_find_similar_requests` | Find similar past requests |

### Migrations

| Tool | Description |
|------|-------------|
| `dbward_migrate_status` | Show migration status |
| `dbward_migrate_up` | Apply migrations |
| `dbward_migrate_down` | Rollback migrations |
| `dbward_migrate_create` | Create migration files (local) |

### Analysis

| Tool | Description |
|------|-------------|
| `dbward_explain_policy_failure` | Explain why a request was blocked |

## How approval works with AI

When the AI executes a query that requires approval:

1. AI calls `dbward_execute_query` → request created (status: pending)
2. If the IDE supports **elicitation**, dbward asks the user for confirmation directly in the IDE
3. Otherwise, the AI reports the request ID and waits
4. A human approves via CLI, another IDE, or Slack
5. AI calls `dbward_wait_request` to wait for approval and result
6. Once complete, the result is returned directly

### Elicitation (interactive approval prompt)

On production operations without a `--reason`, dbward uses MCP elicitation to ask the user directly:

```
dbward: This operation targets production and requires a reason.
Please provide a reason for this query:
> [user types reason in IDE]
```

This works in IDEs that support MCP elicitation (protocol version 2025-11-05+).

## Resources

The MCP server exposes read-only resources:

| Resource | Description |
|----------|-------------|
| `dbward://migrations/status` | Current migration state |
| `dbward://requests/pending` | Pending approval requests |
| `dbward://audit/recent` | Recent audit events |
| `dbward://requests/{id}` | Specific request details (template) |
| `dbward://schema/{database}` | Table list with row counts (from agent snapshot) |
| `dbward://schema/{database}/{table}` | Column, constraint, and index details for a table |

### Schema resources

Schema resources return data from agent-collected snapshots (no live DB query needed).

```
dbward://schema/app          → all tables (name, schema, rows, column count)
dbward://schema/app/users    → full details for 'users' table
dbward://schema/app/public.orders → schema-qualified lookup
```

The server automatically resolves the best environment (production > staging > development) based on snapshot availability and your permissions. The response includes `environment` and `collected_at` so you know which snapshot you're seeing.

If no snapshot is available yet, start an agent for the database — it collects schema on startup.

## Prompts

Pre-built prompts for common AI workflows:

| Prompt | Description |
|--------|-------------|
| `review_migration` | Review a migration for safety issues |
| `explain_request` | Explain what a request will do |
| `draft_migration` | Generate migration SQL from a description |
| `draft_rollback` | Generate rollback SQL for a migration |
| `summarize_audit_trail` | Summarize recent audit events |
| `prepare_approval_comment` | Draft an approval comment |

## Example conversation

> **You:** "Add an index on users.email for faster lookups"
>
> **AI:** I'll create a migration for that.
> *[calls `dbward_migrate_create` with name "add_user_preferences"]*
>
> Created `db/migrations/20260508_add_user_preferences/up.sql`. Here's the SQL:
> ```sql
> CREATE TABLE IF NOT EXISTS user_preferences (
>   user_id INTEGER REFERENCES users(id),
>   key TEXT NOT NULL,
>   value TEXT,
>   PRIMARY KEY (user_id, key)
> );
> ```
>
> **You:** "Apply it to staging"
>
> **AI:** *[calls `dbward_migrate_up` with environment "staging"]*
>
> ✓ Migration applied to staging (auto-approved).
>
> **You:** "Now apply to production"
>
> **AI:** *[calls `dbward_migrate_up` with environment "production"]*
>
> ⚠ Request req_m3x4 requires approval from dba-team.
> I'll check back when it's approved.
>
> *[waits with `dbward_wait_request`]*
>
> ✓ Approved by bob@example.com. Migration applied successfully.

## Security considerations

- The AI tool authenticates as the **user's identity** (their token or OIDC session)
- The AI cannot bypass approval workflows
- All AI-initiated operations appear in the audit log
- The AI never sees database credentials

## Next steps

- [Workflows](workflows.md) — Configure what requires approval
- [Authentication](../deployment/authentication.md) — Token setup for MCP
