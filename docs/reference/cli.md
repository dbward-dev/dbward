# CLI Reference

## Global options

```
dbward [OPTIONS] <COMMAND>

Options:
  --config <PATH>        Config file path (default: dbward.toml)
  --database <NAME>      Target database (env: DBWARD_DATABASE)
  --environment, -e <ENV> Target environment (env: DBWARD_ENV)
  --format <FORMAT>      Output format: human | json (default: human)
```

## Commands

### `dbward init`

Create a `dbward.toml` config file interactively.

```bash
dbward init                    # Interactive prompts
dbward init --non-interactive  # Use defaults
dbward init --force            # Overwrite existing
```

### `dbward dev`

Start a local dev server + agent (single process, auto-approve all).

```bash
dbward dev --database-url "postgres://user:pass@localhost:5432/mydb"
dbward dev --database-url "..." --port 4000
```

### `dbward login`

Authenticate via OIDC (requires `[server.oidc]` in config).

```bash
dbward login            # Opens browser
dbward login --device   # Device flow (headless)
```

### `dbward logout`

Remove stored credentials.

### `dbward whoami`

Display current authenticated identity.

### `dbward execute`

Execute a SQL query through the approval workflow.

```bash
dbward execute "SELECT * FROM users LIMIT 10"
dbward execute "UPDATE users SET active = false WHERE id = 42"
dbward -e production execute "SELECT count(*) FROM orders"
```

Options:
| Flag | Description |
|------|-------------|
| `--emergency` | Break-glass bypass (skips approval) |
| `--reason <TEXT>` | Reason for the operation (required by some workflows) |
| `--output <PATH>` | Save result to file |
| `--no-save` | Don't save result locally |
| `--ticket <URL>` | Link to ticket/issue |
| `--repo <URL>` | Repository reference |
| `--idempotency-key <KEY>` | Prevent duplicate requests |
| `--share-with <SELECTOR>` | Share result (Pro). e.g., `group:backend-team` |

Exit codes: 0 = success, 1 = error, 2 = pending approval.

### `dbward migrate`

#### `dbward migrate create <name>`

Create migration files locally (no server needed).

```bash
dbward migrate create add_users_table
```

#### `dbward migrate up`

Apply pending migrations.

```bash
dbward migrate up              # All pending
dbward migrate up --count 1    # Next one only
dbward -e production migrate up --ticket "JIRA-123"
```

Options: `--count`, `--ticket`, `--repo`, `--idempotency-key`, `--share-with`

#### `dbward migrate down`

Rollback migrations.

```bash
dbward migrate down            # Last one (default --count 1)
dbward migrate down --count 2
```

#### `dbward migrate status`

Show migration status.

```bash
dbward migrate status
dbward -e production migrate status
```

### `dbward request`

#### `dbward request list`

```bash
dbward request list
dbward request list --status pending
dbward request list --pending-for-me
dbward request list --user alice --limit 20
```

#### `dbward request show <id>`

Display request details, approval progress, and SQL.

#### `dbward request approve <id>`

```bash
dbward request approve req_abc123
dbward request approve req_abc123 --comment "Verified row count"
```

#### `dbward request reject <id>`

```bash
dbward request reject req_abc123 --reason "Wrong table"
```

#### `dbward request cancel <id>`

```bash
dbward request cancel req_abc123 --reason "No longer needed"
```

#### `dbward request resume <id>`

Dispatch an approved request and wait for the result.

```bash
dbward request resume req_abc123
dbward request resume req_abc123 --output result.json
```

#### `dbward request result <id>`

Display a locally saved result.

### `dbward result list`

List shared results available to you.

### `dbward audit`

Search audit events.

```bash
dbward audit
dbward audit --user alice --limit 50
dbward audit --event-type request_approved --since 2026-05-01
dbward audit --category auth --outcome failure
dbward audit --verify   # Verify hash chain integrity
```

Options: `--limit`, `--user`, `--operation`, `--status`, `--event-type`, `--category`, `--outcome`, `--since`, `--until`, `--verify`

### `dbward server`

#### `dbward server start`

```bash
dbward server start
dbward server start --listen 0.0.0.0:3000 --data /var/lib/dbward/dbward.db --config dbward-server.toml
```

#### `dbward server token create`

```bash
dbward server token create --user alice --role admin --data dbward.db
dbward server token create --user bot --role developer --agent --data dbward.db
dbward server token create --user bob --role developer --groups "backend-team,dba-team" --data dbward.db
```

#### `dbward server token revoke`

```bash
dbward server token revoke --id tok_abc123 --data dbward.db
```

### `dbward agent`

Start the agent process.

```bash
dbward agent --config dbward-agent.toml
```

### `dbward mcp`

Start the MCP stdio server (for AI IDE integration).

```bash
dbward mcp
```

Reads config from `dbward.toml` (or `--config`). See [MCP Integration](../guides/mcp-integration.md).
