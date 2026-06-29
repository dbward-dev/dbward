---
title: CLI Reference
description: All dbward CLI commands and options
---

# CLI Reference

## Global Options

| Option | Short | Env | Default | Description |
|--------|-------|-----|---------|-------------|
| `--version` | `-v` | | | Show version and exit |
| `--config <PATH>` | | `DBWARD_CONFIG` | | Config file path (standalone mode) |
| `--merge-global` | | | false | Merge global config when --config is set |
| `--database <NAME>` | | `DBWARD_DATABASE` | | Target database |
| `-e, --environment <ENV>` | `-e` | `DBWARD_ENV` | | Target environment |
| `--format <FMT>` | | | human | Output format: `human`, `json` |
| `--allow-insecure` | | `DBWARD_ALLOW_INSECURE` | false | Allow HTTP connections to non-local servers. Suppresses transport security warnings. Does not bypass OIDC+HTTP rejection. |
| `--yes` | `-y` | `DBWARD_YES` | false | Skip interactive confirmation prompts. Env accepts `1`, `true`, or `yes`. |

---

## dbward execute

Execute a SQL query through the approval workflow.

```bash
dbward execute "SELECT * FROM users LIMIT 10"
dbward execute -e production --database app "DELETE FROM sessions WHERE expired = true"
dbward execute --emergency --reason "outage fix" "UPDATE config SET v = 'x'"
```

| Option | Default | Description |
|--------|---------|-------------|
| `<SQL>` (positional) | — | **Required.** SQL statement |
| `--emergency` | false | Break-glass bypass (requires --reason) |
| `--allow-ddl` | false | Allow DDL in emergency mode (requires --emergency) |
| `--reason <TEXT>` | | Reason for this request |
| `--output <PATH>` | | Save result to file |
| `--no-result-store` | false | Do not store query result on server. Request metadata and SQL text are always retained for audit. |
| `--result-format <FMT>` | table | Display format: `table`, `json`, `csv`, `vertical` |
| `--timeout <SECS>` | | Max wait time in seconds |
| `--idempotency-key <KEY>` | | Deduplication key |
| `--share-with <SELECTOR>` | | Share result (repeatable, e.g. `group:team`) |
| `--ticket <ID>` | | Metadata: ticket identifier |
| `--repo <URL>` | | Metadata: repository URL |

---

## dbward request

Manage requests.

### dbward request list

```bash
dbward request list
dbward request list --status pending --pending-for-me
```

| Option | Default | Description |
|--------|---------|-------------|
| `--limit <N>` | | Max results |
| `--status <STATUS>` | | Filter by status |
| `--pending-for-me` | false | Only show requests I can approve |
| `--user <ID>` | | Filter by requester |

### dbward request show

```bash
dbward request show <ID>
```

### dbward request approve

```bash
dbward request approve <ID>
dbward request approve <ID> --comment "Verified"
```

| Option | Description |
|--------|-------------|
| `--comment <TEXT>` | Approval comment |

### dbward request reject

```bash
dbward request reject <ID> --reason "Add WHERE clause"
```

| Option | Description |
|--------|-------------|
| `--reason <TEXT>` | Rejection reason (alias: `--comment`) |

### dbward request cancel

```bash
dbward request cancel <ID>
```

| Option | Description |
|--------|-------------|
| `--reason <TEXT>` | Cancellation reason |

### dbward request resume

Wait for execution and display result.

```bash
dbward request resume <ID>
dbward request resume <ID> --result-format json --output results.json
```

| Option | Default | Description |
|--------|---------|-------------|
| `--output <PATH>` | | Save result to file |
| `--result-format <FMT>` | table | Display format: `table`, `json`, `csv`, `vertical` |

### dbward request result

Retrieve execution result for a request.

```bash
dbward request result <ID>
dbward request result <ID> --execution <EXECUTION_ID>
dbward request result <ID> --output ./result.json
dbward request result <ID> --result-format csv
dbward request result <ID> --list
dbward request result <ID> --list --limit 10
```

| Option | Default | Description |
|--------|---------|-------------|
| `--execution <ID>` | latest | Retrieve a specific execution's result. Default: latest completed or failed execution |
| `--output <PATH>` | | Save result to a specific file (JSON) |
| `--result-format <FMT>` | table | Display format: `table`, `json`, `csv`, `vertical` |
| `--list` | | List execution history for this request |
| `--limit <N>` | 20 | Max results (with `--list`) |

`--list` cannot be combined with `--execution`, `--output`, or `--result-format`.

### dbward request results

List shared results across requests.

```bash
dbward request results
dbward request results --limit 20
```

| Option | Default | Description |
|--------|---------|-------------|
| `--limit <N>` | 50 | Max results |

---

## dbward migrate

Database migrations.

### dbward migrate create

Create a new migration file (local only).

```bash
dbward migrate create add_users_table
```

### dbward migrate status

Show applied and pending migrations.

```bash
dbward migrate status
```

### dbward migrate up

Apply pending migrations.

```bash
dbward migrate up
dbward migrate up --count 1
```

| Option | Default | Description |
|--------|---------|-------------|
| `--count <N>` | all | Max migrations to apply |
| `--ticket <ID>` | | Metadata |
| `--repo <URL>` | | Metadata |
| `--idempotency-key <KEY>` | | Deduplication key |
| `--share-with <SELECTOR>` | | Share result |

### dbward migrate down

Rollback migrations.

```bash
dbward migrate down
dbward migrate down --count 2
```

| Option | Default | Description |
|--------|---------|-------------|
| `--count <N>` | 1 | Migrations to rollback |
| `--ticket <ID>` | | Metadata |
| `--repo <URL>` | | Metadata |
| `--idempotency-key <KEY>` | | Deduplication key |

### dbward migrate repair

Repair schema_migrations metadata. This modifies only the version tracking table, not the actual database schema. Verify DB state manually before use.

```bash
dbward migrate repair --emergency --action mark-applied --version 20240601_add_index --reason "partial migration recovery"
dbward migrate repair --emergency --action remove --version 20240601_add_index --reason "rolled back manually"
```

| Option | Default | Description |
|--------|---------|-------------|
| `--action <ACTION>` | (required) | `mark-applied` or `remove` |
| `--version <VERSION>` | (required) | Migration version to repair |
| `--emergency` | (required) | Safety flag (break-glass permission required) |
| `--reason <TEXT>` | (required) | Reason for the repair (recorded in audit log) |
| `--ticket <ID>` | | Metadata |
| `--repo <URL>` | | Metadata |

---

## dbward audit

Search and verify audit logs.

```bash
dbward audit
dbward audit --user alice --since 2026-05-01 --output json
dbward audit --verify
```

| Option | Default | Description |
|--------|---------|-------------|
| `--limit <N>` | | Max results |
| `--user <ID>` | | Filter by actor |
| `--operation <OP>` | | Filter by operation |
| `--status <STATUS>` | | Filter by status |
| `--event-type <TYPE>` | | Filter by event type |
| `--category <CAT>` | | Filter by category |
| `--outcome <OUTCOME>` | | Filter by outcome |
| `--since <DATETIME>` | | Events after this time |
| `--until <DATETIME>` | | Events before this time |
| `--verify` | false | Verify hash chain integrity |
| `--output <FMT>` | table | Output format: `table`, `json`, `csv` |

---

## dbward token

Manage API tokens.

### dbward token create

```bash
dbward token create --subject alice --scope-roles developer
dbward token create --subject agent-1 --subject-type agent --no-scope-ceiling
dbward token create --subject bob --scope-roles developer,dba --expires 90d
```

| Option | Default | Description |
|--------|---------|-------------|
| `--subject <ID>` | — | **Required.** Subject ID |
| `--scope-roles <ROLES>` | — | Comma-separated roles for scope ceiling. **Required** for user tokens. Conflicts with `--no-scope-ceiling`. |
| `--subject-type <TYPE>` | user | `user` or `agent` |
| `--name <NAME>` | | Token display name |
| `--no-scope-ceiling` | false | Remove scope ceiling (agent tokens only). Token inherits all bound roles. Conflicts with `--scope-roles`. |
| `--expires <DURATION>` | | Expiry: `90d`, `24h`, `30m`, ISO date, or datetime |
| `--role <ROLE>` | | **Deprecated.** Alias for `--scope-roles`. Will be removed in a future release. |

### dbward token list

```bash
dbward token list
dbward token list --subject alice --status active
```

| Option | Description |
|--------|-------------|
| `--subject <ID>` | Filter by subject |
| `--status <STATUS>` | `active` or `revoked` |
| `--type <TYPE>` | `user` or `agent` |

### dbward token revoke

```bash
dbward token revoke <ID>
```

### dbward token inspect

Show a token's current effective permissions. Token owners can inspect their own tokens; otherwise requires `token.write` permission.

```bash
dbward token inspect <ID>
```

---

## dbward user

### dbward user update

Update your user profile.

```bash
dbward user update --slack-user-id U02CR3TMKKJ
```

| Option | Description |
|--------|-------------|
| `--slack-user-id <ID>` | Link Slack account for approval notifications |

---

## dbward login / logout / whoami

OIDC authentication.

```bash
dbward login              # Browser-based login
dbward login --device     # Device flow (headless/SSH)
dbward logout             # Revoke tokens + delete credentials
dbward whoami             # Show current identity
```

| Option | Description |
|--------|-------------|
| `--device` | Use device code flow (login only) |

`whoami` shows Subject, Roles, and Groups when connected to the server. Falls back to local OIDC credentials if the server is unreachable.

---

## dbward databases

List registered databases.

```bash
dbward databases
dbward databases --format json
```

---

## dbward agents

Show agent status (admin only).

```bash
dbward agents
dbward agents --format json
```

---

## dbward policy resolve

Show effective policy for a database/environment combination.

```bash
dbward policy resolve app production
dbward policy resolve app production --operation execute_dml
```

| Option | Description |
|--------|-------------|
| `<DATABASE>` (positional) | **Required.** Database name |
| `<ENVIRONMENT>` (positional) | **Required.** Environment name |
| `--operation <OP>` | Specific operation to resolve |

---

## dbward doctor

Diagnose configuration and connectivity. Checks include server reachability, OIDC discovery, agent polling, and **token binding validation** (verifies that all token subjects have at least one matching `[[auth.role_bindings]]` entry or `default_role`).

```bash
dbward doctor
dbward doctor --agent agent.toml
dbward doctor --server server.toml
```

| Option | Default | Description |
|--------|---------|-------------|
| `--agent <PATH>` | | Validate agent config |
| `--server <PATH>` | | Validate server config |
| `--timeout <SECS>` | 5 | Network timeout per check |

---

## dbward init

Initialize configuration files.

```bash
dbward init
dbward init --preset small-team --output-dir ./config
```

| Option | Default | Description |
|--------|---------|-------------|
| `--preset <NAME>` | | Config template (e.g. `small-team`) |
| `--output-dir <PATH>` | `.` | Output directory |
| `--non-interactive` | false | Skip prompts |
| `--force` | false | Overwrite existing files |
| `--dry-run` | false | Print to stdout only |

---

## dbward dev

Start local development server + agent (single process).

```bash
dbward dev --database-url "postgres://localhost/myapp"
```

| Option | Default | Description |
|--------|---------|-------------|
| `--database-url <URL>` | — | **Required.** Database connection URL |
| `--port <PORT>` | 3000 | Server port |

---

## dbward server start

Start the dbward HTTP server (production).

```bash
dbward server start --config server.toml --listen 0.0.0.0:3000
```

| Option | Default | Description |
|--------|---------|-------------|
| `--config <PATH>` | `dbward-server.toml` | Server config file |
| `--listen <ADDR>` | `127.0.0.1:3000` | Listen address |

---

## dbward agent

Start the dbward agent.

```bash
dbward agent --config agent.toml
```

| Option | Default | Description |
|--------|---------|-------------|
| `--config <PATH>` | `dbward-agent.toml` | Agent config file |

---

## dbward mcp

Start MCP stdio server (for AI IDE integration).

```bash
dbward mcp
```

No additional options. See [MCP Reference](mcp.md).

---

## dbward self-update

Update dbward to the latest version.

```bash
dbward --version        # check current version
dbward self-update      # download and install latest
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error (connection, validation, execution failure) |
| 2 | Approval pending (request created but not yet approved) |
