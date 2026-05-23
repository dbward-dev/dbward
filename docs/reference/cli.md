# CLI Reference

## Global Options

```
--config <PATH>     Config file path (env: DBWARD_CONFIG)
--database <NAME>   Target database (env: DBWARD_DATABASE)
--environment <ENV> Target environment (env: DBWARD_ENV)
--format <FORMAT>   Output format: human (default), json
```

---

## Commands

### dbward init

Initialize configuration file interactively.

```bash
dbward init
dbward init --non-interactive --force
```

| Option | Description |
|--------|-------------|
| `--non-interactive` | Skip prompts, use defaults |
| `--force` | Overwrite existing config |

---

### dbward execute

Execute a SQL query through the approval workflow.

```bash
dbward execute "SELECT * FROM users"
dbward execute "UPDATE users SET active = false WHERE id = 5" --reason "Disable inactive user"
dbward execute "DROP TABLE temp" --emergency --reason "Production incident"
```

| Option | Description |
|--------|-------------|
| `--reason <TEXT>` | Reason for this request |
| `--emergency` | Break-glass bypass (requires `--reason`) |
| `--timeout <SECS>` | Timeout in seconds (no timeout if not specified). Exit code 124 on timeout |
| `--output <PATH>` | Save result to file |
| `--no-save` | Do not save result locally |
| `--no-store` | Do not persist result to server storage |
| `--share-with <SELECTOR>` | Share result (e.g. `group:dba`, `user:bob`) |
| `--ticket <ID>` | Attach ticket metadata |
| `--repo <NAME>` | Attach repository metadata |
| `--idempotency-key <KEY>` | Deduplication key |
| `--result-format <FORMAT>` | Result display format: `table` (default), `json`, `csv` |

---

### dbward request

Manage approval requests.

#### dbward request list

```bash
dbward request list
dbward request list --status pending --user alice
```

| Option | Description |
|--------|-------------|
| `--status <STATUS>` | Filter by status |
| `--user <USER>` | Filter by requester |

#### dbward request show

```bash
dbward request show <ID>
dbward request show <ID> --json   # Full JSON output (includes raw EXPLAIN plan)
```

Shows request details including automatically collected context:

```
Request 0da70e0e-...
  Status:      pending
  Operation:   execute_dml
  Detail:      DELETE FROM orders WHERE status = 'pending' AND created_at < '2025-01-01'
  Environment: production
  Database:    app
  Reason:      Quarterly cleanup
  Created by:  alice

  Risk:        High (CascadeDelete { targets: ["users"] })
  SQL Review:  passed
  Tables:      orders
  Explain:     ModifyTable on orders (rows=0, cost=1342)
                 Seq Scan on orders (rows=1, cost=1342)  Filter: ((created_at < ...))

  Approval (0/2 complete):
    [wait] Step 1 [all]: group:backend-team
    [wait] Step 2 [all]: group:dba-team
```

Context fields:
- **Risk** — Auto-assessed risk level + factors (ReadOnly, LargeTable, CascadeDelete, MultiStatement, etc.)
- **SQL Review** — Rule-based check results (passed / N warnings)
- **Tables** — Affected tables extracted from SQL
- **Explain** — EXPLAIN plan tree (PostgreSQL and MySQL supported)

#### dbward request approve

```bash
dbward request approve <ID>
dbward request approve <ID> --comment "LGTM"
```

| Option | Description |
|--------|-------------|
| `--comment <TEXT>` | Approval comment |

#### dbward request reject

```bash
dbward request reject <ID> --reason "Needs review"
```

| Option | Description |
|--------|-------------|
| `--reason <TEXT>` | Rejection reason (alias: `--comment`) |

#### dbward request cancel

```bash
dbward request cancel <ID>
dbward request cancel <ID> --reason "No longer needed"
```

#### dbward request resume

Wait for a pending/running request to complete.

```bash
dbward request resume <ID>
dbward request resume <ID> --no-save
```

| Option | Description |
|--------|-------------|
| `--no-save` | Do not save result locally |

---

### dbward result

Manage execution results.

#### dbward result list

```bash
dbward result list
```

#### dbward result get

```bash
dbward result get <ID>
```

---

### dbward migrate

Run database migrations.

#### dbward migrate up

```bash
dbward migrate up
dbward migrate up --count 3
dbward migrate up --share-with "group:backend-team"
```

| Option | Description |
|--------|-------------|
| `--count <N>` | Apply at most N migrations |
| `--share-with <SELECTOR>` | Share result |
| `--ticket <ID>` | Ticket metadata |
| `--repo <NAME>` | Repository metadata |
| `--idempotency-key <KEY>` | Deduplication key |

#### dbward migrate down

```bash
dbward migrate down --count 1
```

| Option | Description |
|--------|-------------|
| `--count <N>` | Revert N migrations (required) |
| `--ticket <ID>` | Ticket metadata |
| `--repo <NAME>` | Repository metadata |
| `--idempotency-key <KEY>` | Deduplication key |

#### dbward migrate status

```bash
dbward migrate status
```

#### dbward migrate create

```bash
dbward migrate create "add_email_index"
```

---

### dbward audit

Search and verify audit logs.

```bash
dbward audit
dbward audit --output json
dbward audit --verify
```

| Option | Description |
|--------|-------------|
| `--output <FORMAT>` | Output format: table (default), json, csv |
| `--verify` | Verify hash chain integrity |

---

### dbward databases

List registered databases.

```bash
dbward databases
```

---

### dbward agents

Show agent status (admin only).

```bash
dbward agents
```

---

### dbward doctor

Diagnose configuration and connectivity issues. Three modes:

```bash
dbward doctor                              # Check CLI config + server connectivity
dbward doctor --agent dbward-agent.toml    # Validate agent config
dbward doctor --server dbward-server.toml  # Validate server config
```

| Option | Description |
|--------|-------------|
| `--agent <PATH>` | Validate agent config file instead of CLI config |
| `--server <PATH>` | Validate server config file instead of CLI config |
| `--timeout <SECS>` | Network timeout per check (default: 5) |
| `--format json` | Machine-readable JSON output (global flag) |

**Exit codes:**
- `0` — all checks passed (warnings are OK)
- `1` — one or more checks failed
- `2` — cannot start (flag conflict)

**CLI mode checks:** config parse, env vars, server reachable, version info, auth configured, auth valid, databases exist, workflows exist.

**Agent mode checks:** env var audit (detects silent empty expansion), config parse + validate, server reachable, agent token type validation (via `/api/public-key`), DB URL scheme.

**Server mode checks:** env vars, config parse + validate (mirrors server startup: approval_ttl, execution_policy timeout, auto_approve duplicates, workflow operation overlap), workflow validity (db + env), workflow coverage (reverse: registered DB×env with no workflow), role resolution, auto_approve consistency.

Example output:

```
$ dbward doctor
dbward doctor — CLI configuration

  ✓ config_parse             dbward.toml
  ✓ env_vars                 all resolved
  ✓ server_reachable         http://localhost:3000 (v0.1.3)
  ✓ version_info             CLI v0.1.3, Server v0.1.3
  ✓ auth_configured          token
  ✓ auth_valid               admin (admin)
  ✓ databases_exist          2 registered
  ✓ workflows_exist          3 defined

  8 passed, 0 warnings, 0 failed, 0 skipped
```

---

### dbward policy resolve

Show the effective policy for a database/environment. Reveals which workflow matches, auto-approve configuration, execution policy, and predicted decision for each operation.

```bash
dbward policy resolve <database> <environment>                # All operations
dbward policy resolve <database> <environment> --operation execute_dml  # Single operation
```

| Option | Description |
|--------|-------------|
| `--operation <OP>` | Resolve for a specific operation only |
| `--format json` | Machine-readable JSON output (global flag) |

**Decision preview values:**
- `auto_approved` — request would be auto-approved (read-only + allow_read_only, or empty workflow steps)
- `needs_approval` — request would need human approval (risk unknown without SQL)
- `deny` — request would be rejected (no workflow or DB not registered)

---

### dbward agent

Start the dbward agent process.

```bash
dbward agent --config dbward-agent.toml
```

| Option | Description |
|--------|-------------|
| `--config <PATH>` | Agent config file (default: `dbward-agent.toml`) |

---

### dbward login / logout / whoami

OIDC authentication.

```bash
dbward login              # Browser-based login
dbward login --device     # Device flow (headless)
dbward logout
dbward whoami
```

---

### dbward dev

Start local development server + agent.

```bash
dbward dev --database-url "postgres://localhost/myapp"
```

---

### dbward server

Start the dbward HTTP server (production).

```bash
dbward server start --config server.toml --data /data/dbward.db --listen 0.0.0.0:3000
```

#### dbward server token create

```bash
dbward server token create --user alice --role admin --data /data/dbward.db
dbward server token create --user agent-1 --role agent-default --agent --data /data/dbward.db
dbward server token create --user bob --role developer --groups "backend,dba" --data /data/dbward.db
```

| Option | Description |
|--------|-------------|
| `--user <NAME>` | Token subject |
| `--role <ROLE>` | Role to assign |
| `--agent` | Create agent token |
| `--groups <LIST>` | Comma-separated groups |
| `--data <PATH>` | SQLite database path |

---

### dbward self-update

Update dbward to the latest version.

```bash
dbward self-update
```

---

### dbward mcp

Start MCP stdio server (for AI agent integration).

```bash
dbward mcp
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error |
| 2 | Request pending (awaiting approval) |
