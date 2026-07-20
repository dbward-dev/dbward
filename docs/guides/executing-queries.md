---
title: Executing Queries
description: Submit SQL queries through dbward's approval workflow
---

# Executing Queries

This guide covers how to execute SQL through dbward — from submission to result retrieval.

## How it works

```
You run:         dbward execute "SELECT * FROM users"
                         │
                         ▼
Server:          Classify SQL → Match workflow → Check auto-approve
                         │
              ┌──────────┼──────────┐
              ▼                     ▼
         Auto-approved         Needs approval
              │                     │
              ▼                     ▼ (wait for approve)
Agent:   Execute on DB         Execute on DB
              │                     │
              ▼                     ▼
CLI:     Display result        Display result
```

## Basic usage

```bash
# Simple query
dbward execute "SELECT * FROM users LIMIT 10"

# With explicit database and environment
dbward execute -e production --database app "SELECT count(*) FROM orders"
```

The CLI submits the query, waits for approval (if required), and displays the result.

## Dev mode vs production

| | Dev mode (`dbward dev`) | Production |
|---|---|---|
| Approval | All queries auto-execute | Determined by [workflow](policies/workflows.md) |
| Agent | Built-in (same process) | Separate process on DB network |
| Use case | Local development, testing | Team environments |

## Output formats

### Result display format (`--result-format`)

Controls how query results are rendered in human mode:

```bash
# Table (default)
dbward execute "SELECT id, name FROM users"

# Vertical (one row per block, useful for wide results)
dbward execute --result-format vertical "SELECT * FROM users WHERE id = 1"

# JSON (raw result data)
dbward execute --result-format json "SELECT id, name FROM users"

# CSV (for spreadsheets/scripts)
dbward execute --result-format csv "SELECT id, name FROM users"

# Save to file
dbward execute --output results.csv --result-format csv "SELECT * FROM users"
```

### Machine-readable output (`--format json`)

For scripting and CI/CD, use `--format json` to get a structured JSON envelope on stdout:

```bash
dbward --format json -y execute "SELECT version()"
```

```json
{"ok": true, "data": {"_dbward_result": true, "success": true, "execution_id": "...", "result_data": {"rows": [{"version": "PostgreSQL 16.2"}], "truncated": false}}}
```

When `--format json` is active, `--result-format` is silently ignored — the full result data is always in the JSON envelope's `data` field.

See [CLI Reference: Output Modes](../reference/cli.md#output-modes) for full details on the JSON envelope structure and exit codes.

## Approval flow

When a query requires approval:

1. CLI submits the request and prints the request ID
2. CLI polls the server, waiting for approval
3. An authorized user approves (via CLI, API, Slack, or MCP)
4. Agent executes the query
5. CLI displays the result

```bash
# Approve from another terminal
dbward request approve <request-id>

# Approve with comment
dbward request approve <request-id> --comment "Verified the query is safe"
```

## Options reference

| Flag | Description |
|------|-------------|
| `--emergency` | Break-glass bypass (requires `--reason`) |
| `--allow-ddl` | Allow DDL statements in emergency mode (requires `--emergency`) |
| `--reason <text>` | Reason for the request (required for emergency) |
| `--output <path>` | Save result to a file |
| `--no-save` | Do not save result locally |
| `--no-result-store` | Do not store query result on server (metadata and SQL always retained for audit) |
| `--result-format <fmt>` | Output format: `table`, `json`, `csv`, `vertical` (default: table) |
| `--timeout <secs>` | Maximum wait time in seconds |
| `--ticket <id>` | Attach ticket metadata (e.g., JIRA-123) |
| `--repo <url>` | Attach repository metadata |
| `--idempotency-key <key>` | Deduplicate identical submissions |
| `--share-with <selector>` | Share result with principals (e.g., `group:backend-team`) |

## Idempotency

Use `--idempotency-key` to safely retry requests in scripts and CI:

```bash
dbward execute --idempotency-key "deploy-v1.2.3-check" "SELECT version FROM schema_info"
```

If a request with the same key already exists, dbward returns the existing result instead of creating a duplicate.

## Result sharing

Share query results with team members without re-executing:

```bash
dbward execute --share-with "group:backend-team" "SELECT * FROM metrics"
```

Recipients can retrieve shared results with:

```bash
dbward result list
dbward result get <result-id>
```

## MCP (AI integration)

When using dbward through an AI assistant (via MCP), the same approval flow applies:

1. AI calls `dbward_execute_query` tool
2. If approval is needed, the AI informs you and waits
3. You approve via CLI, Slack, or API
4. AI receives and presents the result

See [MCP Integration](mcp-integration.md) for setup instructions.

## Slack

Submit SQL directly from Slack using the `/dbward execute` slash command:

1. Type `/dbward execute` in any channel
2. Fill in Database/Environment, SQL, and optional Reason
3. Submit — the request enters the approval flow

See [Slack Integration: Slash Commands](slack.md#slash-commands) for setup instructions.

## See also

- [Policies Overview](policies/overview.md) — understand when approval is required
- [Auto-Approve](policies/auto-approve.md) — configure automatic approval for safe queries
- [CI/CD Integration](ci-cd.md) — use dbward in automated pipelines
