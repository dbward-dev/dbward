---
title: Workflows
description: Design approval workflows for your team
---

# Workflows

Workflows define who must approve a database operation before it executes. Configure them in `dbward-server.toml`.

## Basic concepts

- **No workflow match = request rejected (fail-closed)**
- **Workflow with steps = approval required** (one or more people must approve)
- **`[workflows.auto_approve] mode = "always"`** = unconditional auto-approve (executes immediately)
- Workflows are scoped by **database × environment × operation**
- Auto-approve thresholds are configured as `[workflows.auto_approve]` sub-table within each workflow

## Quick examples

### Require one admin approval for production

```toml
[[workflows]]
database = "*"
environment = "production"

[[workflows.steps]]
type = "approval"
[[workflows.steps.approvers]]
role = "admin"
min = 1
```

### Auto-approve development

```toml
[[workflows]]
database = "*"
environment = "development"

[workflows.auto_approve]
mode = "always"
```

### Risk-based auto-approve for staging

```toml
[[workflows]]
database = "*"
environment = "staging"

[workflows.auto_approve]
mode = "risk_based"
risk = "low"

[[workflows.steps]]
type = "approval"
mode = "any"
[[workflows.steps.approvers]]
role = "team-lead"
min = 1
[[workflows.steps.approvers]]
role = "dba"
min = 1
```

With this config:
- Low-risk SELECT → auto-approved
- Safe DDL (CREATE TABLE) → auto-approved (Low risk)
- Large table UPDATE → requires human approval (Medium/High risk)

---

## Auto-Approve

Auto-approve evaluates the risk level of each request and skips human approval if the risk is at or below the configured threshold. It is configured as a sub-table within each workflow.

### Configuration

```toml
[workflows.auto_approve]
mode = "risk_based"        # "always" or "risk_based"
risk = "low"               # Threshold (risk_based only): "low" | "medium" | "high"
allow_read_only = true     # SELECT → Low risk
allow_safe_ddl = true      # CREATE TABLE/INDEX/VIEW → Low risk
max_estimated_rows = 1000  # Tables above this increase risk
```

### How it works

1. A request matches a workflow
2. dbward checks the workflow's `[workflows.auto_approve]` sub-table
3. `mode = "always"` → auto-approved unconditionally
4. `mode = "risk_based"` + risk ≤ threshold → auto-approved
5. Otherwise → falls through to `[[workflows.steps]]` for human approval

**Important rules:**
- No `[workflows.auto_approve]` → always require human approval
- `mode = "risk_based"` requires `[[workflows.steps]]` as fallback
- Risk level `Unknown` or `Unavailable` → never auto-approved

### Risk levels

| Level | Triggers |
|-------|----------|
| Low | SELECT (with `allow_read_only`), safe DDL (with `allow_safe_ddl`), simple DML with no warnings |
| Medium | 1-2 SQL review warnings (e.g. `CREATE INDEX` without `CONCURRENTLY`), CASCADE FK on small table |
| High | CASCADE FK on large table, multi-statement DML, ≥3 warnings, DROP/TRUNCATE |
| Critical | (reserved for future use) |
| Unknown | Schema not synced yet — **never auto-approved regardless of threshold** |

### What counts as "safe DDL"

When `allow_safe_ddl = true`, these DDL statements are classified as Low risk:

| Statement | Condition |
|-----------|-----------|
| `CREATE TABLE` | Not `CREATE TABLE ... AS SELECT` or `OR REPLACE` |
| `CREATE VIEW` | Not `OR REPLACE` |
| `CREATE INDEX CONCURRENTLY` | PostgreSQL only, `CONCURRENTLY` keyword present |
| `ALTER TABLE ADD COLUMN` | PostgreSQL only, all operations are `ADD COLUMN` |

`CREATE INDEX` (without `CONCURRENTLY`) is **not** safe DDL — it produces a `create_index_not_concurrently` warning and raises risk to Medium.

### What counts as "read only"

When `allow_read_only = true`, plain `SELECT` queries are classified as Low risk. `SET` prelude + `SELECT` also counts. However, writable CTEs (`INSERT/UPDATE/DELETE ... RETURNING` inside WITH), `SELECT ... INTO`, and queries using dangerous functions are classified as DML, not read-only.

### The `max_estimated_rows` field

This is used during risk scoring for DML statements:
- If any referenced table's `estimated_rows` exceeds this value → risk increases
- Combined with FK CASCADE detection → High risk
- Default: 1000 rows

**Requires schema sync**: The agent must have collected schema information for the target database. Without schema sync, risk = Unknown (never auto-approved).

### Decision flow diagram

```
Request created
  │
  ├─ mode = "always"? ──→ Auto-approved
  │
  ├─ No auto_approve entry? ──→ Needs approval
  │
  ├─ risk = "none"? ──────────→ Needs approval
  │
  ├─ Risk = Unknown? ─────────→ Needs approval
  │
  └─ Risk ≤ threshold? ───────→ Auto-approved (risk-based)
       │
       └─ Risk > threshold ────→ Needs approval
```

### Example: different thresholds per environment

```toml
# Global default: only Low is auto-approved
[workflows.auto_approve]
database = "*"
environment = "*"
risk = "low"

# Staging: auto-approve up to Medium
[workflows.auto_approve]
database = "*"
environment = "staging"
risk = "medium"

# Production: no auto-approve
[workflows.auto_approve]
database = "*"
environment = "production"
risk = "none"
```

---

## Multi-step approval

Steps execute in order. Step 2 only becomes active after step 1 is satisfied.

```toml
[[workflows]]
database = "primary"
environment = "production"
operations = ["execute_select", "execute_dml"]

# Step 1: Team lead review
[[workflows.steps]]
type = "approval"
[[workflows.steps.approvers]]
role = "team-lead"
min = 1

# Step 2: DBA approval
[[workflows.steps]]
type = "approval"
[[workflows.steps.approvers]]
group = "dba-team"
min = 1
```

Flow:
```
Developer submits → Team lead approves (step 1) → DBA approves (step 2) → Executes
```

## Multiple approvers per step

### All groups must be satisfied (`mode = "all"`, default)

```toml
[[workflows.steps]]
type = "approval"
mode = "all"
[[workflows.steps.approvers]]
role = "team-lead"
min = 1
[[workflows.steps.approvers]]
group = "dba-team"
min = 1
```

Requires **both** a team-lead AND a dba-team member to approve.

### Any group is sufficient (`mode = "any"`)

```toml
[[workflows.steps]]
type = "approval"
mode = "any"
[[workflows.steps.approvers]]
role = "team-lead"
min = 1
[[workflows.steps.approvers]]
group = "dba-team"
min = 1
```

Requires **either** a team-lead OR a dba-team member to approve.

---

## Workflow options

```toml
[[workflows]]
database = "primary"
environment = "production"
operations = ["execute_select", "execute_dml"]  # Filter by operation (omitted = all)
require_reason = true                # Force users to provide --reason (default: false)
allow_self_approve = false           # Requester cannot approve own request (default: false)
allow_same_approver_across_steps = false  # Same person can't approve in multiple steps (default: true)
pending_ttl_secs = 3600             # Pending request expires after this duration (default: none)
approval_ttl_secs = 600             # Approved request must execute within this duration (default: none)
explain = true                      # Run EXPLAIN before approval for preview context (default: false)
```

### `operations` filter

| Value | Matches |
|-------|---------|
| omitted | All operations |
| `["execute_select"]` | SELECT queries only |
| `["execute_dml"]` | DML (INSERT/UPDATE/DELETE) only |
| `["migrate_up", "migrate_down"]` | Migrations only |

---

## Context information

When a request is pending, dbward automatically collects context to help approvers make informed decisions:

```
$ dbward request show req_a1b2
Request req_a1b2
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

Context includes:
- **Risk level** — automatically assessed from SQL structure and schema
- **SQL Review** — rule-based checks (DELETE without WHERE, etc.)
- **Tables** — affected tables extracted from SQL
- **EXPLAIN** — execution plan from a dry-run (read-only, no side effects)

This context is available to both the requester and approvers.

---

## Break-glass (emergency bypass)

For urgent situations, users can bypass the approval workflow:

```bash
dbward execute --emergency --reason "incident #1234" \
  "UPDATE pg_settings SET setting = '200' WHERE name = 'max_connections'"
```

Break-glass:
- Skips all approval steps
- Executes immediately
- Is **fully audited** (who, what, when, reason)
- Triggers a webhook notification (`break_glass` event)

---

## Matching rules

When a request comes in, dbward finds the most specific matching workflow:

**Priority (most specific wins):**

1. Exact database + exact environment + specific operations
2. Exact database + exact environment + catchall operations
3. Wildcard database + exact environment
4. Exact database + wildcard environment
5. Wildcard database + wildcard environment

**No match = rejected (fail-closed).**

---

## Tips

- **Start simple:** One workflow rule for production, auto-approve for development.
- **Use `[workflows.auto_approve]` for risk-based automation:** Don't manually approve every low-risk SELECT.
- **Use groups over roles:** Groups come from your IdP and don't require dbward-specific configuration.
- **Require reason for production:** `require_reason = true` creates better audit trails.
- **Monitor with webhooks:** Get Slack notifications so approvers don't miss requests.

## See also

- [Configuration Reference](../../reference/configuration.md) — All workflow, auto_approve, and execution_policies options
- [Authentication](../authentication.md) — Set up groups and role mappings
- [CLI Reference](../../reference/cli.md) — Request and approval commands

## Related: Execution Policies

After a request is approved, **execution policies** control how it runs:
- `statement_timeout_secs` — SQL statement timeout
- `max_executions` — How many times a request can be re-executed
- `max_rows` — Maximum rows returned

Configure in `[[execution_policies]]` in `dbward-server.toml`. See [Execution Policies](execution-policies.md).
