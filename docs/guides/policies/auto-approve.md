---
title: Auto-Approve
description: Automatically approve low-risk queries without human intervention
---

# Auto-Approve

Auto-approve lets safe queries bypass the approval step while still recording them in the audit log. It uses risk scoring to determine what qualifies as "safe."

## How it works

```
Request arrives
    │
    ▼
Workflow matched → has steps?
    │                   │
    No                  Yes
    ▼                   ▼
AutoApproved       Check auto_approve config
                        │
                   Risk ≤ threshold?
                   ┌────┼────┐
                   Yes       No
                   ▼         ▼
              AutoApproved   Pending (needs human)
```

## Configuration

```toml
[[auto_approve]]
database = "*"
environment = "staging"
risk = "low"                 # Maximum risk level to auto-approve
allow_read_only = true       # SELECT always counts as Low
allow_safe_ddl = true        # CREATE TABLE/INDEX counts as Low
max_estimated_rows = 1000    # Row threshold for large-table risk
```

## Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `database` | String | `"*"` | Database scope |
| `environment` | String | `"*"` | Environment scope |
| `risk` | String | `"none"` | Max risk to auto-approve: `low`, `medium`, `high`, or `none` (disabled) |
| `allow_read_only` | Boolean | `true` | If true, SELECT is always Low risk |
| `allow_safe_ddl` | Boolean | `true` | If true, CREATE TABLE/VIEW/INDEX is always Low risk |
| `max_estimated_rows` | Integer | `1000` | Tables above this row count trigger higher risk |

## Risk levels

| Level | Meaning |
|-------|---------|
| **Low** | Safe operation (SELECT, safe DDL, small tables) |
| **Medium** | Moderate concern (1 warning, large table without cascade) |
| **High** | Significant risk (DROP/TRUNCATE, multi-DML, cascade FK + large table, ≥3 warnings) |
| **Critical** | Reserved for future use |
| **Unknown** | Schema not synced — cannot assess risk |
| **Unavailable** | Parse failure — cannot classify |

**Important:** `Unknown` and `Unavailable` are never auto-approved regardless of the `risk` threshold.

## Risk factors

| Factor | Triggers | Result |
|--------|----------|--------|
| Read-only | SELECT + `allow_read_only = true` | Low |
| Safe DDL | CREATE TABLE/VIEW/INDEX + `allow_safe_ddl = true` | Low |
| Schema not synced | Agent hasn't synced schema yet | Unknown |
| Multi-statement DML | >1 DML statements in one request | High |
| DROP / TRUNCATE | Destructive operations detected | High |
| ≥3 SQL review warnings | Multiple issues found | High |
| Cascade FK + large table | FK with CASCADE on table > max_estimated_rows | High |
| Cascade FK + small table | FK with CASCADE on table ≤ max_estimated_rows | Medium |
| Large table | Table > max_estimated_rows (without cascade) | Medium |
| 1-2 SQL review warnings | Minor issues found | Medium |

## Examples

### Auto-approve all reads on staging

```toml
[[auto_approve]]
environment = "staging"
risk = "low"
allow_read_only = true
```

Result: All SELECT queries on staging auto-approve. DML still needs human approval.

### Auto-approve reads + small writes on development

```toml
[[auto_approve]]
environment = "development"
risk = "high"
```

Result: Everything except DROP/TRUNCATE/multi-DML auto-approves on development.

### Disable auto-approve on production

```toml
# Simply don't add an [[auto_approve]] entry for production.
# Or explicitly:
[[auto_approve]]
environment = "production"
risk = "none"
```

## Debugging

Use `dbward policy resolve` to see why a query was or wasn't auto-approved:

```bash
dbward policy resolve --database app --environment production \
  --sql "DELETE FROM sessions WHERE expired_at < now()"
```

The MCP tool `dbward_explain_policy_failure` provides the same information for AI assistants.

## See also

- [Workflows](workflows.md) — approval requirements
- [SQL Safety](../../reference/sql-safety.md) — classification and review rules
- [Policies Overview](overview.md) — how all policies interact
