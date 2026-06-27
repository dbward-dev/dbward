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
Workflow matched
    │
    ▼
Has [workflows.auto_approve]?
    │              │
    No             Yes
    ▼              ▼
Pending       mode = "always"?
(needs human)  ┌────┼────┐
               Yes       No (risk_based)
               ▼         ▼
          AutoApproved  Risk ≤ threshold?
                        ┌────┼────┐
                        Yes       No
                        ▼         ▼
                   AutoApproved   Pending
```

## Configuration

Auto-approve is configured as a sub-table within each workflow:

```toml
[[workflows]]
database = "*"
environment = "staging"

[workflows.auto_approve]
mode = "risk_based"          # "always" or "risk_based"
risk = "low"                 # Maximum risk level (risk_based only)
allow_read_only = true       # SELECT always counts as Low
allow_safe_ddl = true        # CREATE TABLE/INDEX counts as Low
max_estimated_rows = 1000    # Row threshold for large-table risk
```

## Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `mode` | String | Yes | — | `"always"` (unconditional) or `"risk_based"` (conditional) |
| `risk` | String | risk_based only | — | Max risk: `low`, `medium`, or `high` |
| `allow_read_only` | Boolean | No | `true` | If true, SELECT is always Low risk |
| `allow_safe_ddl` | Boolean | No | `true` | If true, CREATE TABLE/VIEW/INDEX is always Low risk |
| `max_estimated_rows` | Integer | No | `1000` | Tables above this row count trigger higher risk |

## Modes

### `mode = "always"`

All requests matching this workflow are auto-approved unconditionally. No steps are needed.

```toml
[[workflows]]
database = "*"
environment = "development"

[workflows.auto_approve]
mode = "always"
```

### `mode = "risk_based"`

Requests are auto-approved only if the assessed risk level is at or below the threshold. If risk exceeds the threshold, the request falls through to approval steps.

```toml
[[workflows]]
database = "*"
environment = "staging"

[workflows.auto_approve]
mode = "risk_based"
risk = "low"

[[workflows.steps]]
type = "approval"

[[workflows.steps.approvers]]
role = "dba"
min = 1
```

> **Important:** `risk_based` mode requires `[[workflows.steps]]` — without steps, there's no fallback when risk exceeds the threshold.

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

### Auto-approve everything on development

```toml
[[workflows]]
database = "*"
environment = "development"

[workflows.auto_approve]
mode = "always"
```

### Auto-approve reads + safe operations on staging

```toml
[[workflows]]
database = "*"
environment = "staging"

[workflows.auto_approve]
mode = "risk_based"
risk = "low"
allow_read_only = true

[[workflows.steps]]
type = "approval"

[[workflows.steps.approvers]]
role = "team-lead"
min = 1
```

### No auto-approve on production

Simply omit `[workflows.auto_approve]` from the production workflow:

```toml
[[workflows]]
database = "*"
environment = "production"
require_reason = true

[[workflows.steps]]
type = "approval"

[[workflows.steps.approvers]]
role = "dba"
min = 1
```

## Debugging

Use `dbward policy resolve` to see why a query was or wasn't auto-approved:

```bash
dbward policy resolve --database app --environment staging
```

## See also

- [Workflows](workflows.md) — approval requirements
- [SQL Safety](../../reference/sql-safety.md) — classification and review rules
- [Policies Overview](overview.md) — how all policies interact
