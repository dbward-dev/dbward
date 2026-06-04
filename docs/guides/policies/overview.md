---
title: Policies Overview
description: How dbward's four policy types control database operations
---

# Policies Overview

dbward uses four policy types to control what happens when a database operation is requested. Each policy type answers a different question.

## The four policies

| Policy | Question it answers | Configured in |
|--------|--------------------|----|
| [Workflow](workflows.md) | Who must approve this operation? | `[[workflows]]` |
| [Execution Policy](execution-policies.md) | What constraints apply during execution? | `[[execution_policies]]` |
| [Result Policy](result-policies.md) | How long are results kept and who can access them? | `[[result_policies]]` |
| [Notification Policy](notification-policies.md) | Which webhooks fire for which events? | `[[notification_policies]]` |

## Scoping model

All policies are scoped by **database × environment × operation**:

```toml
[[workflows]]
database = "app"              # or "*" for all databases
environment = "production"    # or "*" for all environments
operations = ["execute_dml"]  # optional filter
```

When multiple policies could match a request, dbward uses this priority:

1. Exact database + exact environment
2. Wildcard database + exact environment
3. Exact database + wildcard environment
4. Wildcard database + wildcard environment

Within the same specificity, policies with `operations` filter take priority over those without.

## Fail-closed principle

**If no workflow matches a request, it is rejected.**

This means every (database, environment) pair that should accept operations must have at least one matching workflow — even if that workflow auto-approves everything.

```toml
# Allow all operations on development (no approval needed)
[[workflows]]
database = "*"
environment = "development"
# steps = [] means auto-approve
```

## Operations

The five operation types that policies can filter on:

| Operation | Triggered by |
|-----------|-------------|
| `execute_select` | SELECT, SHOW, EXPLAIN queries |
| `execute_dml` | INSERT, UPDATE, DELETE, DDL |
| `migrate_up` | `dbward migrate up` |
| `migrate_down` | `dbward migrate down` |
| `migrate_status` | `dbward migrate status` |

## How policies interact

When a request arrives:

```
1. SQL classification  →  Determine operation type (execute_select / execute_dml)
2. Workflow matching   →  Find approval requirements
3. Auto-approve check  →  Skip approval if risk is low enough
4. Execution policy    →  Apply timeout, row limit, retry constraints
5. Result policy       →  Determine retention and access rules
6. Notification policy →  Fire webhooks for relevant events
```

## Next steps

- [Workflows](workflows.md) — configure approval requirements
- [Auto-Approve](auto-approve.md) — skip approval for safe queries
- [Execution Policies](execution-policies.md) — set timeouts and limits
- [Result Policies](result-policies.md) — control result retention
- [Notification Policies](notification-policies.md) — configure event notifications
