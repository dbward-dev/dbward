---
title: Execution Policies
description: Control timeouts, row limits, and retry behavior for database operations
---

# Execution Policies

Execution policies set constraints on how operations run. They limit resource usage and prevent runaway queries.

## Configuration

```toml
[[execution_policies]]
database = "app"
environment = "production"
statement_timeout_secs = 30
max_rows = 10000
max_executions = 3
execution_window_secs = 3600
retry_on_failure = false
```

## Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `database` | String | `"*"` | Database scope (or `*` for all) |
| `environment` | String | `"*"` | Environment scope (or `*` for all) |
| `statement_timeout_secs` | Integer | — | Maximum seconds a statement can run (applies to migrations too) |
| `max_statement_timeout_secs` | Integer | — | Upper bound for user-requested timeouts |
| `max_rows` | Integer | — | Maximum rows returned by a query |
| `max_executions` | Integer | — | Maximum times a request can be executed |
| `execution_window_secs` | Integer | — | Time window (seconds) for `max_executions` |
| `retry_on_failure` | Boolean | — | Allow agent to retry on transient failure |
| `migration_lease_duration_secs` | Integer | — | Override lease duration for migration operations |

Fields left unset have no limit applied.

## Scoping

Execution policies follow the same [scoping rules](overview.md#scoping-model) as workflows. You can set global defaults and override per-database or per-environment:

```toml
# Global: 30s timeout, 10k row limit
[[execution_policies]]
database = "*"
environment = "*"
statement_timeout_secs = 30
max_rows = 10000

# Production: stricter
[[execution_policies]]
database = "*"
environment = "production"
statement_timeout_secs = 10
max_rows = 1000
max_executions = 1
```

## Rate limiting

Use `max_executions` + `execution_window_secs` to prevent repeated execution of the same request:

```toml
[[execution_policies]]
database = "*"
environment = "production"
max_executions = 3
execution_window_secs = 3600  # 3 executions per hour
```

## Interaction with agent config

The agent also has a `statement_timeout_secs` setting. The effective timeout is:

```
min(execution_policy.statement_timeout_secs, agent.statement_timeout_secs)
```

If neither is set, the database's own statement timeout applies.

## See also

- [Policies Overview](overview.md)
- [Workflows](workflows.md) — who approves operations
- [Configuration Reference](../../reference/configuration.md#execution_policies) — full field reference
