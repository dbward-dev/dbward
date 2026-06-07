---
title: Configuration Reference
description: Complete field reference for dbward server, agent, and CLI configuration files.
---

# Configuration Reference

## Overview

dbward uses TOML configuration files for its three binaries:

| Binary | Config file | Purpose |
|---|---|---|
| `dbward-server` | `dbward-server.toml` (via `--config`) | Approval engine, policies, audit |
| `dbward-agent` | `dbward-agent.toml` (via `--config`) | Database execution, polling |
| `dbward` (CLI) | `~/.config/dbward/config.toml` + `./dbward.toml` | Server connection, project defaults |

All files support [variable expansion](#variable-expansion) for secrets and environment-specific values.

---

## Server Configuration

### Minimal Example

```toml
state_dir = "./data"

[[databases]]
name = "app"
environments = ["production"]
```

### Top-level

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `state_dir` | String | ✓ | — | Directory for SQLite state and keys. Created on first start. |
| `trusted_proxies` | String[] | | `[]` | CIDR ranges trusted for `X-Forwarded-For`. See [trusted_proxies](#trusted_proxies). |

### [[databases]]

Registers a database that the server will accept requests for.

```toml
[[databases]]
name = "analytics"
environments = ["staging", "production"]
```

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `name` | String | ✓ | — | Logical database identifier. Referenced in workflows and policies. |
| `environments` | String[] | ✓ | — | Environments this database operates in. |

### [auth]

```toml
[auth]
mode = "both"
default_role = "readonly"
```

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `mode` | String | | `"both"` | Authentication mode: `"token"`, `"oidc"`, `"both"`. |
| `default_role` | String | | — | Role assigned when no binding matches. Unset = reject unmatched users. |

### [auth.oidc]

```toml
[auth.oidc]
issuer_url = "https://auth.example.com/realms/dbward"
audience = "dbward"
```

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `issuer_url` | String | ✓ | — | OIDC issuer URL for token validation. Alias: `issuer`. |
| `audience` | String | | `""` | Expected `aud` claim. Empty string disables audience validation. |
| `jwks_uri` | String | | — | Override JWKS endpoint (useful in Docker/internal networks). |
| `client_id` | String | | — | Client ID for PKCE flows. Defaults to `audience` if unset. |
| `default_role` | String | | — | Role for OIDC users when no mapping matches. Falls back to `[auth].default_role`. |

### [[auth.oidc.role_mappings]]

Maps OIDC claims to dbward roles.

```toml
[[auth.oidc.role_mappings]]
claim = "groups"
value = "dba-team"
role = "admin"
```

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `claim` | String | ✓ | — | OIDC token claim name to inspect. |
| `value` | String | ✓ | — | Claim value that triggers the mapping. Exact match. |
| `role` | String | ✓ | — | dbward role to assign when matched. |

### [[auth.role_bindings]]

Binds API token subjects or groups to roles.

```toml
[[auth.role_bindings]]
role = "admin"
subjects = ["alice", "bob"]
```

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `role` | String | ✓ | — | Role to assign. Must be a built-in or custom role. |
| `subjects` | String[] | | `[]` | Token subject identifiers to bind. |
| `groups` | String[] | | `[]` | Group names. All members receive this role. |

### [[auth.roles]] / [[auth.groups]]

Define custom roles and groups in TOML.

```toml
[[auth.roles]]
name = "dba"
permissions = ["request.create", "request.approve", "audit.view"]

[[auth.groups]]
name = "backend-team"
members = ["alice", "bob", "carol"]
```

**[[auth.roles]]**

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `name` | String | ✓ | — | Role identifier. Cannot redefine built-ins: `admin`, `developer`, `readonly`, `agent-default`. |
| `permissions` | String[] | ✓ | — | Granted permissions (e.g. `"request.create"`, `"request.approve"`, `"*"`). [Full list →](authorization.md#permissions) |
| `databases` | String[] | | `[]` | Restrict to specific databases. Empty = all. |
| `environments` | String[] | | `[]` | Restrict to specific environments. Empty = all. |

**[[auth.groups]]**

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `name` | String | ✓ | — | Group identifier. Referenced in role_bindings and workflow approvers. |
| `members` | String[] | ✓ | — | Token subject identifiers belonging to this group. |

### [[workflows]]

Defines approval requirements per database × environment × operation.

```toml
[[workflows]]
database = "app"
environment = "production"
operations = ["execute_dml", "migrate_up"]
require_reason = true

[[workflows.steps]]
mode = "all"

[[workflows.steps.approvers]]
role = "admin"
min = 1
```

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `database` | String | | `"*"` | Scope filter. `"*"` matches all databases. |
| `environment` | String | | `"*"` | Scope filter. `"*"` matches all environments. |
| `operations` | String[] | | `[]` | Operations filter. Empty = all. Values: `execute_select`, `execute_dml`, `migrate_up`, `migrate_down`, `migrate_status`, `migrate_repair`. |
| `steps` | Step[] | | `[]` | Approval steps. Empty = auto-approve. |
| `require_reason` | bool | | `false` | Reject requests without `--reason`. |
| `allow_self_approve` | bool | | `false` | Allow requester to approve own request. |
| `allow_same_approver_across_steps` | bool | | `true` | Allow same person to approve multiple steps. |
| `explain` | bool | | `true` | Auto-run EXPLAIN on request creation. |
| `pending_ttl_secs` | u64 | | — | Request expires if not approved within this window. Falls back to `retention.approval_ttl_secs`. |
| `statement_timeout_secs` | u64 | | — | Override agent's statement timeout. Capped by `execution_policies.max_statement_timeout_secs`. |

### Workflow Steps

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `mode` | String | | `"all"` | `"all"`: every approver entry satisfied. `"any"`: any single entry suffices. |
| `approvers` | Approver[] | ✓ | — | Approver requirements. |

**Approver entry** (use exactly one of `role`, `group`, or `user`):

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `role` | String | | — | Role whose members can approve. |
| `group` | String | | — | Group whose members can approve. |
| `user` | String | | — | Specific user subject. |
| `min` | u32 | | `1` | Minimum approvals needed from this entry. |

### [[auto_approve]]

Risk-based automatic approval.

```toml
[[auto_approve]]
database = "app"
environment = "staging"
risk = "low"
```

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `database` | String | | `"*"` | Scope filter. |
| `environment` | String | | `"*"` | Scope filter. |
| `risk` | String | | `"none"` | Max risk level: `"none"`, `"low"`, `"medium"`, `"high"`. `"none"` = disabled. |
| `allow_read_only` | bool | | `true` | SELECT counts as Low risk. |
| `allow_safe_ddl` | bool | | `true` | CREATE TABLE/INDEX/VIEW counts as Low risk. |
| `max_estimated_rows` | u64 | | `1000` | Threshold for large-table risk increase. |

### [sql_review]

Static SQL analysis rules. Typos in field names cause startup error (`deny_unknown_fields`).

```toml
[sql_review]
no_where_delete = "block"
drop_table = "block"
truncate = "warn"
```

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `no_where_delete` | String | | `"warn"` | DELETE without WHERE. Values: `"block"`, `"warn"`, `"off"`. |
| `no_where_update` | String | | `"warn"` | UPDATE without WHERE. |
| `drop_table` | String | | `"warn"` | DROP TABLE. |
| `drop_column` | String | | `"warn"` | ALTER TABLE DROP COLUMN. |
| `not_null_without_default` | String | | `"warn"` | NOT NULL column without DEFAULT. |
| `create_index_not_concurrently` | String | | `"warn"` | CREATE INDEX without CONCURRENTLY (PostgreSQL). |
| `alter_column_type` | String | | `"warn"` | ALTER COLUMN TYPE. |
| `truncate` | String | | `"warn"` | TRUNCATE. |
| `mixed_ddl_dml` | String | | `"warn"` | DDL and DML in same request. |
| `large_in_list` | String | | `"warn"` | IN clause with excessive values. |

### [[webhooks]]

```toml
[[webhooks]]
url = "https://hooks.slack.com/services/T.../B.../xxx"
format = "slack"
secret = "${WEBHOOK_SECRET}"
```

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `url` | String | ✓ | — | Webhook destination URL. |
| `secret` | String | | — | HMAC-SHA256 key. Sent in `X-Dbward-Signature`. |
| `events` | String[] | | `[]` | Filter events. Empty = all. |
| `format` | String | | `"generic"` | Payload format: `"generic"` (JSON) or `"slack"` (Block Kit). |

### [[execution_policies]]

Rate limiting and timeout per scope.

```toml
[[execution_policies]]
database = "app"
environment = "production"
max_executions = 3
statement_timeout_secs = 60
```

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `database` | String | | `"*"` | Scope filter. |
| `environment` | String | | `"*"` | Scope filter. |
| `max_executions` | u32 | | — | Max executions per window. Unset = no limit. |
| `execution_window_secs` | u64 | | — | Time window for `max_executions`. |
| `retry_on_failure` | bool | | — | Allow re-dispatch on failure. Unset = no retry. |
| `statement_timeout_secs` | u32 | | — | SQL timeout. Unset = use agent default (30s). |
| `max_statement_timeout_secs` | u32 | | — | Cap for workflow-level timeout override. |
| `migration_statement_timeout_secs` | u32 | | — | Statement timeout for migrations. Unset = unlimited (no timeout). |
| `max_rows` | u32 | | — | Max result rows. Unset = no limit. |

### [retention]

```toml
[retention]
request_ttl_days = 90
audit_ttl_days = 365
```

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `request_ttl_days` | u64 | | `90` | Auto-delete completed requests after N days. |
| `audit_ttl_days` | u64 | | `365` | Auto-delete audit events after N days. |
| `result_ttl_days` | u64 | | `30` | Auto-delete stored results after N days. |
| `approval_ttl_secs` | u64 | | `86400` | Approved requests expire if not resumed within this window. |

### [audit]

```toml
[audit]
redaction = "literals"
```

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `redaction` | String | | `"literals"` | SQL redaction: `"literals"` (mask values), `"full"` (hide SQL), `"none"`. |

### [result_storage]

```toml
[result_storage]
backend = "local"
```

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `backend` | String | | `"local"` | Storage backend: `"local"` or `"s3"`. |
| `root_dir` | String | | `"{state_dir}/results"` | Local backend directory. |
| `max_persist_bytes` | usize | | `10485760` | Results above 10 MB are not persisted. |
| `bucket` | String | | — | S3 bucket name. Required when `backend = "s3"`. |
| `region` | String | | — | AWS region for S3. |
| `endpoint` | String | | — | Custom S3 endpoint (MinIO, localstack). |
| `access_key_id` | String | | — | S3 access key. Prefer IAM roles. |
| `secret_access_key` | String | | — | S3 secret key. |
| `path_style` | bool | | `false` | Path-style S3 URLs (set `true` for MinIO). |
| `prefix` | String | | — | Key prefix for S3 objects. |

### [result_channel]

In-memory relay for streaming results.

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `max_slots` | usize | | `10000` | Max concurrent result slots. |
| `slot_ttl_secs` | u64 | | `600` | Slot removed after 10 min if unclaimed. |

### [logging]

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `level` | String | | `"info"` | Log level: `debug`, `info`, `warn`, `error`. |
| `format` | String | | `"text"` | Output format: `"text"` or `"json"`. Overridden by `DBWARD_LOG_FORMAT`. |

### [slack]

Slack integration for notifications and interactive approve/reject.

```toml
[slack]
bot_token = "${SLACK_BOT_TOKEN}"
signing_secret = "${SLACK_SIGNING_SECRET}"
channel = "C02C1EUJ0EN"
```

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `bot_token` | String | ✓ | — | Slack Bot OAuth token (`xoxb-...`). |
| `signing_secret` | String | ✓ | — | Slack signing secret for request verification. |
| `channel` | String | | `"#db-approvals"` | Default channel (ID or name). |
| `channels` | Map | | `{}` | Per-environment override. Key = env, value = channel. |

### trusted_proxies

```toml
trusted_proxies = ["10.0.0.0/8", "172.16.0.0/12"]
```

When empty (default), the direct connection IP is used. Required behind a load balancer for accurate audit log IPs.

---

## Agent Configuration

### Minimal Example

```toml
[server]
url = "http://localhost:3000"
agent_token = "${DBWARD_AGENT_TOKEN}"

[databases.app.production]
url = "${DATABASE_URL}"
```

### Top-level

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `agent_id` | String | | hostname | Unique agent identifier. |
| `poll_interval_ms` | u64 | | `1000` | Milliseconds between poll requests. |
| `max_concurrent_tasks` | u32 | | `2` | Max parallel executions. |
| `drain_timeout_secs` | u64 | | `60` | Graceful shutdown wait. |
| `statement_timeout_secs` | u64 | | `30` | Default SQL timeout. |
| `lease_duration_secs` | u64 | | `300` | Job lease before server reclaims. |
| `operations` | String[] | | all | Operation types to handle. Unset = all. |
| `startup_retry_initial_ms` | u64 | | `1000` | Initial retry backoff. |
| `startup_retry_max_ms` | u64 | | `15000` | Max retry backoff. |
| `startup_max_wait_secs` | u64 | | `60` | Max startup wait. `0` = wait forever. |

### [server]

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `url` | String | ✓ | — | Server URL to poll. |
| `agent_token` | String | ✓ | — | Auth token. Use `${DBWARD_AGENT_TOKEN}` expansion. |

### [databases.\<name\>.\<env\>]

```toml
[databases.app.production]
url = "postgres://user:pass@db:5432/app"
```

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `url` | String | ✓ | — | Database connection URL. Scheme = driver (`postgres://` or `mysql://`). |

### [schema_sync]

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `enabled` | bool | | `true` | Enable schema collection. |
| `sync_on_startup` | bool | | `true` | Collect on agent startup. |
| `interval_secs` | u64 | | `0` | Periodic interval. `0` = startup + after migrations only. |

---

## CLI Configuration

### Resolution Order

1. Environment variables (`DBWARD_SERVER_URL`, `DBWARD_TOKEN`, etc.)
2. `--config` flag (standalone mode — no merging)
3. Project config (`./dbward.toml` or `DBWARD_CONFIG`)
4. Global config (`~/.config/dbward/config.toml`)

### [server] (Global/Project)

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `url` | String | ✓ | — | Server URL. |
| `token` | String | | — | API token. Mutually exclusive with `[server.oidc]`. |

### [server.oidc]

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `issuer` | String | ✓ | — | OIDC issuer URL. |
| `client_id` | String | ✓ | — | OIDC client ID for PKCE. |
| `discovery_url` | String | | — | Override discovery endpoint. |
| `backchannel_url` | String | | — | Override token endpoint. |
| `browser_url` | String | | — | Override authorize URL. |

### Project Config (dbward.toml)

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `default_database` | String | | — | Database when `--database` omitted. |
| `default_environment` | String | | — | Environment when `-e` omitted. |
| `migrations_dir` | Path | | `"./migrations"` | Migration SQL directory. |

### [results]

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `dir` | Path | | `"~/.dbward/results"` | Local directory for saving query results. |
| `format` | String | | `"table"` | Default result format: `table`, `json`, `csv`, `vertical`. |

Per-database override:

```toml
[databases.analytics]
migrations_dir = "migrations/analytics"
```

---

## Environment Variables

| Variable | Description |
|---|---|
| `DBWARD_CONFIG` | Project config path. Enables standalone mode. |
| `DBWARD_SERVER_URL` | Override server URL. |
| `DBWARD_TOKEN` | Override API token. |
| `DBWARD_DATABASE` | Default database. |
| `DBWARD_ENV` | Default environment. |
| `DBWARD_AGENT_TOKEN` | Agent token (referenced via `${DBWARD_AGENT_TOKEN}`). |
| `DBWARD_LOG_FORMAT` | Force `"json"` log output. Overrides `[logging].format`. |

---

## Variable Expansion

All TOML config files support shell-style variable expansion:

| Syntax | Behavior |
|---|---|
| `${VAR}` | Required — startup error if unset. |
| `${VAR:-default}` | Use `default` if unset. |
| `${VAR:-}` | Empty string if unset. |

```toml
[server]
agent_token = "${DBWARD_AGENT_TOKEN}"

[databases.app.production]
url = "${DATABASE_URL:-postgres://localhost:5432/app}"
```
