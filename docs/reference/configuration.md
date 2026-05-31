---
title: Configuration Reference
description: Complete field reference for dbward server, agent, and CLI configuration files.
---

# Configuration Reference

## Overview

dbward uses TOML configuration files for its three binaries:

| Binary | Config file | Purpose |
|---|---|---|
| `dbward-server` | `server.toml` (via `--config`) | Approval engine, policies, audit |
| `dbward-agent` | `agent.toml` (via `--config`) | Database execution, polling |
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

| Field | Type | Default | Description |
|---|---|---|---|
| state_dir* | String | — | Directory for SQLite state and keys. Created on first start. |
| trusted_proxies | String[] | `[]` | CIDR ranges trusted for `X-Forwarded-For`. See [trusted_proxies](#trusted_proxies). |

### [[databases]]

Registers a database that the server will accept requests for.

```toml
[[databases]]
name = "analytics"
environments = ["staging", "production"]
```

| Field | Type | Default | Description |
|---|---|---|---|
| name* | String | — | Logical database identifier. Referenced in workflows and policies. |
| environments* | String[] | — | Environments this database operates in. Requests must match one of these. |

### [auth]

```toml
[auth]
mode = "token"
default_role = "readonly"
```

| Field | Type | Default | Description |
|---|---|---|---|
| mode | String | `"both"` | Authentication mode. Options: `"token"`, `"oidc"`, `"both"`. |
| default_role | String? | — | Role assigned when no role binding matches. If unset, unmatched users are rejected. |

### [auth.oidc]

```toml
[auth.oidc]
issuer_url = "https://auth.example.com/realms/dbward"
audience = "dbward"
```

| Field | Type | Default | Description |
|---|---|---|---|
| issuer_url* | String | — | OIDC issuer URL for token validation. Alias: `issuer`. |
| audience | String | `""` | Expected `aud` claim. Empty string disables audience validation. |
| jwks_uri | String? | — | Override JWKS endpoint. Useful when the issuer URL is not reachable from the server (Docker, internal networks). |
| client_id | String? | — | Client ID for PKCE flows. Defaults to `audience` if unset. |
| default_role | String? | — | Role for OIDC-authenticated users when no role mapping matches. Falls back to `[auth].default_role`. |

### [[auth.oidc.role_mappings]]

Maps OIDC claims to dbward roles.

```toml
[[auth.oidc.role_mappings]]
claim = "groups"
value = "dba-team"
role = "admin"
```

| Field | Type | Default | Description |
|---|---|---|---|
| claim* | String | — | OIDC token claim name to inspect. |
| value* | String | — | Claim value that triggers the mapping. Exact match. |
| role* | String | — | dbward role to assign when matched. |

### [[auth.role_bindings]]

Binds API token subjects or groups to roles.

```toml
[[auth.role_bindings]]
role = "admin"
subjects = ["alice", "bob"]
```

| Field | Type | Default | Description |
|---|---|---|---|
| role* | String | — | Role to assign. Must be a builtin or custom role. |
| subjects | String[] | `[]` | Token subject identifiers to bind. |
| groups | String[] | `[]` | Group names to bind. All members of listed groups receive this role. |

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

| Field | Type | Default | Description |
|---|---|---|---|
| name* | String | — | Role identifier. Cannot redefine builtins: `admin`, `developer`, `readonly`, `agent-default`. |
| permissions* | String[] | — | Granted permissions. Use `"*"` for all. Values: `request.create`, `request.approve`, `request.break_glass`, `audit.view`, etc. |

**[[auth.groups]]**

| Field | Type | Default | Description |
|---|---|---|---|
| name* | String | — | Group identifier. Referenced in role_bindings and workflow approvers. |
| members* | String[] | — | Token subject identifiers belonging to this group. |

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

| Field | Type | Default | Description |
|---|---|---|---|
| database | String | `"*"` | Scope filter. `"*"` matches all databases. |
| environment | String | `"*"` | Scope filter. `"*"` matches all environments. |
| operations | String[] | `[]` | Operations requiring this workflow. Empty = all operations. Options: `execute_select`, `execute_dml`, `migrate_up`, `migrate_down`, `migrate_status`. |
| steps | Step[] | `[]` | Approval steps. Empty = auto-approve (no human approval required). |
| require_reason | bool | `false` | Reject requests submitted without `--reason`. |
| allow_self_approve | bool | `false` | Whether the requester can approve their own request. |
| allow_same_approver_across_steps | bool | `true` | Whether the same person can approve multiple steps. |
| explain | bool | `true` | Run EXPLAIN via agent on request creation. Disable for non-query operations. |
| pending_ttl_secs | u64? | — | Request expires if not approved within this window. Falls back to `retention.approval_ttl_secs`. |
| statement_timeout_secs | u64? | — | Override agent's default statement timeout for this workflow. Capped by `execution_policies.max_statement_timeout_secs`. |

### Workflow Steps

Each entry in `steps[]` defines one approval gate.

```toml
[[workflows.steps]]
mode = "any"

[[workflows.steps.approvers]]
role = "admin"
min = 1

[[workflows.steps.approvers]]
group = "dba-team"
min = 2
```

| Field | Type | Default | Description |
|---|---|---|---|
| mode | String | `"all"` | `"all"`: every approver entry must be satisfied. `"any"`: any single entry suffices. |
| approvers | Approver[] | — | List of approver requirements. Each entry uses exactly one of `role`, `group`, or `user`. |

**Approver entry:**

| Field | Type | Default | Description |
|---|---|---|---|
| role | String? | — | Role whose members can approve. |
| group | String? | — | Group whose members can approve. |
| user | String? | — | Specific user subject. |
| min | u32 | `1` | Minimum approvals needed from this entry. |

Priority when multiple fields are set (avoid this): `role` > `group` > `user`.

### [[auto_approve]]

Risk-based automatic approval. Most specific scope wins: `(db, env)` > `(*, env)` > `(db, *)` > `(*, *)`.

```toml
[[auto_approve]]
database = "app"
environment = "staging"
risk = "low"
```

| Field | Type | Default | Description |
|---|---|---|---|
| database | String | `"*"` | Scope filter. |
| environment | String | `"*"` | Scope filter. |
| risk | String | `"none"` | Maximum risk level for auto-approval. Options: `"none"`, `"low"`, `"medium"`, `"high"`. `"none"` = never auto-approve for this scope. |
| allow_read_only | bool | `true` | Classify SELECT statements as Low risk. |
| allow_safe_ddl | bool | `true` | Classify CREATE TABLE/INDEX/VIEW as Low risk. |
| max_estimated_rows | u64 | `1000` | Tables with estimated rows above this threshold get risk increase. `0` = any rows increase risk. |

### [sql_review]

Static SQL analysis rules applied at request creation. Uses `deny_unknown_fields` — typos in field names cause a startup error.

```toml
[sql_review]
no_where_delete = "block"
drop_table = "block"
truncate = "warn"
```

| Field | Type | Default | Description |
|---|---|---|---|
| no_where_delete | String | `"warn"` | DELETE without WHERE clause. Options: `"block"`, `"warn"`, `"off"`. |
| no_where_update | String | `"warn"` | UPDATE without WHERE clause. |
| drop_table | String | `"warn"` | DROP TABLE statements. |
| drop_column | String | `"warn"` | ALTER TABLE DROP COLUMN. |
| not_null_without_default | String | `"warn"` | Adding NOT NULL column without DEFAULT. |
| create_index_not_concurrently | String | `"warn"` | CREATE INDEX without CONCURRENTLY (PostgreSQL). |
| alter_column_type | String | `"warn"` | ALTER COLUMN TYPE (potential table rewrite). |
| truncate | String | `"warn"` | TRUNCATE statements. |
| mixed_ddl_dml | String | `"warn"` | Mixing DDL and DML in one request. |
| large_in_list | String | `"warn"` | IN clauses with excessive values. |

### [[webhooks]]

```toml
[[webhooks]]
url = "https://hooks.slack.com/services/T.../B.../xxx"
format = "slack"
```

| Field | Type | Default | Description |
|---|---|---|---|
| url* | String | — | Webhook destination URL. |
| secret | String? | — | HMAC-SHA256 signing key. Signature sent in `X-Dbward-Signature` header. |
| events | String[] | `[]` | Filter events. Empty = all events. Options: `request_created`, `request_approved`, `request_rejected`, `execution_completed`, `break_glass`. |
| format | String | `"generic"` | Payload format. `"generic"`: JSON. `"slack"`: Slack Block Kit. |

### [[execution_policies]]

Rate limiting and timeout configuration per scope.

```toml
[[execution_policies]]
database = "app"
environment = "production"
max_executions = 3
statement_timeout_secs = 60
```

| Field | Type | Default | Description |
|---|---|---|---|
| database | String | `"*"` | Scope filter. |
| environment | String | `"*"` | Scope filter. |
| max_executions | u32 | `1` | Maximum times the same request can be executed within the window. |
| execution_window_secs | u64 | `86400` | Time window (seconds) for counting executions. |
| retry_on_failure | bool | `false` | Allow re-dispatch after execution failure. |
| statement_timeout_secs | u32 | `30` | SQL statement timeout in seconds. Applied by agent. |
| max_statement_timeout_secs | u32 | `600` | Upper cap for workflow-level `statement_timeout_secs` override. |
| max_rows | u32? | — | Maximum result row count. Unset = no limit. |

### [retention]

```toml
[retention]
request_ttl_days = 90
audit_ttl_days = 365
```

| Field | Type | Default | Description |
|---|---|---|---|
| request_ttl_days | u64 | `90` | Auto-delete completed requests after this many days. |
| audit_ttl_days | u64 | `365` | Auto-delete audit events after this many days. |
| result_ttl_days | u64 | `30` | Auto-delete stored results after this many days. |
| approval_ttl_secs | u64 | `86400` | Approved requests must be resumed within this window or they expire. |

### [audit]

```toml
[audit]
redaction = "literals"
```

| Field | Type | Default | Description |
|---|---|---|---|
| redaction | String | `"literals"` | SQL redaction in webhooks and audit responses. `"literals"`: mask values. `"full"`: hide entire SQL. `"none"`: no redaction. |

### [result_storage]

```toml
[result_storage]
backend = "local"
root_dir = "./data/results"
```

| Field | Type | Default | Description |
|---|---|---|---|
| backend | String | `"local"` | Storage backend. Options: `"local"`, `"s3"`. |
| root_dir | String | `"./data/results"` | Directory for local backend. Ignored when backend is `"s3"`. |
| max_persist_bytes | usize | `10485760` | Results larger than 10 MB are not persisted to storage. |
| bucket | String? | — | S3 bucket name. Required when backend is `"s3"`. |
| region | String? | — | AWS region for S3. |
| endpoint | String? | — | Custom S3 endpoint (for MinIO or localstack). |
| access_key_id | String? | — | S3 access key. Prefer environment variables or IAM roles. |
| secret_access_key | String? | — | S3 secret key. |
| path_style | bool | `false` | Use path-style S3 URLs. Set `true` for MinIO. |
| prefix | String? | — | Key prefix for S3 objects. |

### [result_channel]

In-memory relay for streaming results to waiting clients.

```toml
[result_channel]
max_slots = 10000
slot_ttl_secs = 600
```

| Field | Type | Default | Description |
|---|---|---|---|
| max_slots | usize | `10000` | Maximum concurrent in-memory result slots. |
| slot_ttl_secs | u64 | `600` | Slot removed after 10 minutes even if unclaimed by client. |

### [logging]

```toml
[logging]
level = "info"
format = "json"
```

| Field | Type | Default | Description |
|---|---|---|---|
| level | String | `"info"` | Log level filter. Options: `debug`, `info`, `warn`, `error`. |
| format | String | `"text"` | Log output format. `"json"` recommended for production. Overridden by `DBWARD_LOG_FORMAT` env var. |

### [slack]

Slack integration for approval notifications and interactive approve/reject.

```toml
[slack]
bot_token = "${SLACK_BOT_TOKEN}"
signing_secret = "${SLACK_SIGNING_SECRET}"
channel = "#db-approvals"
```

| Field | Type | Default | Description |
|---|---|---|---|
| bot_token* | String | — | Slack Bot OAuth token (`xoxb-...`). Required for Slack integration. |
| signing_secret* | String | — | Slack app signing secret for request verification. Empty string disables Slack integration entirely. |
| channel | String | `"#db-approvals"` | Default channel for notifications. |
| channels | Map\<String, String\> | `{}` | Per-environment channel override. Key = environment name, value = channel. |

### trusted_proxies

List of CIDR ranges whose `X-Forwarded-For` headers are trusted for client IP extraction.

```toml
trusted_proxies = ["10.0.0.0/8", "172.16.0.0/12"]
```

When empty (default), the direct connection IP is used. Required when running behind a load balancer to get accurate client IPs in audit logs.

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

| Field | Type | Default | Description |
|---|---|---|---|
| agent_id | String? | hostname | Unique agent identifier. Auto-detected from hostname if unset. |
| poll_interval_ms | u64 | `1000` | Milliseconds between poll requests to the server. |
| max_concurrent_tasks | u32 | `2` | Maximum parallel SQL executions. |
| drain_timeout_secs | u64 | `60` | Seconds to wait for in-flight tasks during graceful shutdown. |
| statement_timeout_secs | u64 | `30` | Default SQL statement timeout. Overridden by execution policy or workflow. |
| lease_duration_secs | u64 | `300` | How long the agent holds a job before the server reclaims it. |
| operations | String[]? | all | Limit which operation types this agent handles. Unset = all operations. |
| startup_retry_initial_ms | u64 | `1000` | Initial backoff delay when server is unreachable at startup. |
| startup_retry_max_ms | u64 | `15000` | Maximum backoff delay cap. |
| startup_max_wait_secs | u64 | `0` | Maximum total time to wait for server. `0` = wait forever. |

### [server]

```toml
[server]
url = "https://dbward.internal:3000"
agent_token = "${DBWARD_AGENT_TOKEN}"
```

| Field | Type | Default | Description |
|---|---|---|---|
| url* | String | — | Server URL the agent polls for jobs. |
| agent_token* | String | — | Authentication token. Use `${DBWARD_AGENT_TOKEN}` expansion to avoid hardcoding. |

### [databases.\<name\>.\<env\>]

Database connections keyed by logical name and environment.

```toml
[databases.app.production]
url = "postgres://user:pass@db:5432/app"

[databases.app.staging]
url = "postgres://user:pass@db-staging:5432/app"
```

| Field | Type | Default | Description |
|---|---|---|---|
| url* | String | — | Database connection URL. Supports `${VAR}` expansion. Scheme determines driver: `postgres://` or `mysql://`. |

### [schema_sync]

Controls automatic schema snapshot collection.

```toml
[schema_sync]
enabled = true
interval_secs = 3600
```

| Field | Type | Default | Description |
|---|---|---|---|
| enabled | bool | `true` | Enable schema sync. When disabled, no schema snapshots are collected. |
| sync_on_startup | bool | `true` | Collect schema immediately on agent startup. |
| interval_secs | u64 | `0` | Periodic sync interval. `0` = sync only on startup and after migrations. |

---

## CLI Configuration

### Resolution Model

The CLI merges configuration from multiple sources (highest priority first):

1. Environment variables (`DBWARD_SERVER_URL`, `DBWARD_TOKEN`, etc.)
2. `--config` flag (enables standalone mode — single file, no merging)
3. Project config (`./dbward.toml` or `DBWARD_CONFIG`)
4. Global config (`~/.config/dbward/config.toml`)

### Global Config

Located at `~/.config/dbward/config.toml`. Stores server connection and authentication.

```toml
[server]
url = "https://dbward.example.com:3000"
token = "dbw_abc123..."
```

### [server]

| Field | Type | Default | Description |
|---|---|---|---|
| url* | String | — | Server URL for API calls. |
| token | String? | — | API token for authentication. Mutually exclusive with `[server.oidc]`. |

### [server.oidc]

OIDC authentication for CLI login flows.

```toml
[server.oidc]
issuer = "https://auth.example.com/realms/dbward"
client_id = "dbward-cli"
```

| Field | Type | Default | Description |
|---|---|---|---|
| issuer* | String | — | OIDC issuer URL. Used for discovery. |
| client_id* | String | — | OIDC client ID for PKCE flow. |
| discovery_url | String? | — | Override OpenID Connect discovery endpoint. |
| backchannel_url | String? | — | Token endpoint URL override (when issuer is not reachable from CLI host). |
| browser_url | String? | — | Authorization URL override for browser redirect. |

### Project Config

Located at `./dbward.toml` in the project root. Defines database and migration defaults.

```toml
default_database = "app"
migrations_dir = "db/migrations"
```

| Field | Type | Default | Description |
|---|---|---|---|
| default_database | String? | — | Database used when `--database` is not specified. |
| default_environment | String? | — | Environment used when `--environment` is not specified. |
| migrations_dir | Path | `"./migrations"` | Directory containing migration SQL files. |

**[databases.\<name\>]** in project config:

| Field | Type | Default | Description |
|---|---|---|---|
| migrations_dir | Path? | — | Per-database migration directory override. |

A `[server]` section is also accepted in project config and overrides the global config.

---

## Environment Variables

| Variable | Description |
|---|---|
| `DBWARD_CONFIG` | Path to project config file. Enables standalone mode (no global config merging). |
| `DBWARD_SERVER_URL` | Override server URL from any config file. |
| `DBWARD_TOKEN` | Override API token. |
| `DBWARD_DATABASE` | Default database when `--database` is omitted. |
| `DBWARD_ENV` | Default environment when `--environment` is omitted. |
| `DBWARD_AGENT_TOKEN` | Agent authentication token. Typically referenced via `${DBWARD_AGENT_TOKEN}` in agent config. |
| `DBWARD_LOG_FORMAT` | Set to `"json"` to force JSON log output (server and agent). Overrides `[logging].format`. |

---

## Variable Expansion

All TOML config files support shell-style variable expansion for secrets and environment-specific values.

| Syntax | Behavior |
|---|---|
| `${VAR}` | Required — startup error if `VAR` is not set. |
| `${VAR:-default}` | Uses `default` if `VAR` is not set. |
| `${VAR:-}` | Empty string if `VAR` is not set. |

```toml
# Examples
[server]
agent_token = "${DBWARD_AGENT_TOKEN}"

[databases.app.production]
url = "${DATABASE_URL:-postgres://localhost:5432/app}"
```
