# Changelog

## [0.1.2] — 2026-05-18

Production readiness: Kubernetes/ECS deployment, agent resilience, Pro plan enforcement, and operational hardening.

### Bug Fixes

- **max_executions off-by-one**: Execution count check now uses `>=` instead of `>`
- **reject permission asymmetry**: Non-admin requesters can no longer reject others' requests
- **find_similar_requests**: Fixed permission check and improved matching logic
- **apply_migration multi-statement**: MySQL migrations with multiple statements now execute atomically
- **Result truncation**: Large results are properly truncated with reason metadata
- **Multi-statement SELECT**: Queries with multiple result-producing statements are now rejected with a clear error (was silently broken — PG merged result sets, MySQL dropped all but first)
- **token create license limit**: CLI `token create` now respects Free plan token limits

### Features

- **Pro plan enforcement**: License key verification (Ed25519), Free tier limits on workflows/databases/agents/tokens
- **Kubernetes deployment**: Manifests, Helm chart, liveness/readiness probes, ConfigMap/Secret management
- **ECS deployment**: CloudFormation template with Fargate + EBS, Service Connect, EFS support
- **Docker image**: Published to `ghcr.io/dbward-dev/dbward-server` and `ghcr.io/dbward-dev/dbward-agent` (amd64 + arm64)
- **S3 Result Storage**: Production-ready with streaming, zero-copy relay, TTL-based lifecycle deletion
- **Agent reconnect**: Startup retry + exponential backoff + degraded mode
- **gosu privilege drop**: Docker entrypoint handles EBS volume chown then drops to non-root
- **Audit enrichment**: Reject reason, approval comment, row count, execution duration recorded
- **Version upgrade strategy**: Compatibility model, self-update detection, automatic schema migration

### UX

- Long query display with truncation indicator
- Result format switching (table/json/csv)
- DDL rejection error shows next action (`dbward migrate create`)
- Selector format errors show expected pattern
- `/api/me` returns permissions + scope

### Refactoring

- RequestRepo split into focused modules
- Shared test mock/fake aggregation
- Approval progress display improvements
- Agent crate architecture: runner/executor/heartbeat separation
- display.rs module split

### Testing

- Test strategy documented (testing-rules.md)
- +40 unit tests (fake aggregation, agent/auth/boundary)
- E2E scripts: 3 new + existing fixes (users.sh, registry.sh)
- CI stabilized: 550+ tests pass, clippy/fmt clean

### Infrastructure

- Agent metrics and extended health checks
- Docker security hardening (non-root, network isolation, secrets management)
- `gosu` for ECS EBS volume permission handling

## [0.1.1] — 2026-05-15

Quality, safety, and completeness improvements based on comprehensive scenario testing.

### Bug Fixes

- **Multi-statement execution**: PG `execute_cancellable` now uses `raw_sql` + `fetch_many` for multi-statement support; MySQL uses `BEGIN/COMMIT` with `ROLLBACK` on error
- **PostgreSQL array types**: Arrays now return as JSON arrays (`[1,2,3]`) instead of text (`"{1,2,3}"`) via recursive descent parser
- **Invalid operation validation**: Unknown operation values now return 400 with valid values hint (was silent fallback)
- **share_with prefix validation**: `"bob"` → 400; `"user:bob"` → accepted
- **Statement::Replace/Do classification**: Explicit match for REPLACE and DO statements
- **GetRequest approver fallback**: Workflow selector match for approver determination
- **RetentionConfig default**: `approval_ttl_secs` no longer defaults to 0
- **migrate up**: Single-file format detection fixed
- **migrate_status**: No longer falls through to default handler
- **dbward dev restart**: Config files generated correctly on restart

### Features

- **ResultPolicy / NotificationPolicy**: Full CRUD API with per-DB/environment specificity
- **Users table**: Auto-create on first authentication
- **Request visibility scoping**: Developers see only their own requests; admins see all
- **Claim response**: `lease_expires_at` field added
- **default_environment**: Read from `client.toml`
- **Logging config + trusted_proxies**: XFF middleware with configurable trusted proxy CIDRs, client IP recorded in audit events
- **Token create/revoke subcommands**: `dbward-server token create/revoke` for standalone operation

### Safety

- **Agent job parallelization**: `tokio::spawn` + `InFlightGuard` + `max_concurrent` control
- **Result storage size limit**: `max_persist_bytes` enforcement
- **Per-DB/environment result policies**: Specificity-based policy matching with `retention_days`, `delivery_mode`, `access`
- **ResultChannels backpressure**: Memory-bounded with eviction
- **Webhook DLQ**: Persist-first delivery, background retry, dead letter after max attempts

### Refactoring

- **Clock trait** + **IdGenerator trait**: Testability improvements
- **routes.rs split**: Modular route organization
- **Execution pipeline redesign**: Operation enum, type-safe ExecutionToken, unified ExecutionResult, independent Heartbeat component, Pipeline separation
- **CLI workflow.rs extraction**: Request lifecycle orchestration separated from commands

### UX

- `--config` promoted to global option
- Error messages include `--database app` hint
- `approve/reject/cancel` accept shortened IDs (CLI)
- Invalid operation errors list valid values
- Expired request errors show `pending_ttl_secs` hint
- `migrate up` parse errors improved

### Infrastructure

- Agent healthcheck (file-based probe)
- Agent `stop_grace_period: 90s`
- `after_connect`: Always sets `bytea_output = 'hex'` (was conditional)
- E2E scripts updated to PR#16 `dbward-server token create` format

## [0.1.0] — 2026-05-13

Initial release. A workflow and approval engine for database operations.

### Architecture

- **Agent-only execution**: CLI/MCP clients never touch the database directly. Only the agent connects to target databases.
- **Three components**: CLI (request/approve), Server (workflow/audit/coordination), Agent (DB execution)
- **On-demand execution**: Agent executes only after client dispatches, preventing result loss

### Features

#### Query Execution
- PostgreSQL and MySQL support via `DatabaseDriver` trait
- SELECT (read-only) and DML (write) with workflow-based approval
- Multi-statement execution with atomicity guarantees (PG simple query protocol, MySQL explicit TX)
- Statement timeout (PG `statement_timeout`, MySQL `max_execution_time` + external timeout fallback)
- Query classification via sqlparser AST (3-layer defense: structural/semantic/opaque)
- Cancel support with graceful KILL

#### Migrations
- `migrate up/down/status/create` commands
- Idempotent execution (applied_versions check + max_count limit)
- Concurrent migration prevention (same db/env exclusion)
- Migration content embedded in request detail (no agent filesystem access needed)

#### Workflow & Approval
- Policy engine with multi-step approval workflows
- Designated approvers (role/group/user selectors)
- Admin override (per-step, not all-at-once)
- Self-approve prevention, cross-step distinct actor enforcement
- Break-glass emergency bypass with audit trail
- Pending TTL with automatic expiration

#### Authentication & Authorization
- API token authentication (Ed25519 signed execution tokens)
- OIDC authentication (Google, Keycloak, etc.)
- Dual auth mode (`token`, `oidc`, `both`)
- RBAC with built-in roles (admin, developer, readonly, agent-default)
- Role bindings + OIDC role mappings via ConfigRoleResolver
- Scoped permissions per database/environment

#### Audit
- Hash-chain integrity (SHA-256 linked events)
- 7 categories, 24+ event types
- SQL redaction via sqlparser VisitorMut (literals → `?`)
- IP recording, detail fingerprint (search-only, not in chain)
- Export: `dbward audit --output csv/json`, `--verify` integrity check

#### Result Storage
- Always-store default with `--no-store` opt-out
- `--share-with` access control (user/group/role selectors, validated on creation)
- 30-day retention with automatic cleanup
- Result list endpoint (`GET /api/results`)

#### Webhook Notifications
- Slack Block Kit format with v1-style separators
- Generic JSON format with HMAC signing
- Event filtering per webhook
- Smart retry (4xx immediate fail, 5xx exponential backoff)
- Requester/actor/operation visibility in notifications

#### MCP (Model Context Protocol)
- Async stdio mode with Connection Actor
- 15 tools, Resources, Prompts, Elicitation
- Same workflow enforcement as CLI/API

#### CLI
- `dbward execute`, `request list/show/approve/reject/cancel/resume`
- `dbward result list/get`, `dbward audit`
- `dbward migrate up/down/status/create`
- `dbward dev up` (local server+agent auto-start)
- Ctrl+C graceful handling with continuation message
- State-specific error messages for resume
- `--pending-for-me` filter (denormalized table, no N+1)
- Exit code 2 for pending (CI/CD friendly)

#### API
- REST API with structured errors (`ApiError` type)
- Long-poll support for request status changes
- Pagination, lease reclaim, result size limits
- `pending_for_me` query parameter

#### Infrastructure
- SQLite embedded storage (WAL mode, checkpoint, token purge)
- Docker development environment (BuildKit cache, cargo-chef)
- Structured logging (tracing, JSON/compact, file output + daily rotation)
- Free tier limits (5 workflows, 3 databases, 3 agents, 3 webhooks, 10 tokens)

### Security
- Fail-closed workflow evaluation
- Token replay prevention (execution token protocol)
- SSRF protection for webhooks (private IP/invalid URL rejection)
- Query classification prevents DDL via execute API
- Audit redaction prevents sensitive data in logs
- `cargo deny` clean (licenses + advisories)
