# Changelog

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
