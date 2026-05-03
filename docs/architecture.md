# Architecture

## Components

```
┌──────────────────────────────────────────────────────────┐
│ AI Client (Kiro / Cursor / Copilot)                      │
│   uses MCP stdio to talk to dbward                       │
└──────────────┬───────────────────────────────────────────┘
               │ MCP (JSON-RPC 2.0 over stdin/stdout)
               ▼
┌──────────────────────────────────────────────────────────┐
│ Client (dbward-cli / dbward mcp)                         │
│   - NO DB credentials or DB connection                   │
│   - Creates requests, retrieves results                  │
│   - CLI: dbward login/migrate/execute/approve/reject/... │
│   - MCP: dbward mcp --server http://...                  │
└──────────────┬───────────────────────────────────────────┘
               │ HTTPS (OIDC JWT or API token)
               ▼
┌──────────────────────────────────────────────────────────┐
│ Server (dbward server)                                   │
│   - OIDC JWT verification                                │
│   - API token auth                                       │
│   - Policy engine (approval rules)                       │
│   - Approval state (SQLite)                              │
│   - Audit log (SQLite)                                   │
│   - Ed25519 token signing                                │
│   - Job dispatch (poll/claim)                            │
│   - Result storage                                       │
│   - Webhook notifications                                │
│   - NO DB connection                                     │
└──────────────┬───────────────────────────────────────────┘
               │ Outbound HTTPS polling (no inbound needed)
               ▼
┌──────────────────────────────────────────────────────────┐
│ Agent (dbward agent)                                     │
│   - ONLY component with DB credentials                   │
│   - Polls server for approved jobs                       │
│   - Claims + executes operations                         │
│   - Returns results to server                            │
│   - Runs on DB-reachable network                         │
│   - Multiple agents supported (capabilities matching)    │
└──────────────┬───────────────────────────────────────────┘
               │ DatabaseDriver (sqlx)
               ▼
┌──────────────────────────────────────────────────────────┐
│ Target DB (PostgreSQL / MySQL)                           │
└──────────────────────────────────────────────────────────┘

               ┌────────────────────────────┐
               │ Identity Provider (IdP)    │
               │ Google / Okta / OneLogin / │
               │ Auth0 / Keycloak /         │
               │ AWS IAM Identity Center /  │
               │ K8s ServiceAccount         │
               └────────────────────────────┘
```

## Crate Dependency Graph

```
dbward (binary, CLI)
├── dbward-core      (types, RBAC, audit, config, token verification)
├── dbward-migrate   (migration file I/O)
│     └── dbward-core
├── dbward-server    (axum HTTP, OIDC/token auth, policy, approval state, SQLite, Ed25519 signing, webhooks, job dispatch, result storage)
│     └── dbward-core
└── dbward-agent     (DatabaseDriver, polls server, executes operations, returns results)
      ├── dbward-core
      └── dbward-migrate
```

## Authentication

Two authentication methods coexist. Server distinguishes by Bearer token prefix.

```
Bearer dbw_xxx   → API token (SHA-256 prefix lookup)
Bearer eyJxxx    → JWT (OIDC verification)
```

Both resolve to the same `AuthenticatedUser { identity, role, auth_method }`.

### OIDC (for humans)

Server validates JWTs against the IdP's JWKS endpoint.

```
dbward login
  → Browser opens → IdP authentication → Callback with auth code
  → Exchange code for tokens (Authorization Code Flow + PKCE)
  → Save to ~/.dbward/credentials.json (0600)

dbward login --device
  → Display user code → User visits URL on any device → Poll for token
  → For SSH / container environments without browser

dbward whoami
  → Show current identity, role, token expiry

dbward logout
  → Revoke tokens at IdP + delete local credentials
```

### API Tokens (for CI/CD, MCP agents)

Existing mechanism. Managed via `dbward server token create/revoke`.
Used when OIDC is not practical (stdio MCP, CI pipelines, scripts).

### K8s ServiceAccount

K8s ServiceAccount tokens are OIDC-compliant JWTs since K8s 1.20.
Server validates them through the same OIDC verification path.
No additional implementation needed — just configure the K8s OIDC issuer.

### Server Auth Configuration

```toml
# dbward-server.toml

[auth]
mode = "both"  # "oidc", "token", "both" (default: "token" for backward compat)

[auth.oidc]
issuer = "https://accounts.google.com"
client_id = "xxx.apps.googleusercontent.com"
client_secret_env = "DBWARD_OIDC_CLIENT_SECRET"  # env var name, not the secret itself
default_role = "readonly"

# Role mappings (evaluated in order, first match wins)
[[auth.oidc.role_mappings]]
subject = "alice@example.com"
role = "admin"

[[auth.oidc.role_mappings]]
claim = "groups"
value = "dbward-developers"
role = "developer"

[[auth.oidc.role_mappings]]
claim = "groups"
value = "dbward-admins"
role = "admin"
```

### Role Mapping (3-level fallback)

1. **Server-side mapping table** (subject/claim → role) — highest priority
2. **JWT custom claim** (role_claim config) — for orgs managing groups in IdP
3. **default_role** — safety net, recommend `readonly`

### JWT Verification

| Check | Detail |
|---|---|
| iss | Must match configured issuer |
| aud | Must contain configured client_id |
| exp | Current time + 30s leeway |
| iat | Must be within 24 hours |
| kid → key | Lookup in cached JWKS |
| signature | RS256 or ES256 |

JWKS cache: 1-hour TTL, re-fetch on unknown kid (min 60s interval).
JWKS URI auto-discovered from `{issuer}/.well-known/openid-configuration`.

### Token Storage (CLI)

```
~/.dbward/credentials.json (permissions: 0600)
{
  "default": {
    "access_token": "eyJ...",
    "refresh_token": "xxx",
    "id_token": "eyJ...",
    "expires_at": "2026-05-02T15:00:00Z",
    "issuer": "https://accounts.google.com"
  }
}
```

Auto-refresh: before each command, if token expires within 5 minutes.

### Security Considerations (Auth)

| Concern | Mitigation |
|---|---|
| Auth code interception | PKCE (S256) required for all CLI flows |
| CSRF on callback | state parameter verified |
| DNS rebinding | Callback on 127.0.0.1 only (not localhost) |
| client_secret leak | Loaded from env var, never in config file |
| Token leak (access) | Short-lived (1h), limited blast radius |
| Token leak (refresh) | `dbward logout` revokes at IdP |
| Token leak (credentials.json) | 0600 permissions |

## Request Flow (Agent-Only Architecture)

All DB operations go through the same flow: client → server → agent → DB.

```
Client                              Server                              Agent
  │                                   │                                   │
  ├─① POST /api/requests ───────────▶│ auth + policy check               │
  │                                   │ → pending / auto_approved /       │
  │                                   │   break_glass                     │
  │                                   │                                   │
  │  (if pending)                     │                                   │
  │  CLI prints request ID and exits  │                                   │
  │                                   │                                   │
  │    (human approves via CLI)       │                                   │
  │                                   │◀── POST /api/requests/{id}/approve│
  │                                   │     → Ed25519 execution_token     │
  │                                   │     → webhook notification        │
  │                                   │                                   │
  │                                   │  ② Agent polls for approved jobs  │
  │                                   │◀──────── GET /api/agent/jobs ─────┤
  │                                   │                                   │
  │                                   │  ③ Agent claims job               │
  │                                   │◀──── POST /api/agent/jobs/{id}/claim
  │                                   │     → returns execution_token     │
  │                                   │                                   │
  │                                   │  ④ Agent verifies token,          │
  │                                   │     executes on DB                │
  │                                   │                                   │
  │                                   │  ⑤ Agent returns result           │
  │                                   │◀── POST /api/agent/jobs/{id}/complete
  │                                   │     → audit_log + status update   │
  │                                   │     → webhook notification        │
  │                                   │                                   │
  ├─⑥ GET /api/requests/{id} ──────▶│ → status + result                 │
  │  (dbward resume {id})             │                                   │
```

### Break-Glass (Emergency Bypass)

For incidents when no approver is available.

```bash
dbward execute "SELECT pg_terminate_backend(12345)" \
  --emergency --reason "connection pool exhausted at 3am"
```

- Server issues token immediately (no approval needed)
- Status = `break_glass`
- Agent picks up and executes immediately
- Webhook fires `break_glass` event to all hooks (🚨 in Slack)
- Reason is recorded in audit log
- Admin + Developer can use (Readonly cannot)

## Agent

### Responsibilities

- **Only component with DB credentials** — credentials never leave the agent's network
- Polls server for approved/auto_approved/break_glass jobs
- Claims jobs (lease-based, prevents double execution)
- Verifies Ed25519 execution token before executing
- Executes SQL via DatabaseDriver
- Returns results (rows/affected count/error) to server

### Capabilities Matching

Each agent registers its capabilities (which databases it can reach):

```toml
# dbward-agent.toml
[agent]
server = "https://dbward.internal:8080"
token = "dbw_agent_xxx"
poll_interval = "5s"

[[agent.databases]]
name = "primary"
url = "postgres://user:pass@db-primary:5432/app"

[[agent.databases]]
name = "analytics"
url = "mysql://user:pass@db-analytics:3306/warehouse"
```

Server matches jobs to agents based on the `database` field in the request.

### Multiple Agents

- Multiple agents can run simultaneously (e.g., one per DB, one per network zone)
- Lease/claim prevents double execution: agent claims a job → server marks it as claimed
- If an agent crashes, lease expires and another agent can pick up the job

## DatabaseDriver Trait

Abstracts over database backends. URL scheme selects the driver automatically.
Lives in the agent — client and server never use this.

```rust
#[async_trait]
pub trait DatabaseDriver: Send + Sync {
    async fn query(&self, sql: &str) -> Result<Vec<Value>, Error>;
    async fn execute(&self, sql: &str) -> Result<u64, Error>;
    async fn apply_migration(&self, sql: &str, version: &str) -> Result<(), Error>;
    async fn revert_migration(&self, down_sql: &str, version: &str) -> Result<(), Error>;
    async fn ensure_migrations_table(&self) -> Result<(), Error>;
    async fn applied_versions(&self) -> Result<Vec<String>, Error>;
}

// postgres:// → PostgresDriver (PgPool)
// mysql://    → MysqlDriver (MySqlPool)
pub async fn connect(url: &str) -> Result<Arc<dyn DatabaseDriver>, Error>;
```

## Execution Token (Ed25519)

```json
{
  "request_id": "req_abc",
  "operation": "migrate_up",
  "environment": "production",
  "database": "primary",
  "detail_hash": "sha256(SQL)",
  "expires_at": "2026-05-01T14:00:00Z",
  "signature": "ed25519_sign(message)"
}
```

- Server holds **private key** (signs). Agent holds **public key** (verifies before executing).
- `detail_hash` = SHA-256 of SQL — prevents approve-one-execute-another.
- `database` in signature — prevents executing against wrong database.
- Token replay prevention: executed/failed requests don't issue new tokens.
- Public key available via `GET /api/public-key`.

## Webhook Notifications

Server sends HTTP webhooks on approval events.

```toml
# dbward-server.toml
[[webhooks]]
url = "https://hooks.slack.com/services/T.../B.../xxx"
events = ["request_created", "request_approved", "request_rejected", "request_completed", "break_glass"]
format = "slack"

[[webhooks]]
url = "https://internal.example.com/dbward-webhook"
events = ["break_glass"]
format = "generic"
secret = "whsec_xxxx"  # HMAC-SHA256 signature in X-Dbward-Signature header
```

- Fire-and-forget (tokio::spawn)
- 3 retries with exponential backoff (1s → 4s → 16s)
- Failure is warn log only (never blocks request processing)

## MCP Async Approval

MCP client never connects to DB. All operations go through the server → agent flow.

1. `dbward_execute_query` → creates request on server → returns `"Request {id} created (pending approval)"` or result if auto-approved and agent completes quickly
2. Human approves via CLI: `dbward approve {id}`
3. AI calls `dbward_check_request` → returns status (pending/approved/executed/failed)
4. AI calls `dbward_get_result` → returns query result after agent execution

MCP agents authenticate via API tokens (OIDC browser flow not available in stdio mode).

## REST API

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | No | Health check |
| GET | `/api/public-key` | No | Ed25519 public key |
| GET | `/api/requests` | Yes | List requests |
| POST | `/api/requests` | Yes | Create request (supports emergency flag) |
| GET | `/api/requests/:id` | Yes | Get request + result |
| POST | `/api/requests/:id/approve` | Yes | Approve (requester ≠ approver) |
| POST | `/api/requests/:id/reject` | Yes | Reject (admin or requester) |
| GET | `/api/audit` | Yes | Audit log |
| GET | `/api/agent/jobs` | Agent | Poll for approved jobs |
| POST | `/api/agent/jobs/:id/claim` | Agent | Claim a job (lease) |
| POST | `/api/agent/jobs/:id/complete` | Agent | Report execution result |

All "Yes" endpoints accept both OIDC JWT and API token. Agent endpoints use agent-specific API tokens.

## Security

| Attack | Mitigation |
|---|---|
| Forge execution token | Ed25519 asymmetric — agent verifies with public key |
| Approve one SQL, execute another | `detail_hash` in signature |
| Token replay | Executed requests don't issue tokens |
| SQL injection (multi-statement) | Semicolon check rejects chained statements |
| Self-approve | Server enforces requester ≠ approver |
| Unauthorized reject | Only admin or requester can reject |
| DB credential leak | Only agent has credentials, not on developer machines |
| Auth token leak (OIDC) | Short-lived JWT + PKCE + revocation |
| Auth token leak (API) | `dbward server token revoke` + audit log |
| Webhook secret leak | HMAC-SHA256 signature verification |
| Agent impersonation | Agent-specific API tokens, scoped to agent role |

## SQLite Schema (Server)

```sql
PRAGMA journal_mode=WAL;

CREATE TABLE tokens (
    id TEXT PRIMARY KEY, user TEXT NOT NULL, role TEXT NOT NULL,
    hash TEXT NOT NULL, prefix TEXT NOT NULL,
    created_at TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE requests (
    id TEXT PRIMARY KEY, user TEXT NOT NULL,
    operation TEXT NOT NULL, environment TEXT NOT NULL,
    database TEXT NOT NULL, detail TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    approved_by TEXT, created_at TEXT NOT NULL, resolved_at TEXT,
    emergency INTEGER NOT NULL DEFAULT 0, reason TEXT,
    execution_result TEXT, completed_at TEXT
);

CREATE TABLE agents (
    id TEXT PRIMARY KEY, name TEXT NOT NULL,
    capabilities TEXT NOT NULL,  -- JSON array of database names
    last_seen TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE audit_log (
    id TEXT PRIMARY KEY, timestamp TEXT NOT NULL,
    user TEXT NOT NULL, role TEXT NOT NULL,
    operation TEXT NOT NULL, environment TEXT NOT NULL,
    database TEXT NOT NULL, detail TEXT NOT NULL,
    success INTEGER NOT NULL, error_message TEXT, request_id TEXT,
    emergency INTEGER NOT NULL DEFAULT 0
);
```

## CLI Commands

```
dbward init                     # Interactive setup wizard
dbward login                    # OIDC login (browser)
dbward login --device           # OIDC login (no browser)
dbward whoami                   # Show current identity
dbward logout                   # Revoke + delete tokens
dbward migrate up/down/status/create
dbward execute <SQL>            # --emergency --reason for break-glass
dbward approve <ID>
dbward reject <ID>
dbward list                     # Show requests
dbward resume <ID>              # Get result after agent execution
dbward mcp                      # MCP stdio server
dbward server start             # HTTP server
dbward server token create/revoke
dbward agent start              # Start agent (polls server, executes jobs)
dbward dev up                   # Start local server + agent for development
```

## Migration File Format (dbmate-compatible)

```sql
-- migrate:up
CREATE TABLE users (id SERIAL PRIMARY KEY, name TEXT NOT NULL);

-- migrate:down
DROP TABLE users;
```
