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
│ Client (dbward process)                                  │
│   - Runs on a network that can reach the target DB       │
│   - Owns Engine (DatabaseDriver → Target DB)             │
│   - CLI: dbward login/migrate/execute/approve/reject/mcp │
│   - MCP: dbward mcp [--server http://...]                │
└──────┬───────────────────────────────────┬───────────────┘
       │ Direct mode                       │ Server mode
       │ (development only)                │ (OIDC / API token)
       ▼                                   ▼
┌──────────────────┐          ┌────────────────────────────┐
│ Target DB        │          │ Server (dbward server)     │
│ (PostgreSQL /    │          │   - OIDC JWT verification  │
│  MySQL)          │          │   - API token auth         │
└──────────────────┘          │   - Approval state (SQLite)│
                              │   - Audit log (SQLite)     │
                              │   - Ed25519 token signing  │
                              │   - Webhook notifications  │
                              │   - NO DB connection       │
                              └────────────────────────────┘
                                        │
                                        ▼
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
├── dbward-core      (Engine, DatabaseDriver trait, types, RBAC, audit, config, token verification)
├── dbward-migrate   (migration file I/O + execution via DatabaseDriver)
│     └── dbward-core
└── dbward-server    (axum HTTP, OIDC/token auth, approval state, SQLite, Ed25519 signing, webhooks)
      └── dbward-core (types + token)
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

## Two Modes

### Direct Mode (development only)

Client connects directly to target DB. No approval flow. Audit log to stdout.

**Restricted to `development` environment only.** Attempting Direct mode with
staging/production is rejected at the CLI level. This prevents bypassing the
approval flow by simply omitting `--server`.

### Server Mode (staging, production)

Client talks to server for approval, then executes locally.

```
Client                              Server
  │                                   │
  ├─① POST /api/requests ───────────▶│ auth (OIDC JWT or API token)
  │                                   │ policy check → pending / auto_approved / break_glass
  │                                   │
  │  (if pending)                     │
  │  CLI prints request ID and exits  │
  │                                   │
  │    (human approves via CLI)       │
  │                                   │◀── POST /api/requests/{id}/approve
  │                                   │     → generates Ed25519 execution_token
  │                                   │     → webhook notification
  │                                   │
  │  dbward resume {id}              │
  ├─② GET /api/requests/{id} ──────▶│ → status + execution_token
  │                                   │
  ├─③ verify token → Engine → DB     │
  │                                   │
  ├─④ POST /api/requests/{id}/complete▶│ → audit_log + status: "executed"
  │                                   │     → webhook notification
```

### Break-Glass (Emergency Bypass)

For incidents when no approver is available.

```bash
dbward execute "SELECT pg_terminate_backend(12345)" \
  --emergency --reason "connection pool exhausted at 3am"
```

- Server issues token immediately (no approval needed)
- Status = `break_glass`
- Webhook fires `break_glass` event to all hooks (🚨 in Slack)
- Reason is recorded in audit log
- Admin + Developer can use (Readonly cannot)

## DatabaseDriver Trait

Abstracts over database backends. URL scheme selects the driver automatically.

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
  "detail_hash": "sha256(SQL)",
  "expires_at": "2026-05-01T14:00:00Z",
  "signature": "ed25519_sign(message)"
}
```

- Server holds **private key** (signs). Client holds **public key** only (verifies).
- `detail_hash` = SHA-256 of SQL — prevents approve-one-execute-another.
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

## MCP Async Approval (Server Mode)

MCP tools don't block on approval. Instead:

1. `dbward_execute_query` → returns `"Request {id} requires approval"` immediately
2. Human approves via CLI: `dbward approve {id}`
3. AI calls `dbward_check_request` → returns status
4. AI calls `dbward_resume_execution` → verifies token, executes, reports completion

8 MCP tools total (6 base + `check_request` + `resume_execution`).

MCP agents authenticate via API tokens (OIDC browser flow not available in stdio mode).

## REST API (9 endpoints)

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | No | Health check |
| GET | `/api/public-key` | No | Ed25519 public key (32 bytes) |
| GET | `/api/requests` | Yes | List requests |
| POST | `/api/requests` | Yes | Create request (supports emergency flag) |
| GET | `/api/requests/:id` | Yes | Get request + token if approved |
| POST | `/api/requests/:id/approve` | Yes | Approve (requester ≠ approver) |
| POST | `/api/requests/:id/reject` | Yes | Reject (admin or requester) |
| POST | `/api/requests/:id/complete` | Yes | Report execution result |
| GET | `/api/audit` | Yes | Audit log |

All "Yes" endpoints accept both OIDC JWT and API token in Authorization header.

## Security

| Attack | Mitigation |
|---|---|
| Forge execution token | Ed25519 asymmetric — client has public key only |
| Approve one SQL, execute another | `detail_hash` in signature |
| Token replay | Executed requests don't issue tokens |
| SQL injection (multi-statement) | Semicolon check rejects chained statements |
| Self-approve | Server enforces requester ≠ approver |
| Unauthorized reject | Only admin or requester can reject |
| Direct mode bypass | Blocked for non-development environments |
| Auth token leak (OIDC) | Short-lived JWT + PKCE + revocation |
| Auth token leak (API) | `dbward server token revoke` + audit log |
| Webhook secret leak | HMAC-SHA256 signature verification |

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
    operation TEXT NOT NULL, environment TEXT NOT NULL, detail TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    approved_by TEXT, created_at TEXT NOT NULL, resolved_at TEXT,
    emergency INTEGER NOT NULL DEFAULT 0, reason TEXT
);

CREATE TABLE audit_log (
    id TEXT PRIMARY KEY, timestamp TEXT NOT NULL,
    user TEXT NOT NULL, role TEXT NOT NULL,
    operation TEXT NOT NULL, environment TEXT NOT NULL, detail TEXT NOT NULL,
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
dbward mcp                      # MCP stdio server
dbward server start             # HTTP server
dbward server token create/revoke
dbward approve <ID>
dbward reject <ID>
dbward list                     # Show requests
dbward resume <ID>              # Resume after approval
```

## Migration File Format (dbmate-compatible)

```sql
-- migrate:up
CREATE TABLE users (id SERIAL PRIMARY KEY, name TEXT NOT NULL);

-- migrate:down
DROP TABLE users;
```
