---
title: Security Hardening
description: Production hardening guide for dbward
---

# Security Hardening

Recommendations for running dbward securely in production.

## Network Architecture

### Server

Place the server behind a reverse proxy that terminates TLS:

```
Internet → [Reverse Proxy (TLS)] → [dbward-server :3000]
```

- Configure `trusted_proxies` in server.toml to enable correct client IP extraction from `X-Forwarded-For`
- Firewall: allow inbound only from your reverse proxy CIDR
- The server does **not** need direct database access

### Agent

The agent uses **outbound-only** connections:

```
[dbward-agent] → [dbward-server] (HTTPS, poll)
[dbward-agent] → [Target DB] (PostgreSQL 5432 / MySQL 3306)
```

- **No inbound ports required** — deploy in private subnets
- Restrict outbound to only the server URL and target database hosts
- Liveness/readiness: file-based (`/tmp/dbward-agent-alive`, `/tmp/dbward-agent-ready`)

### Network Separation

Ideally, the server and agent run in different network zones:

```
┌─ Public Zone ──┐   ┌─ App Zone ──────┐   ┌─ Data Zone ─────┐
│ Reverse Proxy  │──▶│ dbward-server   │◀──│ dbward-agent    │──▶ Database
└────────────────┘   └─────────────────┘   └─────────────────┘
```

The agent bridges the app and data zones. The server never reaches the database.

## Database User Configuration

Create dedicated, minimally-privileged database users for the agent:

```sql
-- Read-only user (for SELECT operations)
CREATE USER dbward_reader WITH PASSWORD '...';
GRANT CONNECT ON DATABASE app TO dbward_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO dbward_reader;

-- Migration user (for DDL operations)
CREATE USER dbward_migrator WITH PASSWORD '...';
GRANT CONNECT ON DATABASE app TO dbward_migrator;
GRANT CREATE ON SCHEMA public TO dbward_migrator;

-- Never use a superuser or the database owner
```

Configure separate agent instances or capabilities per privilege level.

## Authentication

For setup instructions, see [Authentication Guide](../guides/authentication.md).

### OIDC (Recommended)

- Inherits your IdP's MFA, session management, and offboarding
- No token rotation needed on the dbward side
- Configure `auth.oidc.role_mappings` to map IdP groups → dbward roles
- Test: disabling a user in IdP immediately blocks dbward access

### API Tokens

- Set `expires_at` — avoid indefinite tokens
- Rotate periodically (recommended: 90 days)
- Inject via environment variable: `DBWARD_TOKEN=dbw_...`
- Never commit tokens to version control

### Agent Token

- Inject via environment variable: `DBWARD_AGENT_TOKEN=dbw_...`
- Use a secrets manager (Vault, AWS Secrets Manager, K8s secrets) for injection
- Rotate: generate new token → update agent env → revoke old token

## Key Management

### Ed25519 Signing Key

The signing key (`data/signing.key`) is critical — it authorizes database executions.

- Permissions: `0600`, owned by the server's service account
- Location: inside `data/` directory (permissions `0700`)
- **Rotation**: Generate new key → restart server → old tokens expire naturally (5min TTL)
- Future: KMS/HSM integration planned

### Signing Key Compromise Response

If the signing key is suspected compromised:

1. **Immediately stop all agents** — prevents execution of potentially forged tokens
2. **Delete or replace `data/signing.key`** — generate a new key
3. **Restart the server** — it will use the new key for all future tokens
4. **Wait 5 minutes** — all previously-issued tokens expire (max TTL = 5min)
5. **Restart agents** — they fetch the new public key from `GET /api/public-key`
6. **Review audit log** — check for unauthorized executions during the compromise window

The 5-minute token TTL limits the blast radius. An attacker with the signing key can forge tokens, but only for operations the agent's capability config allows and only against databases the agent can reach.

### Agent Trust Revocation

To immediately revoke an agent's ability to execute:

1. **Revoke the agent's API token** — agent can no longer poll or claim jobs
2. **Stop the agent process** — if token revocation alone is insufficient
3. **Rotate the target database credentials** — if agent host is compromised

### Protection

- Disable core dumps on the server host: `ulimit -c 0` or sysctl `kernel.core_pattern=|/bin/false`
- Use encrypted swap or disable swap entirely
- Do not include `signing.key` in backups unless encrypted

## Slack & Webhook Security

### Slack

- Store `signing_secret` as environment variable (never in config files committed to VCS)
- Slack signs every interaction with HMAC-SHA256; dbward verifies with constant-time comparison
- Timestamp validation: requests older than 5 minutes are rejected (replay prevention)
- Consider IP allowlisting for Slack's published CIDR ranges at the firewall level

### Webhooks

- Always configure a webhook secret — dbward signs payloads with HMAC-SHA256
- Verify the `X-Dbward-Signature` header on your receiver
- SQL content is automatically redacted (literals → `?`)
- Built-in SSRF protection: private IPs, loopback, and link-local addresses are blocked
- Recommendation: additionally allowlist specific webhook destination hosts

## Logging & Privacy

### What is logged

- Audit events: actor, action, target, timestamp, outcome (always logged)
- Request SQL: stored in `requests.detail` (server SQLite)
- Webhook payloads: SQL redacted before sending

### What is NOT logged

- API token plaintext (only hash stored)
- Database query results (streamed, not stored on server unless result_store configured)
- OIDC tokens (only subject_id extracted)

### Retention

- Audit events: default 365 days (`audit_ttl_days`), configurable
- Configure `result_ttl_days` for automatic result cleanup
- Export audit logs to external SIEM for long-term retention and independent verification

## Backup & Recovery

### SQLite State

- **Litestream** (recommended): continuous replication to S3/GCS
- Manual: copy `data/dbward.db` while running (SQLite WAL mode is safe for hot copy)
- Test restore procedures regularly

### Integrity After Restore

- Run audit hash chain verification after any restore
- If chain breaks are detected, the backup may be corrupted or tampered with

## Monitoring

| Endpoint | Purpose |
|----------|---------|
| `GET /health` | Basic liveness (always 200 when process is up) |
| `GET /ready` | Readiness (DB connected, migrations applied) |

### Recommended Alerts

- Server `/ready` returning non-200 (service degraded or draining)
- Agent offline or saturated — poll `GET /api/agents` with a `metrics.view` token and check the `status` field
- Agent liveness file missing (`/tmp/dbward-agent-alive`) — container runtime should restart
- Audit chain verification failure (daily cron)
- Unusual approval patterns (e.g., break-glass usage spike)
- Token verification errors (may indicate attack attempts)

For automated monitoring, create a dedicated token with `metrics.view` permission (not the admin token) and poll `GET /api/agents` via cron or Lambda.
