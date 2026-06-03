---
title: Authentication
description: Configure OIDC and API token auth
---

# Authentication

dbward supports two authentication methods: **API tokens** (simple, self-hosted) and **OIDC** (SSO with your identity provider). You can use either or both.

## Authentication modes

```toml
[auth]
mode = "token"   # "token" | "oidc" | "both"
```

| Mode | Use case |
|------|----------|
| `token` | Small teams, CI/CD, agents. No IdP needed. |
| `oidc` | Teams with Google/Okta/Keycloak SSO. |
| `both` | OIDC for humans, API tokens for agents and CI. |

---

## API Tokens

### Creating tokens

```bash
# Via CLI
dbward token create --subject alice --role admin
dbward token create --subject bob --role developer --groups "backend-team" --expires 90d
dbward token create --subject prod-agent --role agent-default --subject-type agent
```

```bash
# Via REST API (requires token.manage permission)
curl -X POST http://localhost:3000/api/tokens \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "subject_id": "bob",
    "roles": ["developer"],
    "groups": ["backend-team"],
    "name": "Bob CI token",
    "expires_at": "2026-09-01T00:00:00Z"
  }'
```

### Token options

| Field | Type | Description |
|-------|------|-------------|
| `subject_id` | string | **Required.** User or service identifier. |
| `roles` | string[] | Roles to assign. Default: `[]` (uses `default_role`). |
| `subject_type` | string | `user` or `agent`. Default: `user`. |
| `name` | string | Human-readable label. |
| `groups` | string[] | Group memberships (for workflow approver matching). |
| `expires_at` | datetime | Absolute expiry (RFC 3339). Unset = no expiration. |

### Token lifecycle

```
Create → Active → [Expired | Revoked]
```

- **Expiration:** Tokens with `expires_at` are rejected after the deadline.
- **Revocation:** Immediate via `DELETE /api/tokens/{id}`.
- **Self-revoke:** Users with `token.revoke_own` permission can revoke their own tokens.
- **No rotate API:** Revoke the old token and create a new one.

### Revoking tokens

```bash
# Admin can revoke any token
curl -X DELETE http://localhost:3000/api/tokens/$TOKEN_ID \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# Users can revoke their own tokens
curl -X DELETE http://localhost:3000/api/tokens/$TOKEN_ID \
  -H "Authorization: Bearer $MY_TOKEN"
```

### Using tokens

```toml
# In dbward.toml (client config)
[server]
url = "https://dbward.internal:3000"
token = "dbw_a1b2c3..."
```

Or via environment variable:

```toml
[server]
url = "https://dbward.internal:3000"
token = "${DBWARD_TOKEN}"
```

---

## OIDC (SSO) (Pro)

### Server configuration

```toml
[auth]
mode = "oidc"    # or "both" to also allow API tokens

[auth.oidc]
issuer = "https://accounts.google.com"
client_id = "123456789.apps.googleusercontent.com"
# # client_secret_env is not supported  # Optional: env var name
# jwks_uri = "http://keycloak:8080/realms/dbward/protocol/openid-connect/certs"  # Override for Docker
default_role = "readonly"         # Role when no mapping matches (default: readonly)
```

### Client configuration

```toml
# In dbward.toml (client config)
[server]
url = "https://dbward.internal:3000"

[server.oidc]
issuer = "https://accounts.google.com"
client_id = "123456789.apps.googleusercontent.com"
# discovery_url = "..."    # Override discovery endpoint
# browser_url = "..."      # Override authorize URL (for Docker)
# backchannel_url = "..."  # Override token endpoint (for Docker)
```

### Login flow

```bash
# Browser-based login (opens browser for OAuth flow)
dbward login

# Device flow (for headless environments / SSH)
dbward login --device

# Check current identity
dbward whoami

# Logout (revokes token locally)
dbward logout
```

### Role mappings

Map IdP claims to dbward roles:

```toml
# Map by group membership
[[auth.oidc.role_mappings]]
claim = "groups"
value = "db-admins"
role = "admin"

[[auth.oidc.role_mappings]]
claim = "groups"
value = "backend-team"
role = "developer"
```

**How it works:**
- All matching mappings are collected (a user can have multiple roles)
- If no mapping matches, `[auth.oidc].default_role` is used, then `[auth].default_role`
- Roles grant specific permissions (see [Authorization Reference](../reference/authorization.md))

### Supported IdPs

| IdP | Notes |
|-----|-------|
| Google Workspace | Set up OAuth consent screen + credentials |
| Okta | Create OIDC app, add `groups` claim to ID token |
| Keycloak | Create client, enable `groups` mapper |
| Azure AD (Entra) | Register app, configure `groups` claim |
| Auth0 | Add groups via Rules/Actions (custom claim namespace) |

---

## Groups

Groups enable team-based approval workflows. They come from the `groups` claim in the OIDC JWT.

### How groups flow

```
IdP (groups: ["dba-team", "backend"])
  │
  │ JWT with groups claim
  ▼
dbward server
  │
  │ Reads groups directly from JWT (no sync, no storage)
  ▼
Workflow evaluation
  │
  │ "Does this user belong to group:dba-team?"
  ▼
Approval decision
```

### Using groups in workflows

```toml
[[workflows]]
database = "primary"
environment = "production"

[[workflows.steps]]
type = "approval"
[[workflows.steps.approvers]]
group = "dba-team"    # Anyone in the IdP "dba-team" group can approve
min = 1
```

### Sync model

**There is no sync.** dbward reads groups from the JWT on every request.

| Question | Answer |
|----------|--------|
| When do group changes take effect? | When the user gets a new JWT (re-login) |
| Can the IdP push changes? | No. JWT-based, stateless. |
| How fast is the update? | Depends on JWT lifetime (IdP setting, typically 5min–1hr) |
| Is there a manual refresh? | `dbward logout && dbward login` |

**Recommendation:** Set your IdP's token lifetime to 5–15 minutes for near-real-time group updates.

### Groups vs Roles

| | Groups | Roles |
|---|---|---|
| Source | IdP `groups` claim | `role_mappings` conversion |
| Purpose | Workflow approver matching | API access control |
| Example | `group:dba-team` | `admin`, `developer` |
| Stored in dbward? | No (JWT only) | No (JWT only) |

Both are extracted from the JWT on every request. Neither is stored in dbward's database.

### API tokens with groups

Admin can assign groups to API tokens (for CI/CD or service accounts that need to act as approvers):

```bash
curl -X POST http://localhost:3000/api/tokens \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "subject_id": "ci-bot",
    "roles": ["developer"],
    "groups": ["backend-team"]
  }'
```

---

## Agent authentication

Agents use API tokens with `subject_type = "agent"`:

```bash
dbward token create --subject prod-agent --role agent-default --subject-type agent
```

In OIDC mode (`mode = "oidc"`), agents are the only entities allowed to use API tokens. Human users must authenticate via OIDC.

In `mode = "both"`, both API tokens and OIDC JWTs are accepted for all users.

---

## Security recommendations

1. **Use TTL on all tokens** — Set `expires_at` to 90 days max. Rotate before expiry.
2. **Use OIDC for humans** — Avoid sharing long-lived tokens between team members.
3. **Separate agent tokens** — One token per agent. Revoke individually if compromised.
4. **Short JWT lifetime** — Configure your IdP to issue tokens with 5–15 minute expiry.
5. **Use `mode = "both"`** — OIDC for humans, API tokens for agents. Best of both worlds.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `401 invalid token` | Token revoked or wrong | Check `dbward token list` |
| `401 token expired` | TTL exceeded | Create a new token |
| `401 OIDC not configured` | JWT sent but `mode = "token"` | Change to `mode = "oidc"` or `"both"` |
| `JWT verification failed` | Wrong issuer/audience/expired | Check `issuer` and `client_id` match IdP |
| JWKS fetch timeout | Server can't reach IdP | Check network, or set `jwks_uri` override |

## Next steps

- [Server setup](../deployment/server.md) — Full server configuration
- [Workflows](policies/workflows.md) — Group-based approval rules
- [Agent setup](../deployment/agent.md) — Agent token configuration
