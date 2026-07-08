---
title: Authentication
description: Configure OIDC and API token auth
---

# Authentication

dbward supports two authentication methods: **API tokens** (simple, self-hosted) and **OIDC** (SSO with your identity provider). You can use either or both.

## Authentication

dbward supports two authentication methods that work simultaneously:

- **API Tokens** (`dbw_...`): Always accepted. Used by CLI, agents, and CI/CD.
- **OIDC JWTs** (`eyJ...`): Accepted when `[auth.oidc]` is configured and a Team license is active.

When `[auth.oidc]` is present, both methods are accepted. When absent, only API tokens work.

---

## API Tokens

### Creating tokens

```bash
# Via CLI
dbward token create --subject alice --scope-roles developer
dbward token create --subject bob --scope-roles developer,dba --expires 90d
dbward token create --subject prod-agent --subject-type agent --no-scope-ceiling
```

```bash
# Via REST API (requires token.write permission)
curl -X POST http://localhost:3000/api/tokens \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "subject_id": "bob",
    "subject_type": "user",
    "scope_ceiling": {"roles": ["developer", "dba"]},
    "name": "Bob CI token",
    "expires_at": "2026-09-01T00:00:00Z"
  }'
```

### Token options

| Field | Type | Description |
|-------|------|-------------|
| `subject_id` | string | **Required.** User or service identifier. |
| `subject_type` | string | **Required.** `user` or `agent`. |
| `scope_ceiling` | object | Max roles this token can activate. Format: `{"roles": ["role1", "role2"]}`. Effective roles = intersection of `scope_ceiling.roles` and the user's assigned roles (direct + group-derived). Set `null` for agent tokens (`--no-scope-ceiling`). **Optional** (auto-derived from resolved roles when omitted) for `user` tokens. |
| `name` | string | Human-readable label. |
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

### Role resolution

Tokens do not embed roles directly. The server resolves roles dynamically at request time:

1. **Direct roles:** Roles assigned to the user via `dbward user add --role` or `dbward user update --role`
2. **Group-derived roles:** Roles inherited from group membership (`[[auth.groups]]` with `roles` field in config)
3. **Default role:** Falls back to `[auth].default_role` if no roles found

The token's `scope_ceiling` intersects with the resolved roles to produce effective permissions.

For details on roles and permissions, see [Authorization Reference](../reference/authorization.md).

### Inspecting tokens

Check a token's current effective permissions:

```bash
dbward token inspect <ID>
```

```bash
# Via REST API (owner or token.write permission)
curl http://localhost:3000/api/tokens/$TOKEN_ID/inspect \
  -H "Authorization: Bearer $MY_TOKEN"
```

---

## OIDC (SSO) (Team)

### Server configuration

```toml
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

## User management

### CLI-managed users

Users are managed via the `dbward user` CLI commands:

```bash
# Add a user with a role
dbward user add alice --role developer

# Add a user to a group (inherits group roles)
dbward user add bob --role dba --group backend-team

# Suspend a user (revokes tokens, cancels pending requests)
dbward user suspend alice

# Reactivate
dbward user activate alice

# Remove entirely
dbward user rm alice
```

Roles are assigned directly to users via `dbward user add --role` or inherited from group membership (`groups.roles` in config).

### OIDC users

OIDC users are created automatically on first login with `source = "oidc"`. To disable an OIDC user:

1. **CLI suspend**: `dbward user suspend <id>` — immediately blocks all requests (the server checks `is_suspended` on every request, even with a valid JWT).
2. **IdP-side disable**: Prevents new JWT issuance. Existing JWTs are still checked against `is_suspended` per-request, so suspend is effective regardless of JWT lifetime.

### API suspend vs CLI suspend

| Method | Effect | Persistence |
|--------|--------|-------------|
| `POST /api/users/{id}/suspend` | Immediate suspend + revoke | Persistent in DB |
| `dbward user suspend <id>` | Immediate suspend + revoke | Persistent in DB |

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

---

## Agent authentication

Agents use API tokens with `subject_type = "agent"` and `--no-scope-ceiling`. Agents always resolve to the `agent-default` role regardless of ceiling:

```bash
dbward token create --subject prod-agent --subject-type agent --no-scope-ceiling
```

The `--no-scope-ceiling` flag removes the scope ceiling restriction, allowing the agent token to activate all roles assigned to the agent user. This is the recommended setup for agents since their permissions are fully controlled via user roles.

> **Note:** `--no-scope-ceiling` conflicts with `--scope-roles` — they cannot be used together.

When [auth.oidc] is configured, both API tokens and OIDC JWTs are accepted. Agents always use API tokens.


---

## Security recommendations

1. **Use TTL on all tokens** — Set `expires_at` to 90 days max. Rotate before expiry.
2. **Use OIDC for humans** — Avoid sharing long-lived tokens between team members.
3. **Separate agent tokens** — One token per agent. Revoke individually if compromised.
4. **Short JWT lifetime** — Configure your IdP to issue tokens with 5–15 minute expiry.
5. **Configure [auth.oidc]** — OIDC for humans, API tokens for agents. Best of both worlds.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `401 invalid token` | Token revoked or wrong | Check `dbward token list` |
| `401 token expired` | TTL exceeded | Create a new token |
| `401 OIDC not configured` | JWT sent but [auth.oidc] not configured | Add [auth.oidc] section to server.toml |
| `JWT verification failed` | Wrong issuer/audience/expired | Check `issuer` and `client_id` match IdP |
| JWKS fetch timeout | Server can't reach IdP | Check network, or set `jwks_uri` override |

## See also

- [Server setup](../deployment/server.md) — Full server configuration
- [Workflows](policies/workflows.md) — Group-based approval rules
- [Agent setup](../deployment/agent.md) — Agent token configuration
