---
title: Authorization Reference
description: Roles, groups, permissions, and access control in dbward
---

# Authorization Reference

dbward uses role-based access control (RBAC) with database and environment scoping.

## Built-in roles

| Role | Permissions | Scope |
|------|-------------|-------|
| `admin` | `workflow.read`, `workflow.write`, `policy.write`, `role.write`, `user.read`, `user.write`, `webhook.write`, `token.create`, `token.revoke:any`, `token.list`, `token.create_agent`, `token.reissue`, `audit.read`, `metrics.view` | All |
| `requester` | `request.dml`, `request.query`, `request.view:own`, `request.cancel:own`, `request.resume:own`, `request.preflight`, `request.preflight_explain`, `result.view:own`, `schema.read`, `workflow.read`, `token.create`, `token.revoke:own` | All |
| `approver` | `request.view:own`, `result.view:own`, `schema.read`, `workflow.read`, `token.create`, `token.revoke:own` | All |
| `operator` | `request.view:any`, `request.cancel:any`, `request.resume:any`, `request.break_glass_query`, `request.break_glass_dml`, `request.break_glass_ddl`, `result.view:any`, `schema.read`, `audit.read`, `metrics.view`, `workflow.read`, `token.create`, `token.revoke:own` | All |
| `agent-default` | `agent.operate` | All |

Built-in roles cannot be redefined in config.

## Custom roles

```toml
[[auth.roles]]
name = "dba"
permissions = ["request.dml", "request.view", "result.view", "audit.read"]
databases = ["app", "analytics"]       # Scope to specific databases (empty = all)
environments = ["production", "staging"]  # Scope to environments (empty = all)
```

Custom role permissions only apply within the specified `databases` and `environments` scope. If both are empty, the role applies globally.

## Groups

Groups are named collections of users with associated roles. Members inherit the group's roles. Groups are also used as approvers in workflow steps:

```toml
[[auth.groups]]
name = "backend-team"
roles = ["requester"]

[[auth.groups]]
name = "dba-team"
roles = ["dba"]
```

Groups are referenced in workflows:

```toml
[[workflows.steps.approvers]]
group = "dba-team"
min = 1
```

Users are added to groups via `dbward user add --group` or `dbward user update --add-group`.

## Role assignment

Roles are assigned to users in two ways:

### Direct assignment

Assign roles directly when creating or updating a user:

```bash
dbward user add alice --role dba
dbward user update alice --add-role admin
```

Roles are stored in the user record (`roles_json` column).

### Group-derived roles

Users inherit roles from their group memberships. Groups define their roles in config:

```toml
[[auth.groups]]
name = "dba-team"
roles = ["dba", "requester"]
```

When a user belongs to `dba-team`, they automatically receive the `dba` and `requester` roles.

### Effective roles

A user's effective roles = direct roles ∪ group-derived roles. For token authentication, effective roles are further intersected with the token's `scope_ceiling`.

## Default role

Assign a role to all authenticated users who don't have an explicit role (neither direct nor group-derived):

```toml
[auth]
default_role = "requester"
```

## Permissions

### Request permissions

| Permission | Description |
|-----------|-------------|
| `request.dml` | Create requests (DML, DDL, migrations) |
| `request.query` | Create SELECT-only requests |
| `request.resume` | Resume approved requests |
| `request.cancel` | Cancel own requests |
| `request.view` | View requests and status |
| `request.break_glass_dml` | Use emergency bypass (DML) |
| `request.break_glass_ddl` | Allow DDL in emergency mode (requires `request.break_glass_dml`) |
| `request.preflight` | Run preflight SQL analysis |
| `request.preflight_explain` | Run preflight with EXPLAIN |

### Result permissions

| Permission | Description |
|-----------|-------------|
| `result.view` | View query results |

### Audit permissions

| Permission | Description |
|-----------|-------------|
| `audit.read` | View audit events |

### Workflow and policy permissions

| Permission | Description |
|-----------|-------------|
| `workflow.read` | View workflow definitions |
| `workflow.write` | Create/update/delete workflows |
| `policy.write` | Manage execution/result/notification policies |
| `role.write` | Create/delete custom roles via API |
| `webhook.write` | Create/update/delete webhooks |

### User and token permissions

| Permission | Description |
|-----------|-------------|
| `user.write` | Add, update, suspend, activate, and delete users |
| `user.read` | List and view users and groups |
| `token.create` | Create tokens for yourself |
| `token.revoke` | Revoke own tokens |
| `token.list` | List all tokens |
| `token.create_agent` | Create agent tokens |
| `token.reissue` | Reissue initial tokens for other users |

### Agent permissions

| Permission | Description |
|-----------|-------------|
| `agent.operate` | Poll, claim, heartbeat, and submit results |

### Other

| Permission | Description |
|-----------|-------------|
| `metrics.view` | Access /metrics endpoint |
| `*` | All permissions (admin only) |

## Selectors

Selectors identify principals in workflow approvers and result access:

| Format | Example | Matches |
|--------|---------|---------|
| `role:<name>` | `role:dba` | Users with the named role |
| `group:<name>` | `group:backend-team` | Members of the named group |
| `user:<subject>` | `user:alice` | Specific user by subject ID |
| `requester` | `requester` | The user who created the request |

## OIDC role mappings

Map OIDC claims to dbward roles:

```toml
[[auth.oidc.role_mappings]]
claim = "groups"
value = "engineering"
role = "requester"

[[auth.oidc.role_mappings]]
claim = "groups"
value = "platform"
role = "admin"
```

OIDC users are auto-provisioned on first login (JIT). Their roles are resolved from OIDC role mappings + group membership + `default_role`.

## See also

- [Authentication](../guides/authentication.md) — OIDC and token setup
- [Workflows](../guides/policies/workflows.md) — using roles/groups as approvers
- [Configuration Reference](configuration.md#auth) — full auth config fields
