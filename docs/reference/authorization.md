---
title: Authorization Reference
description: Roles, groups, permissions, and access control in dbward
---

# Authorization Reference

dbward uses role-based access control (RBAC) with database and environment scoping.

## Built-in roles

| Role | Permissions | Scope |
|------|-------------|-------|
| `admin` | `*` (all) | All databases, all environments |
| `developer` | `request.create`, `request.create_select`, `request.view`, `request.cancel`, `request.resume`, `result.view`, `token.revoke_own` | All |
| `readonly` | `request.create_select`, `request.view`, `result.view` | All |
| `agent-default` | `agent.poll`, `agent.claim`, `agent.heartbeat`, `agent.submit_result` | All |

Built-in roles cannot be redefined in config.

## Custom roles

```toml
[[auth.roles]]
name = "dba"
permissions = ["request.create", "request.approve", "request.view", "result.view", "audit.view"]
databases = ["app", "analytics"]       # Scope to specific databases (empty = all)
environments = ["production", "staging"]  # Scope to environments (empty = all)
```

Custom role permissions only apply within the specified `databases` and `environments` scope. If both are empty, the role applies globally.

## Groups

Groups are named collections of users with associated roles. Members inherit the group's roles. Groups are also used as approvers in workflow steps:

```toml
[[auth.groups]]
name = "backend-team"
roles = ["developer"]

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
dbward user update alice --role admin
```

Roles are stored in the user record (`roles_json` column).

### Group-derived roles

Users inherit roles from their group memberships. Groups define their roles in config:

```toml
[[auth.groups]]
name = "dba-team"
roles = ["dba", "developer"]
```

When a user belongs to `dba-team`, they automatically receive the `dba` and `developer` roles.

### Effective roles

A user's effective roles = direct roles ∪ group-derived roles. For token authentication, effective roles are further intersected with the token's `scope_ceiling`.

## Default role

Assign a role to all authenticated users who don't have an explicit role (neither direct nor group-derived):

```toml
[auth]
default_role = "developer"
```

## Permissions

### Request permissions

| Permission | Description |
|-----------|-------------|
| `request.create` | Create requests (DML, migrations) |
| `request.create_select` | Create SELECT-only requests |
| `request.approve` | Approve requests |
| `request.resume` | Resume approved requests |
| `request.cancel` | Cancel own requests |
| `request.view` | View requests and status |
| `request.break_glass` | Use emergency bypass |
| `request.break_glass_ddl` | Allow DDL in emergency mode (requires `request.break_glass`) |

### Result permissions

| Permission | Description |
|-----------|-------------|
| `result.view` | View query results |

### Audit permissions

| Permission | Description |
|-----------|-------------|
| `audit.view` | View own audit events |
| `audit.view_all` | View all audit events |

### Management permissions

| Permission | Description |
|-----------|-------------|
| `workflow.manage` | Create/delete workflows |
| `policy.manage` | Manage execution/result/notification policies |
| `role.manage` | Create/delete custom roles via API |
| `webhook.manage` | Create/update/delete webhooks |
| `user.manage` | Suspend/activate users |
| `token.write` | Create/revoke any token |
| `token.revoke_own` | Revoke own tokens |
| `metrics.view` | Access /metrics endpoint |

### Agent permissions

| Permission | Description |
|-----------|-------------|
| `agent.poll` | Poll for jobs |
| `agent.claim` | Claim jobs |
| `agent.heartbeat` | Send heartbeats |
| `agent.submit_result` | Submit execution results |

### Wildcard

| Permission | Description |
|-----------|-------------|
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
role = "developer"

[[auth.oidc.role_mappings]]
claim = "groups"
value = "platform"
role = "admin"
```

## See also

- [Authentication](../guides/authentication.md) — OIDC and token setup
- [Workflows](../guides/policies/workflows.md) — using roles/groups as approvers
- [Configuration Reference](configuration.md#auth) — full auth config fields
