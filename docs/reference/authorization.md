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

Groups are named collections of users, used as approvers in workflow steps:

```toml
[[auth.groups]]
name = "backend-team"
members = ["alice", "bob", "charlie"]

[[auth.groups]]
name = "dba-team"
members = ["dave", "eve"]
```

Groups are referenced in workflows:

```toml
[[workflows.steps.approvers]]
group = "dba-team"
min = 1
```

## Role bindings

Bind roles to users or groups. **Required** for API token authentication — tokens without a matching binding (and no `default_role`) are rejected.

```toml
[[auth.role_bindings]]
role = "dba"
subjects = ["alice", "dave"]
groups = ["dba-team"]
```

All members of bound groups inherit the role. `subjects` are raw subject IDs (not `user:` prefixed).

## Default role

Assign a role to all authenticated users who don't have an explicit binding:

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
