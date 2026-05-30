---
title: "ADR-002: Approver Scope"
description: Designated approver scope behavior
---
# ADR-002 Addendum: Designated Approver Scope Behavior

## Context

When a workflow step designates approvers via role/group/user selectors (e.g., `role:dba`),
the authorization check (`authorize_scoped`) is bypassed for designated approvers.

This means a user with `role:dba` (even if their role definition limits `databases: ["app"]`)
can approve/reject requests for **any** database, as long as the workflow step lists their role.

## Decision

This is **intentional by design** (ADR-002: "approver designation = permission grant").

The rationale is:
1. Workflow configuration is the source of truth for "who can approve what"
2. If an admin configures a workflow step to require `role:dba` approval for `database: *`,
   they are explicitly granting approval authority to all DBA role holders for that workflow
3. The role's `databases` scope restricts what the user can *do* (submit requests, view results),
   not what they can *approve*

## Implications for Operators

- **Workflow authors must be careful**: Adding a role to a workflow step grants all members of
  that role approval authority for the workflow's database scope
- **Role database scope**: The `databases` field on a role restricts operational permissions
  (submit, view, cancel), NOT approval permissions
- **Recommendation**: Use user-specific selectors (`user:alice@example.com`) or narrow groups
  for workflows that span multiple databases, if you want to restrict approval by database

## Security Note

This design trades granularity for simplicity. If per-database approval scoping is needed,
create separate workflows per database rather than relying on role database restrictions.
