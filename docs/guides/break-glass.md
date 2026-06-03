---
title: Break-Glass (Emergency Bypass)
description: Bypass approval workflows in emergencies
---

# Break-Glass (Emergency Bypass)

Break-glass allows authorized users to bypass the normal approval workflow in emergencies. The operation executes immediately but is heavily audited.

## Usage

```bash
dbward execute --emergency --reason "Production outage: fixing corrupted session data" \
  "DELETE FROM sessions WHERE user_id = 'broken_account'"
```

Both `--emergency` and `--reason` are required.

## Requirements

| Requirement | Detail |
|-------------|--------|
| Permission | User must have `request.break_glass` (admin role by default) |
| Reason | `--reason` is mandatory — explains why normal workflow was bypassed |
| Channel | CLI and API only — **not available via MCP** |

## What happens

1. SQL is classified and reviewed normally
2. Workflow lookup is skipped
3. Request status is set to `BreakGlass` (immediately dispatchable)
4. Agent picks up and executes the operation
5. All audit events are tagged with emergency context

## Audit trail

Break-glass creates enhanced audit records:

- Event type: `break_glass`
- Includes: user, reason, SQL, result, timestamp
- Webhook notification fires with 🚨 indicator
- Prometheus metric: `dbward_break_glass_total` incremented

## Why MCP is blocked

AI assistants cannot use break-glass because:
- Emergency access requires explicit human intent
- AI-generated reasons could mask unauthorized access
- The audit trail must reflect a conscious human decision

If you need to execute emergency SQL while in an AI session, switch to a terminal and use the CLI directly.

## Configuration

Break-glass permission is granted via roles. By default, only `admin` has it:

```toml
[[auth.roles]]
name = "oncall"
permissions = ["request.break_glass", "request.create", "request.view"]
```

## Limitations

- DDL operations (DROP, GRANT, REVOKE) are still blocked even with `--emergency` (see [SQL Safety](../reference/sql-safety.md))
- Break-glass does not bypass SQL classification or review — it only bypasses the approval step
- Results are still stored and access-controlled normally

## See also

- [Workflows](policies/workflows.md) — normal approval flow
- [Authorization](../reference/authorization.md) — permission system
- [Security Checklist](../security/checklist.md) — restricting break-glass access
