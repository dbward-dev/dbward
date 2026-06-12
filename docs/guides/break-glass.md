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

### DDL bypass (schema repair)

To execute DDL statements (DROP TABLE, CREATE SEQUENCE, etc.) in emergencies, add `--allow-ddl`:

```bash
dbward execute --emergency --allow-ddl --reason "Rebuild corrupted table" \
  "DROP TABLE broken_cache; CREATE TABLE broken_cache (id INT PRIMARY KEY, data TEXT)"
```

`--allow-ddl` requires `--emergency` and the additional `request.break_glass_ddl` permission.

**Bypassable:** DROP TABLE/VIEW/INDEX/SEQUENCE, CREATE SEQUENCE, TRUNCATE, plus CREATE TABLE/VIEW/INDEX and ALTER TABLE in mixed repair batches.

**Never bypassable:** GRANT, REVOKE, CREATE ROLE/FUNCTION/DATABASE/SCHEMA, BEGIN/COMMIT, SET ROLE, LOAD DATA.

## Requirements

| Requirement | Detail |
|-------------|--------|
| Permission | User must have `request.break_glass` (admin role by default) |
| Permission (DDL) | Additionally requires `request.break_glass_ddl` when using `--allow-ddl` |
| Reason | `--reason` is mandatory — explains why normal workflow was bypassed |
| Channel | CLI and API only — **not available via MCP** |

## What happens

1. SQL is classified and reviewed normally
2. If `--allow-ddl`: classifier rejection is bypassed for eligible DDL; reviewer blocks on DDL rules are bypassed
3. Workflow lookup is skipped
4. Request status is set to `BreakGlass` (immediately dispatchable)
5. Agent picks up and executes the operation
6. All audit events are tagged with emergency context

## Audit trail

Break-glass creates enhanced audit records:

- Event type: `break_glass`
- Includes: user, reason, SQL, result, timestamp
- Webhook notification fires with 🚨 indicator
- Prometheus metric: `dbward_break_glass_total` incremented

When `--allow-ddl` is used, an additional `ddl_via_break_glass` audit event is recorded with:
- Which safety layer was bypassed (classifier, reviewer, or both)
- Statement count
- Redacted SQL (literals replaced with `?`)

Prometheus metrics for DDL bypass:
- `dbward_break_glass_ddl_attempted_total` — bypass was requested
- `dbward_break_glass_ddl_allowed_total` — bypass succeeded
- `dbward_break_glass_ddl_denied_total` — bypass was denied (non-bypassable statement)
- `dbward_break_glass_audit_failure_total` — audit write failed after bypass

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

To also allow DDL bypass in emergencies:

```toml
[[auth.roles]]
name = "oncall-senior"
permissions = ["request.break_glass", "request.break_glass_ddl", "request.create", "request.view"]
```

## Limitations

- Privilege DDL (GRANT, REVOKE, CREATE ROLE/FUNCTION/DATABASE) is **always blocked** — even with `--emergency --allow-ddl`
- Transaction control (BEGIN, COMMIT, ROLLBACK) is always blocked
- Break-glass does not bypass SQL classification or review for DML safety rules (e.g., DELETE without WHERE)
- `--allow-ddl` bypasses classifier rejection and reviewer blocking **only for schema-repair DDL**
- Results are still stored and access-controlled normally
- MCP channel cannot use break-glass or `--allow-ddl`

## See also

- [Workflows](policies/workflows.md) — normal approval flow
- [Authorization](../reference/authorization.md) — permission system
- [Security Checklist](../security/checklist.md) — restricting break-glass access
