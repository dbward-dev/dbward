# Workflows

Workflows define who must approve a database operation before it executes. Configure them in `dbward-server.toml`.

## Basic concepts

- **No workflow match = auto-approve** (the operation executes immediately)
- **Workflow match = approval required** (one or more people must approve)
- Workflows are scoped by **database × environment × operation**

## Quick examples

### Require one admin approval for production

```toml
[[workflows]]
database = "*"
environment = "production"

[[workflows.steps]]
type = "approval"
[[workflows.steps.approvers]]
role = "admin"
min = 1
```

### Auto-approve development (no steps)

```toml
[[workflows]]
database = "*"
environment = "development"
# No steps = auto-approve
```

### Require DBA team approval (group-based)

```toml
[[workflows]]
database = "primary"
environment = "production"

[[workflows.steps]]
type = "approval"
[[workflows.steps.approvers]]
group = "dba-team"
min = 1
```

Anyone in the IdP `dba-team` group can approve. See [Authentication](../deployment/authentication.md) for group setup.

---

## Multi-step approval

Steps execute in order. Step 2 only becomes active after step 1 is satisfied.

```toml
[[workflows]]
database = "primary"
environment = "production"
operations = ["execute_query"]

# Step 1: Team lead review
[[workflows.steps]]
type = "approval"
[[workflows.steps.approvers]]
role = "team-lead"
min = 1

# Step 2: DBA approval
[[workflows.steps]]
type = "approval"
[[workflows.steps.approvers]]
group = "dba-team"
min = 1
```

Flow:
```
Developer submits → Team lead approves (step 1) → DBA approves (step 2) → Executes
```

## Multiple approvers per step

### All groups must be satisfied (`mode = "all"`, default)

```toml
[[workflows.steps]]
type = "approval"
mode = "all"
[[workflows.steps.approvers]]
role = "team-lead"
min = 1
[[workflows.steps.approvers]]
group = "dba-team"
min = 1
```

Requires **both** a team-lead AND a dba-team member to approve.

### Any group is sufficient (`mode = "any"`)

```toml
[[workflows.steps]]
type = "approval"
mode = "any"
[[workflows.steps.approvers]]
role = "team-lead"
min = 1
[[workflows.steps.approvers]]
group = "dba-team"
min = 1
```

Requires **either** a team-lead OR a dba-team member to approve.

### Require multiple people

```toml
[[workflows.steps]]
type = "approval"
[[workflows.steps.approvers]]
role = "dba"
min = 2    # Two DBAs must approve
```

---

## Workflow options

```toml
[[workflows]]
database = "primary"
environment = "production"
operations = ["execute_query"]       # Filter by operation (empty = all)
require_reason = true                # Force users to provide --reason (default: false)
allow_self_approve = false           # Requester cannot approve own request (default: false)
allow_same_approver_across_steps = false  # Same person can't approve in multiple steps (default: false)
```

### `operations` filter

| Value | Matches |
|-------|---------|
| `[]` (empty/omitted) | All operations |
| `["execute_query"]` | Ad-hoc SQL only |
| `["migrate_up", "migrate_down"]` | Migrations only |

### `allow_self_approve`

- `false` (default): The person who submitted the request cannot approve it.
- `true`: Useful for small teams where the same person may need to submit and approve.

### `allow_same_approver_across_steps`

- `false` (default): A person who approved step 1 cannot approve step 2.
- `true`: Useful for small teams with limited personnel.

---

## Break-glass (emergency bypass)

For urgent situations, users can bypass the approval workflow entirely:

```bash
dbward execute --emergency --reason "incident #1234: DB connection pool exhausted" \
  "UPDATE pg_settings SET setting = '200' WHERE name = 'max_connections'"
```

Break-glass:
- Skips all approval steps
- Executes immediately
- Is **fully audited** (who, what, when, reason)
- Triggers a webhook notification (`break_glass` event)
- Is restricted to specific roles:

```toml
[auth]
break_glass_roles = ["admin", "developer"]  # Default: ["admin", "developer"]
```

---

## Matching rules

When a request comes in, dbward finds the most specific matching workflow:

**Priority order (most specific wins):**

1. `database + environment` (with matching `operations`)
2. `database + environment` (catchall operations)
3. `* + environment`
4. `database + *`
5. `* + *`

**No match = auto-approve.**

### Example

```toml
# Rule A: DML on production primary needs DBA
[[workflows]]
database = "primary"
environment = "production"
operations = ["execute_query"]
# ... steps ...

# Rule B: All production operations need admin
[[workflows]]
database = "*"
environment = "production"
# ... steps ...

# Rule C: Development is auto-approve
[[workflows]]
database = "*"
environment = "development"
```

| Request | Matches | Why |
|---------|---------|-----|
| `execute_query` on `primary` / `production` | Rule A | Most specific (database + env + operation) |
| `migrate_up` on `primary` / `production` | Rule B | Wildcard database, matching env |
| `execute_query` on `analytics` / `production` | Rule B | Wildcard database, matching env |
| `execute_query` on `primary` / `development` | Rule C | Development auto-approve |
| `execute_query` on `primary` / `staging` | None → auto-approve | No matching rule |

---

## Approval flow in practice

### CLI experience

```bash
# Submit
$ dbward execute "DELETE FROM sessions WHERE expired_at < now()"
⚠ Request req_a1b2 requires approval.
  Approvers: dba-team
Run: dbward request resume req_a1b2

# Check status
$ dbward request show req_a1b2
Request req_a1b2
  Status: pending
  Step: 1/2 (waiting for: dba-team × 1)
  Submitted by: alice@example.com
  SQL: DELETE FROM sessions WHERE expired_at < now()

# Approve (by someone in dba-team)
$ dbward request approve req_a1b2 --comment "Checked row count: ~500"

# Get result (by the submitter)
$ dbward request resume req_a1b2
✓ Dispatching req_a1b2...
  rows_affected: 487
```

### Webhook notifications

Configure Slack notifications to alert approvers:

```toml
[[webhooks]]
url = "https://hooks.slack.com/services/T.../B.../xxx"
events = ["request_created", "request_approved", "request_rejected", "request_completed", "break_glass"]
format = "slack"
```

When a request is created, the configured webhook fires with the request details, SQL preview, and approver information.

---

## Access policies

Restrict who can even submit requests to specific databases:

```toml
[[access_policies]]
database = "primary"
environment = "production"
allowed_roles = ["admin", "dba"]
allowed_groups = ["backend-team"]
```

Users not matching `allowed_roles` or `allowed_groups` will get a 403 when trying to create a request for this database/environment.

---

## Tips

- **Start simple:** One workflow rule for production, auto-approve for development.
- **Use groups over roles:** Groups come from your IdP and don't require dbward-specific configuration per user.
- **Require reason for production:** `require_reason = true` creates better audit trails.
- **Use `mode = "any"` for small teams:** Avoids blocking when specific approvers are unavailable.
- **Monitor with webhooks:** Get Slack notifications so approvers don't miss requests.

## Next steps

- [Authentication](../deployment/authentication.md) — Set up groups and role mappings
- [CI/CD](ci-cd.md) — Automate approvals in pipelines
- [Configuration Reference](../reference/configuration.md) — All workflow options
