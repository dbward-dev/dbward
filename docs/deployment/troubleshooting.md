---
title: Troubleshooting
description: Common deployment issues and fixes
---

# Deployment Troubleshooting

## Agent not picking up jobs

**Symptoms:** Requests stay in `dispatched` status; agent logs show no activity.

**Causes:**

1. **Token mismatch** — The agent token doesn't match what the server expects.
   ```bash
   # Verify token is set
   echo $DBWARD_AGENT_TOKEN
   # Compare with server's agent-token file
   ```

2. **Capabilities mismatch** — The agent's configured scopes (database/environment pairs) don't match the request's `database` + `environment`.
   ```bash
   # Check agent logs for registered capabilities
   grep "capabilities" /var/log/dbward-agent.log
   ```

3. **Network** — The agent cannot reach the server.
   ```bash
   curl http://server-host:3000/health
   ```

**Fix:** Ensure the agent token is correct, database/environment names match the server config, and the agent can reach the server on port 3000.

## Lease expired / execution_lost

**Symptoms:** Job shows `execution_lost` status after timeout.

**Causes:**

1. **Statement timeout too short** — The query takes longer than `statement_timeout_secs` (default: 30s). Especially common with DDL/migrations.
2. **Agent crash** — The agent died mid-execution. Check logs for panics or OOM kills.
3. **Network interruption** — Heartbeats failed to reach the server.

**Fix:**
- Increase `statement_timeout_secs` in agent config or use `[[execution_policies]]` on the server for specific environments.
- For migrations, set a longer timeout via execution policies.
- Check container/process health and resource limits.

## "no matching workflow" error

**Symptoms:** Request immediately rejected with "no matching workflow".

**Cause:** The `database` + `environment` combination in the request doesn't match any `[[workflows]]` entry in the server config. dbward is fail-closed: if no workflow matches, the request is rejected.

**Fix:** Add a `[[workflows]]` section for the target database/environment pair:

```toml
[[workflows]]
database = "app"
environment = "staging"

[[workflows.steps]]
type = "approval"
[[workflows.steps.approvers]]
role = "admin"
min = 1
```

## SQLite locked

**Symptoms:** Server returns 500 errors with "database is locked" in logs.

**Cause:** Multiple server processes are writing to the same SQLite file. dbward-server must run as a single replica.

**Fix:**
- Ensure only one server instance uses the same `state_dir` / PVC.
- On Kubernetes, use `strategy: Recreate` (not `RollingUpdate`) for the server Deployment.
- On ECS, set desired count to 1 for the server service.

## OIDC validation errors

**Symptoms:** Login fails with "invalid token" or "issuer mismatch".

**Causes:**

1. **Issuer mismatch** — The `issuer` in server config doesn't match the `iss` claim in the JWT.
2. **Audience mismatch** — The `audience` in server config doesn't match the `aud` claim.
3. **Clock skew** — Server time is off by more than the allowed leeway.

**Fix:**
```bash
# Decode a token to check claims
echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | jq .

# Verify issuer matches config
grep issuer /etc/dbward/server.toml
```

Ensure `[auth.oidc]` issuer and audience match your identity provider's configuration exactly.
