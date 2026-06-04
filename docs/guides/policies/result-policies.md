---
title: Result Policies
description: Control how query results are stored, delivered, and accessed
---

# Result Policies

Result policies control what happens to query results after execution — how long they're kept, how they're delivered, and who can access them.

## Configuration

Result policies are managed via the REST API:

```bash
# Create a result policy
curl -X POST http://localhost:3000/api/result-policies \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "database": "app",
    "environment": "production",
    "retention_days": 7,
    "delivery_mode": "both",
    "access": ["role:admin", "role:developer"]
  }'
```

## Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `database` | String | — | Database scope (or `*` for all) |
| `environment` | String | — | Environment scope (or `*` for all) |
| `retention_days` | Integer | 30 | Days to keep stored results |
| `delivery_mode` | String | `"both"` | How results are delivered |
| `access` | String[] | `[]` | Selectors for who can access results |

## Delivery modes

| Mode | Behavior |
|------|----------|
| `both` | Stream result to client AND store on server |
| `store_only` | Store result but don't stream (client fetches later) |
| `stream` | Stream to client but don't persist on server |

## Access control

The `access` field uses [selectors](../../reference/authorization.md) to define who can retrieve stored results:

```json
{
  "access": [
    "role:admin",
    "group:backend-team",
    "user:alice",
    "requester"
  ]
}
```

`"requester"` means the user who submitted the original request.

## Global retention defaults

Separate from per-policy retention, the server has global defaults in `[retention]`:

```toml
[retention]
request_ttl_days = 90    # How long request records are kept
audit_ttl_days = 365     # How long audit log entries are kept
result_ttl_days = 30     # Default result retention (overridden by policy)
approval_ttl_secs = 86400  # Seconds before approved requests expire
```

## Result sharing

Users can share results with others using `--share-with` at execution time:

```bash
dbward execute --share-with "group:backend-team" "SELECT * FROM metrics"
```

This creates access grants in addition to the policy's default `access` list.

## See also

- [Policies Overview](overview.md)
- [Executing Queries](../executing-queries.md) — result format and sharing options
- [Configuration Reference](../../reference/configuration.md#retention) — global retention settings
