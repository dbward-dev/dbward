---
title: "Quickstart: Try with Docker"
description: Run the full dbward stack with a test database in 5 minutes
---

# Quickstart: Try with Docker

Run server, agent, and PostgreSQL together. Experience the full approval flow without touching your own database.

**Prerequisites:** Docker and Docker Compose.

## 1. Clone and set up

```bash
git clone https://github.com/dbward-dev/dbward.git
cd dbward
./dev/scripts/dev-setup.sh
```

## 2. Start the stack

```bash
docker compose -f dev/compose.yml up -d
```

This starts:
- **PostgreSQL** — test database (`dbward_dev`)
- **dbward-server** — approval engine
- **dbward-agent** — connected to PostgreSQL

Wait for all services to become healthy (~15 seconds):

```bash
docker compose -f dev/compose.yml ps
```

## 3. Get your CLI token

The dev environment auto-generates tokens on first start:

```bash
# Admin token (can approve requests)
docker compose -f dev/compose.yml exec dbward-server cat /data/admin-token

# Developer token (can submit requests)
docker compose -f dev/compose.yml exec dbward-server cat /data/developer-token
```

Configure your CLI:

```bash
export DBWARD_SERVER_URL="http://localhost:3000"
export DBWARD_TOKEN="<dev-token from above>"
```

## 4. Submit a query

```bash
dbward execute "SELECT version()"
```

In the Docker dev environment, safe queries are auto-approved. You should see the result immediately.

## 5. Experience the approval flow

Submit something that requires approval:

```bash
dbward execute "DELETE FROM pg_catalog.pg_class WHERE 1=1"
```

This will be rejected by SQL safety review. Try a real table:

```bash
# Create a test table first
dbward execute "CREATE TABLE test_orders (id serial, amount int)"
dbward execute "INSERT INTO test_orders (amount) SELECT generate_series(1, 1000)"

# Now submit a DELETE — this requires approval in staging/production workflows
dbward execute --environment production "DELETE FROM test_orders WHERE amount < 500"
```

The request will show as `pending`. Approve it with the admin token:

```bash
export DBWARD_TOKEN="<admin-token>"
dbward request approve <request-id> --comment "Test cleanup"
```

Then resume execution (the original requester or any admin can do this):

```bash
dbward request resume <request-id>
```

## 6. Stop

```bash
docker compose -f dev/compose.yml down
```

Add `-v` to also remove the database volume.

## Next steps

- [Connect your own database](quickstart-local) — use dbward with your real DB
- [Workflows Guide](guides/workflows) — customize approval policies
- [Deployment Overview](deployment/overview) — production architecture
