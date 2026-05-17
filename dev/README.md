# Development Guide

## Prerequisites

- Rust 1.88+ (see `rust-toolchain.toml`)
- Docker & Docker Compose v2
- PostgreSQL client (`psql`) for E2E debugging

## Quick Start

```bash
# Start all services (server + agent + postgres + keycloak)
docker compose -f dev/compose.yml up -d --build

# Run E2E tests
./dev/e2e/lifecycle.sh
```

## Working with Git Worktrees

When using multiple worktrees (`git worktree add`), Docker Compose will create conflicting containers because the default project name is derived from the directory name.

### Fix: Set `COMPOSE_PROJECT_NAME` per worktree

```bash
# In worktree A (e.g., ~/Products/dbward/dbward)
export COMPOSE_PROJECT_NAME=dbward-main

# In worktree B (e.g., ~/Products/dbward/dbward-test-overhaul)
export COMPOSE_PROJECT_NAME=dbward-test

# Then run compose normally
docker compose -f dev/compose.yml up -d --build
```

Or create a `.env` file in the worktree root:

```bash
echo "COMPOSE_PROJECT_NAME=dbward-$(basename $(pwd))" > .env
```

This ensures each worktree gets isolated containers, networks, and volumes.

### Cleanup

```bash
# Stop and remove containers for current project
docker compose -f dev/compose.yml down -v

# List all dbward-related containers
docker ps -a --filter "name=dbward"
```

## Running Tests

```bash
# Unit + integration tests
cargo test --workspace

# With coverage
./dev/scripts/coverage.sh

# E2E (requires Docker services running)
./dev/e2e/lifecycle.sh
./dev/e2e/agent.sh
./dev/e2e/security.sh
# ... or all at once:
for f in dev/e2e/*.sh; do [ "$f" != "dev/e2e/helpers.sh" ] && bash "$f"; done
```

## Configuration

Dev config files are in `dev/config/`:
- `server.toml` — server configuration
- `agent.toml` — agent configuration
- `cli.toml` — CLI configuration

Tokens are created dynamically via `create_token` helper in E2E scripts.
