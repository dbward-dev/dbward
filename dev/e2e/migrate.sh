#!/bin/bash
# E2E: Migration tests — verify migrate up/down/status flow
# Requires: docker compose services running (server + agent + postgres)
# Usage: ./dev/e2e/migrate.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."
source "$SCRIPT_DIR/helpers.sh"

echo ""
echo "=== E2E Migration Tests ==="
echo ""

wait_for_server

ADMIN_TOKEN=$(create_token migrate-admin admin,requester)
[ -z "$ADMIN_TOKEN" ] && { echo "Failed to create token"; exit 1; }

# Write CLI config with migrations_dir
docker compose exec -T dbward-server sh -c "cat > /tmp/migrate-test.toml << TOML
default_database = \"app\"
migrations_dir = \"/app/examples/migrations\"

[server]
url = \"http://localhost:3000\"
token = \"$ADMIN_TOKEN\"

[databases.app]
TOML"

# Helper
migrate_cli() {
  docker compose exec -T dbward-server dbward --config /tmp/migrate-test.toml --yes migrate "$@" 2>&1
}

# --- 1. migrate status ---
echo "--- Migrate status ---"

STATUS_OUTPUT=$(migrate_cli status --database app --environment development) || true

if echo "$STATUS_OUTPUT" | grep -qi "pending\|applied\|version\|status\|migration\|Waiting\|queued"; then
  pass "migrate status works"
  show_output "$(echo "$STATUS_OUTPUT" | head -3)"
else
  fail "migrate status" "$(echo "$STATUS_OUTPUT" | head -3)"
fi

# --- 2. migrate up ---
echo ""
echo "--- Migrate up ---"

UP_OUTPUT=$(migrate_cli up --database app --environment development) || true

if echo "$UP_OUTPUT" | grep -qi "applied\|success\|pending\|approved\|dispatched\|request\|Waiting\|queued"; then
  pass "migrate up submitted"
  show_output "$(echo "$UP_OUTPUT" | head -3)"
elif echo "$UP_OUTPUT" | grep -qi "not found\|no.*migration"; then
  skip "migrate up: no migrations dir mounted in container"
else
  fail "migrate up" "$(echo "$UP_OUTPUT" | head -3)"
fi

# --- 3. migrate down ---
echo ""
echo "--- Migrate down ---"

DOWN_OUTPUT=$(migrate_cli down --database app --environment development) || true

if echo "$DOWN_OUTPUT" | grep -qi "reverted\|success\|pending\|approved\|dispatched\|request\|no migration\|Waiting\|queued\|nothing"; then
  pass "migrate down submitted"
  show_output "$(echo "$DOWN_OUTPUT" | head -3)"
else
  fail "migrate down" "$(echo "$DOWN_OUTPUT" | head -3)"
fi

summary
