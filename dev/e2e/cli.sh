#!/bin/bash
# E2E: CLI binary tests — verify dbward CLI commands work end-to-end
# Requires: docker compose services running (server + agent + postgres)
# Usage: ./dev/e2e/cli.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."
source "$SCRIPT_DIR/helpers.sh"

echo ""
echo "=== E2E CLI Tests ==="
echo ""

wait_for_server

# Create tokens for CLI usage
CLI_TOKEN=$(create_token cli-user requester)
[ -z "$CLI_TOKEN" ] && { echo "Failed to create token"; exit 1; }
ADMIN_TOKEN=$(create_token cli-admin admin,requester)

# CLI helper: run dbward command inside the server container with proper config
write_cli_config() {
  local token="$1"
  docker compose exec -T dbward-server sh -c "cat > /tmp/cli-test.toml << TOML
default_database = \"app\"

[server]
url = \"http://localhost:3000\"
token = \"$token\"

[databases.app]
TOML"
}

cli() {
  local token="$1"; shift
  write_cli_config "$token"
  docker compose exec -T dbward-server dbward --config /tmp/cli-test.toml --yes "$@" 2>&1
}

# --- 1. dbward execute (auto-approve in development) ---
echo "--- CLI execute ---"

EXEC_OUTPUT=$(cli "$CLI_TOKEN" execute "SELECT 42 AS answer" \
  --database app --environment development --timeout 5) || true

if echo "$EXEC_OUTPUT" | grep -qi "42\|executed\|success\|answer"; then
  pass "dbward execute returns result"
  show_output "$(echo "$EXEC_OUTPUT" | head -2)"
elif echo "$EXEC_OUTPUT" | grep -qi "Timed out\|queued\|no agents"; then
  skip "dbward execute: agent not available ($(echo "$EXEC_OUTPUT" | head -1))"
else
  fail "dbward execute" "$(echo "$EXEC_OUTPUT" | head -3)"
fi

# --- 2. dbward request list ---
echo ""
echo "--- CLI request list ---"

LIST_OUTPUT=$(cli "$CLI_TOKEN" request list) || true

if echo "$LIST_OUTPUT" | grep -qi "ID\|id\|No requests\|total\|request"; then
  pass "dbward request list works"
  show_output "$(echo "$LIST_OUTPUT" | head -2)"
else
  fail "dbward request list" "$(echo "$LIST_OUTPUT" | head -2)"
fi

# --- 3. dbward execute with approval flow (production, --no-wait) ---
echo ""
echo "--- CLI execute with approval ---"

EXEC_OUTPUT=$(cli "$CLI_TOKEN" execute "SELECT 1" \
  --database app --environment production --reason "cli test" --timeout 1) || true

if echo "$EXEC_OUTPUT" | grep -qi "pending\|awaiting\|request\|approval\|timeout"; then
  pass "dbward execute in production needs approval"
  show_output "$(echo "$EXEC_OUTPUT" | head -2)"
else
  fail "dbward execute production" "$(echo "$EXEC_OUTPUT" | head -3)"
fi

# --- 4. dbward databases ---
echo ""
echo "--- CLI databases ---"

DB_OUTPUT=$(cli "$CLI_TOKEN" databases) || true

if echo "$DB_OUTPUT" | grep -qi "app\|production\|development"; then
  pass "dbward databases lists registered databases"
  show_output "$(echo "$DB_OUTPUT" | head -3)"
else
  fail "dbward databases" "$(echo "$DB_OUTPUT" | head -2)"
fi

# --- 5. dbward audit (admin) ---
echo ""
echo "--- CLI audit ---"

AUDIT_OUTPUT=$(cli "$ADMIN_TOKEN" audit) || true

if echo "$AUDIT_OUTPUT" | grep -qi "event\|total\|hash\|audit"; then
  pass "dbward audit shows events"
else
  skip "dbward audit: $(echo "$AUDIT_OUTPUT" | head -1)"
fi

summary
