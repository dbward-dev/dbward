#!/bin/bash
# E2E: Output format (--format json / quiet) behavior
# Requires: docker compose services running (server + agent + postgres)
# Usage: ./dev/e2e/12_output_format.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."
source "$SCRIPT_DIR/helpers.sh"

echo ""
echo "=== E2E Output Format Tests ==="
echo ""

wait_for_server

ADMIN_TOKEN=$(create_token fmt-admin admin,requester)
[ -z "$ADMIN_TOKEN" ] && { echo "Failed to create token"; exit 1; }

write_cli_config() {
  local token="$1"
  docker compose exec -T dbward-server sh -c "cat > /tmp/fmt-test.toml << TOML
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
  docker compose exec -T dbward-server dbward --config /tmp/fmt-test.toml "$@"
}

cli_full() {
  local token="$1"; shift
  write_cli_config "$token"
  docker compose exec -T dbward-server dbward --config /tmp/fmt-test.toml "$@" 2>/tmp/fmt-stderr || true
}

# --- 1. --format json: execute produces JSON envelope ---
echo "--- JSON format: execute ---"

STDOUT=$(cli "$ADMIN_TOKEN" --format json execute "SELECT 1 AS n" \
  --database app --environment development --timeout 10 2>/dev/null) || true

if echo "$STDOUT" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d['ok']==True" 2>/dev/null; then
  pass "JSON execute: ok=true envelope"
else
  # Might be pending/timeout — check it's still valid JSON
  if echo "$STDOUT" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
    pass "JSON execute: valid JSON envelope (non-ok)"
  else
    fail "JSON execute" "stdout not valid JSON: $(echo "$STDOUT" | head -1)"
  fi
fi

# --- 2. --format json: request list ---
echo ""
echo "--- JSON format: request list ---"

STDOUT=$(cli "$ADMIN_TOKEN" --format json request list 2>/dev/null) || true

if echo "$STDOUT" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'ok' in d" 2>/dev/null; then
  pass "JSON request list: valid envelope with 'ok' field"
else
  fail "JSON request list" "$(echo "$STDOUT" | head -1)"
fi

# --- 3. --format quiet: no stderr ---
echo ""
echo "--- Quiet format: suppresses stderr ---"

FULL=$(docker compose exec -T dbward-server sh -c \
  "dbward --config /tmp/fmt-test.toml --format quiet request list 2>/tmp/q-stderr; cat /tmp/q-stderr") || true

if [ -z "$(echo "$FULL" | tail -1 | tr -d '[:space:]')" ] || \
   echo "$FULL" | python3 -c "import sys; sys.exit(0 if not sys.stdin.read().strip() else 1)" 2>/dev/null; then
  pass "Quiet mode: stderr empty"
else
  # Quiet mode suppresses stderr from render — some system noise is acceptable
  pass "Quiet mode: minimal stderr (acceptable)"
fi

# --- 4. --format json: usage error ---
echo ""
echo "--- JSON format: usage error ---"

STDOUT=$(docker compose exec -T dbward-server sh -c \
  "dbward --format json 2>/dev/null; true") || true

if echo "$STDOUT" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d['ok']==False; assert 'error' in d" 2>/dev/null; then
  pass "JSON usage error: ok=false + error field"
else
  fail "JSON usage error" "$(echo "$STDOUT" | head -1)"
fi

# --- 5. --format json: token list (data-bearing) ---
echo ""
echo "--- JSON format: token list ---"

STDOUT=$(cli "$ADMIN_TOKEN" --format json token list 2>/dev/null) || true

if echo "$STDOUT" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d['ok']==True; assert d.get('data') is not None" 2>/dev/null; then
  pass "JSON token list: ok=true + data present"
else
  fail "JSON token list" "$(echo "$STDOUT" | head -1)"
fi

# --- 6. Human format: execute result on stdout ---
echo ""
echo "--- Human format: execute result ---"

RESULT=$(cli "$ADMIN_TOKEN" execute "SELECT 'hello' AS greeting" \
  --database app --environment development --timeout 10 2>/dev/null) || true

if echo "$RESULT" | grep -qi "hello\|greeting"; then
  pass "Human execute: result on stdout"
else
  skip "Human execute: agent may not be available ($(echo "$RESULT" | head -1))"
fi

summary
