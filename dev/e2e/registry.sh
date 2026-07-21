#!/bin/bash
# E2E: Database Registry validation
# Tests that unregistered databases/environments are rejected
# Requires: docker compose services running (server + postgres + dev-init)

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."
source "$SCRIPT_DIR/helpers.sh"

echo "=== Database Registry E2E ==="
echo ""
wait_for_server

TS=$(date +%s)
DEV_TOKEN=$(create_token "e2e-dev-$TS" requester)

# --- 1. List databases ---
echo "--- List databases ---"
STATUS=$(api_status GET /api/databases "$DEV_TOKEN")
[ "$STATUS" = "200" ] && pass "GET /api/databases returns 200" || fail "List databases" "got $STATUS"

# --- 2. Registered DB+env succeeds ---
echo ""
echo "--- Registered DB+env ---"
STATUS=$(api_status POST /api/requests "$DEV_TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"app","detail":"SELECT 1"}')
[ "$STATUS" = "201" ] && pass "Registered DB+env accepted (201)" || fail "Expected 201" "got $STATUS"

# --- 3. Unregistered database rejected ---
echo ""
echo "--- Unregistered database ---"
STATUS=$(api_status POST /api/requests "$DEV_TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"nonexistent_db","detail":"SELECT 1"}')
[ "$STATUS" = "400" ] \
  && pass "Unregistered DB rejected (400)" || fail "Expected rejection" "got $STATUS"

# --- 4. Unregistered environment rejected ---
echo ""
echo "--- Unregistered environment ---"
STATUS=$(api_status POST /api/requests "$DEV_TOKEN" \
  -d '{"operation":"execute_query","environment":"nonexistent_env","database":"app","detail":"SELECT 1"}')
[ "$STATUS" = "400" ] \
  && pass "Unregistered env rejected (400)" || fail "Expected rejection" "got $STATUS"

# --- 5. Detail size limit ---
echo ""
echo "--- Detail size limit ---"
BIG_DETAIL=$(python3 -c "print('X' * 200_000)")
STATUS=$(api_status POST /api/requests "$DEV_TOKEN" \
  -d "{\"operation\":\"execute_query\",\"environment\":\"development\",\"database\":\"app\",\"detail\":\"$BIG_DETAIL\"}")
[ "$STATUS" = "400" ] && pass "Oversized detail rejected (400)" || fail "Expected 400" "got $STATUS"

# --- 6. Unauthenticated /api/databases rejected ---
echo ""
echo "--- Auth required for /api/databases ---"
STATUS=$(api_noauth GET /api/databases)
[ "$STATUS" = "401" ] && pass "/api/databases requires auth (401)" || fail "Expected 401" "got $STATUS"

summary
