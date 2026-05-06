#!/bin/bash
# E2E Agent Tests — Agent failures, lease, capability matching
# Requires: docker compose services running (server + agent + postgres)
# Usage: ./dev/e2e-agent.sh

set -euo pipefail
cd "$(dirname "$0")/.."
source dev/e2e-helpers.sh

echo ""
echo "=== E2E Agent Tests ==="
echo ""

DEV_TOKEN=$(docker compose exec -T dbward-server /app/dbward server token create --user bob --role developer --data /data 2>/dev/null | grep -o 'dbw_[a-z0-9]*')
[ -z "$DEV_TOKEN" ] && { echo "Failed to create token"; exit 1; }

# --- 1. Agent executes auto-approved request ---
echo "--- Normal agent execution ---"

REQ=$(api POST /api/requests "$DEV_TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"default","detail":"SELECT 42 AS answer"}')
REQ_ID=$(echo "$REQ" | json_field id)
STATUS=$(echo "$REQ" | json_field status)

if [ -n "$REQ_ID" ]; then
  pass "Created request: ${REQ_ID:0:8} (status=$STATUS)"
  sleep 4
  FINAL=$(api GET "/api/requests/$REQ_ID" "$DEV_TOKEN" | json_field status)
  [ "$FINAL" = "executed" ] && pass "Agent executed request" || fail "Agent exec" "status=$FINAL"
else
  fail "Create request" "no ID"
fi

# --- 2. Agent stop → job stays dispatched → agent restart → executes ---
echo ""
echo "--- Agent restart recovery ---"

docker compose stop dbward-agent 2>/dev/null
sleep 1

REQ2=$(api POST /api/requests "$DEV_TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"default","detail":"SELECT 1"}')
REQ2_ID=$(echo "$REQ2" | json_field id)

sleep 2
STATUS2=$(api GET "/api/requests/$REQ2_ID" "$DEV_TOKEN" | json_field status)
if [ "$STATUS2" = "dispatched" ] || [ "$STATUS2" = "auto_approved" ]; then
  pass "Request stays dispatched while agent is stopped"
else
  skip "Request status=$STATUS2 (may have been claimed before stop)"
fi

docker compose start dbward-agent 2>/dev/null
sleep 5

FINAL2=$(api GET "/api/requests/$REQ2_ID" "$DEV_TOKEN" | json_field status)
[ "$FINAL2" = "executed" ] && pass "Agent executes after restart" || fail "Agent restart" "status=$FINAL2"

# --- 3. Result retrieval after execution ---
echo ""
echo "--- Result retrieval ---"

REQ3=$(api POST /api/requests "$DEV_TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"default","detail":"SELECT 123 AS val"}')
REQ3_ID=$(echo "$REQ3" | json_field id)
sleep 4

RESULT_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  "${SERVER_URL}/api/requests/$REQ3_ID/result/content" \
  -H "Authorization: Bearer $DEV_TOKEN")
# Result content may or may not be stored depending on result_store config
if [ "$RESULT_STATUS" = "200" ] || [ "$RESULT_STATUS" = "404" ]; then
  pass "Result endpoint responds correctly ($RESULT_STATUS)"
else
  fail "Result retrieval" "http=$RESULT_STATUS"
fi

summary
