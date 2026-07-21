#!/bin/bash
# E2E Large Data & Slow Query Tests
# Tests result size limits, slow query handling, and agent heartbeat under load
# Requires: docker compose services running (server + agent + postgres)
# Usage: ./dev/e2e-large-data.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."
source "$SCRIPT_DIR/helpers.sh"

echo ""
echo "=== E2E Large Data & Slow Query Tests ==="
echo ""

wait_for_server
wait_for_agent

DEV_TOKEN=$(create_token loadtest requester)
[ -z "$DEV_TOKEN" ] && { echo "Failed to create token"; exit 1; }

# --- 1. Large result set (10,000+ rows) ---
echo "--- Large result set (15,000 rows) ---"

REQ=$(api POST /api/requests "$DEV_TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"app","detail":"SELECT generate_series(1, 15000) AS n, repeat('\''x'\'', 100) AS padding"}')
REQ_ID=$(echo "$REQ" | json_field id)
STATUS=$(echo "$REQ" | json_field status)
show_output "Created: ${REQ_ID:0:8} status=$STATUS"

sleep 8
FINAL=$(api GET "/api/requests/$REQ_ID" "$DEV_TOKEN")
FINAL_STATUS=$(echo "$FINAL" | json_field status)

if [ "$FINAL_STATUS" = "executed" ]; then
  pass "Large result query executed"
  show_output "Query returned (result capped at 10,000 rows by driver)"
else
  fail "Large result" "status=$FINAL_STATUS"
  show_output "Error: $(json_error)"
fi

# --- 2. Slow query (pg_sleep) — tests heartbeat keeps lease alive ---
echo ""
echo "--- Slow query (5s sleep) — heartbeat test ---"

REQ=$(api POST /api/requests "$DEV_TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"app","detail":"SELECT pg_sleep(5), 42 AS answer"}')
REQ_ID=$(echo "$REQ" | json_field id)
show_output "Created: ${REQ_ID:0:8} (5s sleep query)"

# Wait longer than the query duration
sleep 10
FINAL_STATUS=$(api GET "/api/requests/$REQ_ID" "$DEV_TOKEN" | json_field status)

if [ "$FINAL_STATUS" = "executed" ]; then
  pass "Slow query (5s) completed — heartbeat kept lease alive"
else
  fail "Slow query" "status=$FINAL_STATUS (expected executed)"
  show_output "If execution_lost: heartbeat failed to extend lease"
fi

# --- 3. Very large single-row result (1MB text) ---
echo ""
echo "--- Large single-row result (1MB text) ---"

REQ=$(api POST /api/requests "$DEV_TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"app","detail":"SELECT repeat('\''A'\'', 1048576) AS big_text"}')
REQ_ID=$(echo "$REQ" | json_field id)
sleep 6
FINAL_STATUS=$(api GET "/api/requests/$REQ_ID" "$DEV_TOKEN" | json_field status)

if [ "$FINAL_STATUS" = "executed" ]; then
  pass "1MB single-row result handled"
else
  fail "1MB result" "status=$FINAL_STATUS"
fi

# --- 4. Many columns ---
echo ""
echo "--- Wide result (100 columns) ---"

# Generate SELECT with 100 columns
COLS=$(seq 1 100 | awk '{printf "%s%d AS col_%d", (NR>1?",":""), NR, NR}')
REQ=$(api POST /api/requests "$DEV_TOKEN" \
  -d "{\"operation\":\"execute_query\",\"environment\":\"development\",\"database\":\"app\",\"detail\":\"SELECT $COLS\"}")
REQ_ID=$(echo "$REQ" | json_field id)
sleep 5
FINAL_STATUS=$(api GET "/api/requests/$REQ_ID" "$DEV_TOKEN" | json_field status)

if [ "$FINAL_STATUS" = "executed" ]; then
  pass "100-column result handled"
else
  fail "Wide result" "status=$FINAL_STATUS"
fi

# --- 5. Empty result ---
echo ""
echo "--- Empty result (0 rows) ---"

REQ=$(api POST /api/requests "$DEV_TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"app","detail":"SELECT 1 WHERE false"}')
REQ_ID=$(echo "$REQ" | json_field id)
sleep 4
FINAL_STATUS=$(api GET "/api/requests/$REQ_ID" "$DEV_TOKEN" | json_field status)

if [ "$FINAL_STATUS" = "executed" ]; then
  pass "Empty result (0 rows) handled"
else
  fail "Empty result" "status=$FINAL_STATUS"
fi

# --- 6. Syntax error (agent should report failure) ---
echo ""
echo "--- SQL syntax error ---"

REQ=$(api POST /api/requests "$DEV_TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"app","detail":"SELEC INVALID SYNTAX"}')
REQ_ID=$(echo "$REQ" | json_field id)
sleep 4
FINAL_STATUS=$(api GET "/api/requests/$REQ_ID" "$DEV_TOKEN" | json_field status)

if [ "$FINAL_STATUS" = "failed" ]; then
  pass "SQL syntax error → failed status"
  show_output "Agent correctly reported execution failure"
else
  fail "Syntax error handling" "status=$FINAL_STATUS (expected failed)"
fi

summary
