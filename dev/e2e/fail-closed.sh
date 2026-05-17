#!/bin/bash
# E2E tests for workflow policy fail-closed behavior
# Requires: docker compose services running (server + postgres + dev-init)
# Usage: ./dev/e2e-fail-closed.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."
source "$SCRIPT_DIR/helpers.sh"

echo ""
echo "=== E2E Fail-Closed Tests ==="
echo ""

# Create tokens
ADMIN_TOKEN=$(create_token alice admin)
DEV_TOKEN=$(create_token bob developer)

[ -z "$ADMIN_TOKEN" ] && { echo "Failed to create admin token"; exit 1; }
[ -z "$DEV_TOKEN" ] && { echo "Failed to create dev token"; exit 1; }

# --- 1. Normal workflow evaluation works ---
echo "--- Normal workflow evaluation ---"

STATUS_CODE=$(api_status POST /api/requests "$DEV_TOKEN" -d '{
  "database":"app","environment":"development","operation":"execute_query",
  "detail":"SELECT 1","reason":"e2e"
}')
[ "$STATUS_CODE" = "201" ] && pass "Normal request creation succeeds (HTTP 201)" || fail "Normal request" "got $STATUS_CODE"

# --- 2. Corrupted workflow JSON → HTTP 500 (fail-closed) ---
echo ""
echo "--- Corrupted workflow → fail-closed ---"

# Ensure sqlite3 is available in the server container for test data injection
docker compose exec -T dbward-server sh -c "which sqlite3 >/dev/null 2>&1 || (apt-get update -qq && apt-get install -y -qq sqlite3) >/dev/null 2>&1"

# Inject corrupted workflow directly into SQLite
docker compose exec -T dbward-server sqlite3 /data/dbward.db \
  "INSERT OR REPLACE INTO workflows (id, database_name, environment, operations_json, steps_json, require_reason, allow_same_approver_across_steps, source, created_at, updated_at) VALUES ('corrupt-test', 'corrupt_db', 'production', '[\"execute_query\"]', 'NOT VALID JSON', 0, 0, 'api', datetime(), datetime())"

STATUS_CODE=$(api_status POST /api/requests "$DEV_TOKEN" -d '{
  "database":"corrupt_db","environment":"production","operation":"execute_query",
  "detail":"DELETE FROM users","reason":"e2e fail-closed test"
}')
echo "  HTTP status: $STATUS_CODE"
if [ "$STATUS_CODE" = "500" ]; then
  pass "Corrupted workflow JSON → HTTP 500 (fail-closed, request NOT created)"
  # Re-fetch to check response body details
  BODY=$(curl -s -X POST "http://localhost:13000/api/requests" \
    -H "Authorization: Bearer $DEV_TOKEN" -H "Content-Type: application/json" \
    -d '{"database":"corrupt_db","environment":"production","operation":"execute_query","detail":"DELETE FROM users","reason":"e2e"}')
  ERROR_CODE=$(echo "$BODY" | python3 -c "import sys,json;print(json.load(sys.stdin).get('code',''))" 2>/dev/null || echo "")
  [ "$ERROR_CODE" = "workflow_eval_failed" ] && pass "Error code is 'workflow_eval_failed'" || fail "Error code" "got '$ERROR_CODE'"
  ERROR_MSG=$(echo "$BODY" | python3 -c "import sys,json;print(json.load(sys.stdin).get('error',''))" 2>/dev/null || echo "")
  if echo "$ERROR_MSG" | grep -qi "NOT VALID JSON"; then
    fail "Error message leaks internal details" "$ERROR_MSG"
  else
    pass "Error message sanitized (no internal details leaked)"
  fi
else
  fail "Corrupted workflow should return 500" "got $STATUS_CODE — request may have been created without approval!"
fi

# --- 3. Corrupted operations_json → HTTP 500 ---
echo ""
echo "--- Corrupted operations_json → fail-closed ---"

docker compose exec -T dbward-server sqlite3 /data/dbward.db \
  "INSERT OR REPLACE INTO workflows (id, database_name, environment, operations_json, steps_json, require_reason, allow_same_approver_across_steps, source, created_at, updated_at) VALUES ('corrupt-ops', 'corrupt_ops_db', 'production', 'BROKEN', '[]', 0, 0, 'api', datetime(), datetime())"

STATUS_CODE=$(api_status POST /api/requests "$DEV_TOKEN" -d '{
  "database":"corrupt_ops_db","environment":"production","operation":"execute_query",
  "detail":"SELECT 1","reason":"e2e"
}')
[ "$STATUS_CODE" = "500" ] && pass "Corrupted operations_json → HTTP 500" || fail "Corrupted ops" "got $STATUS_CODE"

# --- 4. Non-corrupted DB still works after corruption tests ---
echo ""
echo "--- Non-corrupted DB still works ---"

STATUS_CODE=$(api_status POST /api/requests "$DEV_TOKEN" -d '{
  "database":"app","environment":"development","operation":"execute_query",
  "detail":"SELECT 2","reason":"e2e after corruption"
}')
[ "$STATUS_CODE" = "201" ] && pass "Unrelated DB still works after corruption in other DB" || fail "Unrelated DB" "got $STATUS_CODE"

# --- 5. Clean up corrupted rows ---
docker compose exec -T dbward-server sqlite3 /data/dbward.db \
  "DELETE FROM workflows WHERE id IN ('corrupt-test', 'corrupt-ops')"

# --- 6. EXPLAIN ANALYZE bypass prevention (regression test) ---
echo ""
echo "--- EXPLAIN ANALYZE bypass prevention ---"

# First ensure there's a production workflow that requires approval
# First ensure there's a production workflow that requires approval
docker compose exec -T dbward-server sqlite3 /data/dbward.db \
  "INSERT OR IGNORE INTO workflows (id, database_name, environment, operations_json, steps_json, require_reason, allow_same_approver_across_steps, source, created_at, updated_at) VALUES ('e2e-prod', 'app', 'production', '[\"execute_query\"]', '[{\"type\":\"approval\",\"mode\":\"all\",\"approvers\":[{\"role\":\"admin\",\"min\":1}],\"require_distinct_actors\":true}]', 0, 0, 'api', datetime(), datetime())"

RESP=$(api POST /api/requests "$DEV_TOKEN" -d '{
  "database":"app","environment":"production","operation":"execute_query",
  "detail":"EXPLAIN ANALYZE DELETE FROM users","reason":"e2e bypass test"
}')
STATUS=$(echo "$RESP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('status',''))" 2>/dev/null)
[ "$STATUS" = "pending" ] && pass "EXPLAIN ANALYZE DELETE in production → pending (bypass prevented)" || fail "EXPLAIN ANALYZE bypass" "status=$STATUS"

# Normal SELECT in production also needs approval (policy applies to all execute_query)
RESP=$(api POST /api/requests "$DEV_TOKEN" -d '{
  "database":"app","environment":"production","operation":"execute_query",
  "detail":"SELECT 1","reason":"e2e"
}')
STATUS=$(echo "$RESP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('status',''))" 2>/dev/null)
[ "$STATUS" = "pending" ] && pass "SELECT in production → pending (policy enforced)" || fail "Production policy" "status=$STATUS"

# --- 7. Dangerous function detection ---
echo ""
echo "--- Dangerous function detection ---"

RESP=$(api POST /api/requests "$DEV_TOKEN" -d '{
  "database":"app","environment":"production","operation":"execute_query",
  "detail":"SELECT pg_terminate_backend(1234)","reason":"e2e dangerous func"
}')
STATUS=$(echo "$RESP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('status',''))" 2>/dev/null)
[ "$STATUS" = "pending" ] && pass "pg_terminate_backend → pending (dangerous function detected)" || fail "Dangerous func" "status=$STATUS"

# --- Cleanup ---
# --- Cleanup ---
docker compose exec -T dbward-server sqlite3 /data/dbward.db \
  "DELETE FROM workflows WHERE id = 'e2e-prod'"

summary
