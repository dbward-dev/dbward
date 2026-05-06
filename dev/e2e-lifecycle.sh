#!/bin/bash
# E2E Lifecycle Tests — Full request flows, state transitions, retry
# Requires: docker compose services running (server + agent + postgres)
# Usage: ./dev/e2e-lifecycle.sh

set -euo pipefail
cd "$(dirname "$0")/.."
source dev/e2e-helpers.sh

echo ""
echo "=== E2E Lifecycle Tests ==="
echo ""

# Create tokens
# Create tokens (production workflow: step1=backend-team, step2=dba-team, distinct actors required)
ADMIN_BACKEND=$(docker compose exec -T dbward-server dbward server token create --user alice --role admin --groups backend-team --data /data/dbward.db 2>/dev/null | grep -o 'dbw_[a-z0-9]*')
ADMIN_DBA=$(docker compose exec -T dbward-server dbward server token create --user carol --role admin --groups dba-team --data /data/dbward.db 2>/dev/null | grep -o 'dbw_[a-z0-9]*')
DEV_TOKEN=$(docker compose exec -T dbward-server dbward server token create --user bob --role developer --data /data/dbward.db 2>/dev/null | grep -o 'dbw_[a-z0-9]*')

[ -z "$ADMIN_BACKEND" ] && { echo "Failed to create admin token"; exit 1; }
[ -z "$ADMIN_DBA" ] && { echo "Failed to create dba token"; exit 1; }
[ -z "$DEV_TOKEN" ] && { echo "Failed to create dev token"; exit 1; }

# --- 1. Full E2E: create → approve → dispatch → agent execute ---
echo "--- Full approval flow ---"

REQ=$(api POST /api/requests "$DEV_TOKEN" \
  -d '{"operation":"execute_query","environment":"production","database":"app","detail":"SELECT 1","reason":"e2e test"}')
REQ_ID=$(echo "$REQ" | json_field id)
REQ_STATUS=$(echo "$REQ" | json_field status)

if [ "$REQ_STATUS" = "pending" ] && [ -n "$REQ_ID" ]; then
  pass "Create pending request: ${REQ_ID:0:8}"
  show_output "status=$REQ_STATUS (requires admin approval)"
else
  fail "Create pending" "status=$REQ_STATUS"
  show_output "Error: $(json_error)"
fi

# Approve (production requires 2 steps: backend-team then dba-team, distinct actors)
APPROVE_RESP=$(api POST "/api/requests/$REQ_ID/approve" "$ADMIN_BACKEND" -d '{}')
APPROVE_STATUS=$(echo "$APPROVE_RESP" | json_field status)
show_output "Step 1 (backend-team): status=$APPROVE_STATUS"

# Step 2: different user from dba-team
APPROVE_RESP=$(api POST "/api/requests/$REQ_ID/approve" "$ADMIN_DBA" -d '{}')
APPROVE_STATUS=$(echo "$APPROVE_RESP" | json_field status)
show_output "Step 2 (dba-team): status=$APPROVE_STATUS"

[ "$APPROVE_STATUS" = "approved" ] || [ "$APPROVE_STATUS" = "dispatched" ] && \
  pass "Two-step approval → $APPROVE_STATUS" || fail "Approve" "status=$APPROVE_STATUS"

# Dispatch (if not auto-dispatched)
if [ "$APPROVE_STATUS" = "approved" ]; then
  api POST "/api/requests/$REQ_ID/dispatch" "$DEV_TOKEN" -d '{}' >/dev/null
fi

# Wait for agent execution
sleep 4
FINAL_STATUS=$(api GET "/api/requests/$REQ_ID" "$DEV_TOKEN" | json_field status)
[ "$FINAL_STATUS" = "executed" ] && pass "Agent executed successfully" || fail "Agent execution" "status=$FINAL_STATUS"

# --- 2. Auto-approve flow (development) ---
echo ""
echo "--- Auto-approve flow ---"

REQ=$(api POST /api/requests "$DEV_TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"app","detail":"SELECT version()"}')
STATUS=$(echo "$REQ" | json_field status)
REQ_ID=$(echo "$REQ" | json_field id)

if [ "$STATUS" = "auto_approved" ] || [ "$STATUS" = "dispatched" ]; then
  pass "Development auto-approves: $STATUS"
  # Wait for execution
  sleep 3
  FINAL=$(api GET "/api/requests/$REQ_ID" "$DEV_TOKEN" | json_field status)
  [ "$FINAL" = "executed" ] && pass "Auto-approved request executed" || fail "Auto-approve exec" "status=$FINAL"
else
  fail "Auto-approve" "status=$STATUS"
fi

# --- 3. Reject flow ---
echo ""
echo "--- Reject flow ---"

REQ_ID=$(api POST /api/requests "$DEV_TOKEN" \
  -d '{"operation":"execute_query","environment":"production","database":"app","detail":"DROP TABLE x","reason":"reject test"}' | json_field id)
RESULT=$(api POST "/api/requests/$REQ_ID/reject" "$ADMIN_BACKEND" -d '{"comment":"too dangerous"}')
STATUS=$(echo "$RESULT" | json_field status)
[ "$STATUS" = "rejected" ] && pass "Request rejected" || fail "Reject" "status=$STATUS"

# --- 4. Cancel flow ---
echo ""
echo "--- Cancel flow ---"

REQ_ID=$(api POST /api/requests "$DEV_TOKEN" \
  -d '{"operation":"execute_query","environment":"production","database":"app","detail":"SELECT 1","reason":"cancel test"}' | json_field id)
RESULT=$(api POST "/api/requests/$REQ_ID/cancel" "$DEV_TOKEN" -d '{"reason":"changed my mind"}')
STATUS=$(echo "$RESULT" | json_field status)
[ "$STATUS" = "cancelled" ] && pass "Request cancelled" || fail "Cancel" "status=$STATUS"

# --- 5. Break-glass emergency ---
echo ""
echo "--- Break-glass ---"

REQ=$(api POST /api/requests "$DEV_TOKEN" \
  -d '{"operation":"execute_query","environment":"production","database":"app","detail":"SELECT 1","emergency":true,"reason":"incident #123"}')
STATUS=$(echo "$REQ" | json_field status)
[ "$STATUS" = "break_glass" ] && pass "Break-glass request created" || fail "Break-glass" "status=$STATUS"

# --- 6. Idempotency ---
echo ""
echo "--- Idempotency ---"

IDEM_KEY="e2e-test-$(date +%s)"
REQ1=$(api POST /api/requests "$DEV_TOKEN" \
  -d "{\"operation\":\"execute_query\",\"environment\":\"development\",\"database\":\"default\",\"detail\":\"SELECT 1\",\"idempotency_key\":\"$IDEM_KEY\"}")
ID1=$(echo "$REQ1" | json_field id)

REQ2=$(api POST /api/requests "$DEV_TOKEN" \
  -d "{\"operation\":\"execute_query\",\"environment\":\"development\",\"database\":\"default\",\"detail\":\"SELECT 2\",\"idempotency_key\":\"$IDEM_KEY\"}")
ID2=$(echo "$REQ2" | json_field id)
IDEM=$(echo "$REQ2" | python3 -c "import sys,json; v=json.load(sys.stdin).get('idempotent',''); print('true' if v else 'false')")

if [ "$ID1" = "$ID2" ] && [ "$IDEM" = "true" ]; then
  pass "Idempotency key returns existing request"
else
  fail "Idempotency" "id1=$ID1 id2=$ID2 idempotent=$IDEM"
fi

# --- 7. Unicode SQL execution ---
echo ""
echo "--- Unicode ---"

REQ=$(api POST /api/requests "$DEV_TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"app","detail":"SELECT '\''日本語テスト 🎉'\'' AS msg"}')
REQ_ID=$(echo "$REQ" | json_field id)
sleep 3
DETAIL=$(api GET "/api/requests/$REQ_ID" "$DEV_TOKEN" | python3 -c "import sys,json; print(json.load(sys.stdin).get('detail',''))")
if echo "$DETAIL" | grep -q "日本語"; then
  pass "Unicode detail preserved"
else
  fail "Unicode" "detail=$DETAIL"
fi

summary
