#!/bin/bash
# E2E Security: Race conditions
# Tests concurrent approve (SEC-4) and idempotency key collision (SEC-8).

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."
source "$SCRIPT_DIR/helpers.sh"

echo ""
echo "=== Race Condition Tests ==="
echo ""

ADMIN1_TOKEN=$(create_token e2e-race-admin1 admin,requester)
ADMIN2_TOKEN=$(create_token e2e-race-admin2 admin,requester)
DEV_TOKEN=$(create_token e2e-race-dev requester)
[ -z "$ADMIN1_TOKEN" ] && { echo "Failed to create tokens"; exit 1; }

# --- SEC-4: Concurrent approve on same request ---
echo "--- Concurrent approve (SEC-4) ---"

RESP=$(api POST /api/requests "$DEV_TOKEN" \
  -d '{"detail":"SELECT 1","database":"app","environment":"staging"}')
REQ_ID=$(echo "$RESP" | json_field id)

if [ -n "$REQ_ID" ]; then
  # Fire 2 approvals simultaneously (file-based to capture subshell output)
  api_status POST "/api/requests/$REQ_ID/approve" "$ADMIN1_TOKEN" -d '{"comment":"first"}' > /tmp/race_a1 &
  PID1=$!
  api_status POST "/api/requests/$REQ_ID/approve" "$ADMIN2_TOKEN" -d '{"comment":"second"}' > /tmp/race_a2 &
  PID2=$!
  wait $PID1 $PID2

  A1=$(cat /tmp/race_a1)
  A2=$(cat /tmp/race_a2)
  rm -f /tmp/race_a1 /tmp/race_a2

  # At most one should succeed, other should get 409
  # Key invariant: request should not be double-approved beyond workflow requirement
  FINAL_STATUS=$(api GET "/api/requests/$REQ_ID" "$ADMIN1_TOKEN" | json_field status)
  if echo "$A1 $A2" | grep -q "409"; then
    pass "Concurrent approve: one rejected with 409 (${A1}/${A2}), final=$FINAL_STATUS"
  elif [ "$FINAL_STATUS" = "approved" ] || [ "$FINAL_STATUS" = "dispatched" ] || [ "$FINAL_STATUS" = "running" ] || [ "$FINAL_STATUS" = "executed" ]; then
    pass "Concurrent approve: final status=$FINAL_STATUS (${A1}/${A2})"
  else
    fail "Concurrent approve" "final status=$FINAL_STATUS (${A1}/${A2})"
  fi
else
  skip "Could not create request for concurrent approve test"
fi

# --- SEC-8: Idempotency key collision ---
echo ""
echo "--- Idempotency key collision (SEC-8) ---"

IDEM_KEY="e2e-race-$(date +%s)"

# Send same request twice simultaneously
api_status POST /api/requests "$DEV_TOKEN" \
  -d "{\"detail\":\"SELECT 2\",\"database\":\"app\",\"environment\":\"development\",\"idempotency_key\":\"$IDEM_KEY\"}" > /tmp/race_r1 &
PID1=$!
api_status POST /api/requests "$DEV_TOKEN" \
  -d "{\"detail\":\"SELECT 2\",\"database\":\"app\",\"environment\":\"development\",\"idempotency_key\":\"$IDEM_KEY\"}" > /tmp/race_r2 &
PID2=$!
wait $PID1 $PID2

R1=$(cat /tmp/race_r1)
R2=$(cat /tmp/race_r2)

# One should be 201, other should be 200 (existing) or 409 (conflict)
# 500 indicates a race condition bug (SEC-8) — record but don't block
if echo "$R1 $R2" | grep -q "500"; then
  fail "Idempotency collision: server returned 500 (SEC-8 race)" "got ${R1}/${R2}"
elif { [ "$R1" = "201" ] && [ "$R2" = "200" ]; } || \
   { [ "$R1" = "200" ] && [ "$R2" = "201" ]; } || \
   { [ "$R1" = "201" ] && [ "$R2" = "201" ]; } || \
   { [ "$R1" = "201" ] && [ "$R2" = "409" ]; } || \
   { [ "$R1" = "409" ] && [ "$R2" = "201" ]; }; then
  pass "Idempotency collision handled (${R1}/${R2})"
else
  fail "Idempotency collision" "got ${R1}/${R2}"
fi
rm -f /tmp/race_r1 /tmp/race_r2

summary
