#!/bin/bash
# E2E Security: Business logic abuse
# Tests break-glass abuse, post-approval mutation, cancel-after-running.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."
source "$SCRIPT_DIR/helpers.sh"

echo ""
echo "=== Logic Abuse Tests ==="
echo ""

ADMIN_TOKEN=$(create_token e2e-logic-admin admin)
DEV_TOKEN=$(create_token e2e-logic-dev requester)
[ -z "$ADMIN_TOKEN" ] && { echo "Failed to create tokens"; exit 1; }

# --- Break-glass requires reason ---
echo "--- Break-glass controls ---"

# Break-glass without reason should be rejected
STATUS=$(api_status POST /api/requests "$ADMIN_TOKEN" \
  -d '{"detail":"DROP TABLE temp","database":"app","environment":"production","emergency":true}')
[ "$STATUS" = "400" ] && pass "Break-glass without reason rejected" || \
  { [ "$STATUS" = "201" ] && fail "Break-glass" "accepted without reason" || fail "Break-glass" "got $STATUS"; }

# Break-glass with reason should work (admin only)
STATUS=$(api_status POST /api/requests "$ADMIN_TOKEN" \
  -d '{"detail":"SELECT 1","database":"app","environment":"production","emergency":true,"reason":"incident INC-123"}')
[ "$STATUS" = "201" ] && pass "Break-glass with reason accepted (admin)" || fail "Break-glass with reason" "got $STATUS"

# Developer cannot use break-glass
STATUS=$(api_status POST /api/requests "$DEV_TOKEN" \
  -d '{"detail":"SELECT 1","database":"app","environment":"production","emergency":true,"reason":"test"}')
[ "$STATUS" = "403" ] && pass "Developer cannot use break-glass" || fail "Dev break-glass" "got $STATUS"

# --- Post-approval mutation attempt ---
echo ""
echo "--- Post-approval mutation ---"

RESP=$(api POST /api/requests "$DEV_TOKEN" \
  -d '{"detail":"SELECT 1","database":"app","environment":"development"}')
REQ_ID=$(echo "$RESP" | json_field id)

if [ -n "$REQ_ID" ]; then
  # Wait for auto-approve in dev environment
  wait_for_status "$REQ_ID" "executed" "$ADMIN_TOKEN" 10 || true
  FINAL=$(api GET "/api/requests/$REQ_ID" "$ADMIN_TOKEN" | json_field status)

  # Try to re-submit or modify the request (no PATCH endpoint exists, but verify)
  STATUS=$(api_status POST "/api/requests/$REQ_ID/cancel" "$DEV_TOKEN")
  # Cancel on already-completed request should fail
  if [ "$FINAL" = "executed" ] || [ "$FINAL" = "dispatched" ] || [ "$FINAL" = "running" ]; then
    [ "$STATUS" = "409" ] || [ "$STATUS" = "400" ] && pass "Cannot cancel completed request ($FINAL → $STATUS)" || \
      fail "Post-completion cancel" "got $STATUS on status=$FINAL"
  else
    pass "Request status=$FINAL, cancel returned $STATUS"
  fi
else
  skip "Could not create request for post-mutation test"
fi

# --- Reject-then-approve race ---
echo ""
echo "--- Reject blocks further actions ---"

RESP=$(api POST /api/requests "$DEV_TOKEN" \
  -d '{"detail":"SELECT 1","database":"app","environment":"staging"}')
REQ_ID=$(echo "$RESP" | json_field id)

if [ -n "$REQ_ID" ]; then
  # Reject it
  api_status POST "/api/requests/$REQ_ID/reject" "$ADMIN_TOKEN" -d '{"reason":"test"}' >/dev/null
  sleep 1
  # Try to approve after reject
  STATUS=$(api_status POST "/api/requests/$REQ_ID/approve" "$ADMIN_TOKEN" -d '{}')
  [ "$STATUS" = "409" ] && pass "Cannot approve rejected request" || fail "Approve after reject" "got $STATUS"
else
  skip "Could not create request for reject test"
fi

summary
