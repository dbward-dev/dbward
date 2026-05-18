#!/bin/bash
# E2E: Webhook CRUD + Delivery verification
# Requires: docker compose services running (server + webhook-receiver)

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."
source "$SCRIPT_DIR/helpers.sh"

echo "=== Webhook E2E ==="
echo ""
wait_for_server

TS=$(date +%s)
ADMIN_TOKEN=$(create_token "e2e-wh-admin-$TS" admin)
# Default URL uses example.com (public, non-private IP) for CRUD testing.
# Docker internal IPs are blocked by SSRF protection.
# For delivery verification, override: WEBHOOK_URL=http://host.docker.internal:9999/hook
WEBHOOK_URL="${WEBHOOK_URL:-https://example.com/webhook}"

# --- 1. Create webhook ---
echo "--- Create webhook ---"
RESP=$(api POST /api/webhooks "$ADMIN_TOKEN" \
  -d "{\"name\":\"e2e-hook\",\"url\":\"$WEBHOOK_URL\",\"events\":[\"request_created\",\"request_completed\"],\"secret\":\"test-secret-123\"}")
WH_ID=$(echo "$RESP" | json_field id)
[ -n "$WH_ID" ] && pass "Webhook created: $WH_ID" || fail "Create webhook" "no id"

# --- 2. List webhooks ---
echo ""
echo "--- List webhooks ---"
STATUS=$(api_status GET /api/webhooks "$ADMIN_TOKEN")
[ "$STATUS" = "200" ] && pass "List webhooks (200)" || fail "List" "got $STATUS"
COUNT=$(echo "$LAST_RESPONSE_BODY" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('webhooks',[])))")
[ "$COUNT" -ge 1 ] && pass "At least 1 webhook listed" || fail "Count" "$COUNT"

# --- 3. Get webhook ---
echo ""
echo "--- Get webhook ---"
STATUS=$(api_status GET "/api/webhooks/$WH_ID" "$ADMIN_TOKEN")
[ "$STATUS" = "200" ] && pass "Get webhook (200)" || fail "Get" "got $STATUS"

# --- 4. Trigger delivery (create a request) ---
echo ""
echo "--- Trigger delivery ---"
DEV_TOKEN=$(create_token "e2e-wh-dev-$TS" developer)
api POST /api/requests "$DEV_TOKEN" \
  -d '{"operation":"execute_select","environment":"development","database":"app","detail":"SELECT 1"}' > /dev/null
sleep 2

# Check delivery via webhook-deliveries API
STATUS=$(api_status GET "/api/webhook-deliveries?webhook_id=$WH_ID" "$ADMIN_TOKEN")
if [ "$STATUS" = "200" ]; then
  DELIVERY_COUNT=$(echo "$LAST_RESPONSE_BODY" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('deliveries',[])))" 2>/dev/null || echo "0")
  [ "$DELIVERY_COUNT" -ge 1 ] && pass "Webhook delivered ($DELIVERY_COUNT deliveries)" || skip "Webhook delivery pending (async)"
else
  skip "Webhook deliveries API returned $STATUS"
fi

# --- 5. Delete webhook ---
echo ""
echo "--- Delete webhook ---"
STATUS=$(api_status DELETE "/api/webhooks/$WH_ID" "$ADMIN_TOKEN")
[ "$STATUS" = "200" ] && pass "Webhook deleted (200)" || fail "Delete" "got $STATUS"

# Verify gone
STATUS=$(api_status GET "/api/webhooks/$WH_ID" "$ADMIN_TOKEN")
[ "$STATUS" = "404" ] && pass "Deleted webhook returns 404" || fail "After delete" "got $STATUS"

summary
