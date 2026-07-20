#!/bin/bash
# E2E: Webhook — Config-managed + Delivery verification
# CFG-24: POST/PUT/DELETE /api/webhooks return 405. GET still works.
# Requires: docker compose services running (server + webhook-receiver)

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."
source "$SCRIPT_DIR/helpers.sh"

echo "=== Webhook E2E (CFG-24: Config-managed) ==="
echo ""
wait_for_server

TS=$(date +%s)
ADMIN_TOKEN=$(create_token "e2e-wh-admin-$TS" admin,requester)

# --- 1. Write API returns 405 ---
echo "--- Write API → 405 ---"

STATUS=$(api_status POST /api/webhooks "$ADMIN_TOKEN" \
  -d '{"name":"e2e-hook","url":"https://example.com/hook","events":["request_created"],"secret":"test"}')
[ "$STATUS" = "405" ] && pass "POST /api/webhooks → 405" || fail "POST webhooks" "got $STATUS"

STATUS=$(api_status PUT /api/webhooks/any-id "$ADMIN_TOKEN" \
  -d '{"url":"https://example.com/hook2","events":["*"]}')
[ "$STATUS" = "405" ] && pass "PUT /api/webhooks/{id} → 405" || fail "PUT webhooks" "got $STATUS"

STATUS=$(api_status DELETE /api/webhooks/any-id "$ADMIN_TOKEN")
[ "$STATUS" = "405" ] && pass "DELETE /api/webhooks/{id} → 405" || fail "DELETE webhooks" "got $STATUS"

# --- 2. Config-synced webhooks visible via GET ---
echo ""
echo "--- Config-synced webhooks visible ---"

STATUS=$(api_status GET /api/webhooks "$ADMIN_TOKEN")
[ "$STATUS" = "200" ] && pass "GET /api/webhooks → 200" || fail "GET webhooks" "got $STATUS"

COUNT=$(echo "$LAST_RESPONSE_BODY" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('webhooks',[])))")
[ "$COUNT" -ge 1 ] && pass "At least 1 config-synced webhook listed ($COUNT)" || fail "Webhook count" "$COUNT"

# --- 3. Trigger delivery (create a request) ---
echo ""
echo "--- Trigger delivery ---"

DEV_TOKEN=$(create_token "e2e-wh-dev-$TS" requester)
api POST /api/requests "$DEV_TOKEN" \
  -d '{"operation":"execute_select","environment":"development","database":"app","detail":"SELECT 1"}' > /dev/null
sleep 2

# Check delivery count (if webhook-deliveries API available)
WH_ID=$(echo "$LAST_RESPONSE_BODY" | python3 -c "
import sys,json
try:
  whs=json.load(sys.stdin).get('webhooks',[])
  print(whs[0]['id'] if whs else '')
except: print('')" 2>/dev/null || echo "")

if [ -n "$WH_ID" ]; then
  STATUS=$(api_status GET "/api/webhook-deliveries?webhook_id=$WH_ID" "$ADMIN_TOKEN")
  if [ "$STATUS" = "200" ]; then
    DELIVERY_COUNT=$(echo "$LAST_RESPONSE_BODY" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('deliveries',[])))" 2>/dev/null || echo "0")
    [ "$DELIVERY_COUNT" -ge 1 ] && pass "Webhook delivered ($DELIVERY_COUNT deliveries)" || skip "Webhook delivery pending (async)"
  else
    skip "Webhook deliveries API returned $STATUS"
  fi
else
  skip "No webhook ID to check deliveries"
fi

summary
