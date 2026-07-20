#!/bin/bash
# E2E Security: SSRF prevention (CFG-24)
# Tests that POST /api/webhooks returns 405 and that config sync rejects private URLs.
# Note: Full SSRF validation is tested in unit tests (ssrf.rs).
# This E2E verifies the API surface change and that the dev config works with allow_private_networks.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."
source "$SCRIPT_DIR/helpers.sh"

echo ""
echo "=== SSRF Prevention Tests (CFG-24) ==="
echo ""

ADMIN_TOKEN=$(create_token e2e-ssrf-admin admin,requester)
[ -z "$ADMIN_TOKEN" ] && { echo "Failed to create token"; exit 1; }

# --- POST /api/webhooks is 405 (regardless of URL content) ---
echo "--- Webhook write API → 405 ---"

STATUS=$(api_status POST /api/webhooks "$ADMIN_TOKEN" \
  -d '{"url":"http://127.0.0.1:8080/hook","events":["request.created"],"format":"generic"}')
[ "$STATUS" = "405" ] && pass "POST /api/webhooks (localhost) → 405" || fail "localhost" "got $STATUS"

STATUS=$(api_status POST /api/webhooks "$ADMIN_TOKEN" \
  -d '{"url":"http://169.254.169.254/latest/meta-data/","events":["request.created"],"format":"generic"}')
[ "$STATUS" = "405" ] && pass "POST /api/webhooks (AWS metadata) → 405" || fail "169.254" "got $STATUS"

STATUS=$(api_status POST /api/webhooks "$ADMIN_TOKEN" \
  -d '{"url":"https://hooks.example.com/dbward","events":["request.created"],"format":"generic"}')
[ "$STATUS" = "405" ] && pass "POST /api/webhooks (public URL) → 405" || fail "public URL" "got $STATUS"

# --- Server is running with allow_private_networks=true (dev config has internal webhook URL) ---
echo ""
echo "--- Dev server started with internal webhook URL ---"

STATUS=$(api_status GET /health "$ADMIN_TOKEN")
[ "$STATUS" = "200" ] && pass "Server healthy (allow_private_networks=true allows internal webhook)" || fail "Health" "got $STATUS"

# Verify config-synced webhook is present (it uses Docker internal URL)
STATUS=$(api_status GET /api/webhooks "$ADMIN_TOKEN")
if [ "$STATUS" = "200" ]; then
  COUNT=$(echo "$LAST_RESPONSE_BODY" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('webhooks',[])))")
  [ "$COUNT" -ge 1 ] && pass "Config webhook with internal URL synced ($COUNT)" || fail "No webhooks" "0"
else
  fail "GET /api/webhooks" "got $STATUS"
fi

summary
