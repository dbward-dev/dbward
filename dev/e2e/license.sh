#!/bin/bash
# E2E: License / Team Plan Limits (CFG-24)
# Tests that config sync respects license limits.
# POST /api/workflows is now 405. Limits are enforced at startup (config sync).
# Requires: docker compose services running + test license keys generated

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/../.."
export COMPOSE_FILE="dev/compose.yml:dev/compose.override.yml"
source "$SCRIPT_DIR/helpers.sh"

echo "=== License / Team Plan E2E (CFG-24) ==="
echo ""

# --- 1. Free plan: server starts with config within limits ---
echo "--- Free plan: server starts with valid config ---"

wait_for_server
TS=$(date +%s)
ADMIN_TOKEN=$(create_token "e2e-license-admin-$TS" admin)

STATUS=$(api_status GET /health "$ADMIN_TOKEN")
[ "$STATUS" = "200" ] && pass "Server healthy (Free plan, config within limits)" || fail "Health" "got $STATUS"

# --- 2. Workflow write API returns 405 ---
echo ""
echo "--- Workflow write API → 405 ---"

STATUS=$(api_status POST /api/workflows "$ADMIN_TOKEN" \
  -d '{"database":"app","environment":"lic-env","operations":["execute_select"],"steps":[]}')
[ "$STATUS" = "405" ] && pass "POST /api/workflows → 405 (config-managed)" || fail "POST workflows" "got $STATUS"

# --- 3. Config-synced workflows are listed ---
echo ""
echo "--- Config-synced workflows ---"

STATUS=$(api_status GET /api/workflows "$ADMIN_TOKEN")
[ "$STATUS" = "200" ] && pass "GET /api/workflows → 200" || fail "GET workflows" "got $STATUS"

COUNT=$(echo "$LAST_RESPONSE_BODY" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('workflows',[])))")
[ "$COUNT" -ge 1 ] && pass "Config-synced workflows present ($COUNT)" || fail "Workflow count" "$COUNT"

# --- 4. Database count matches config ---
echo ""
echo "--- Database registry ---"

STATUS=$(api_status GET /api/databases "$ADMIN_TOKEN")
[ "$STATUS" = "200" ] && pass "GET /api/databases → 200" || fail "GET databases" "got $STATUS"

# --- 5. Expired license: server still starts (graceful degradation) ---
echo ""
echo "--- Expired license graceful degradation ---"

LICENSE_DIR="$(dirname "$0")/../testdata/licenses"
if [ -f "$LICENSE_DIR/expired.key" ]; then
  EXPIRED_KEY=$(cat "$LICENSE_DIR/expired.key" | tr -d '\n')
  echo "$EXPIRED_KEY" > "$SCRIPT_DIR/../secrets/license.key"
  docker compose restart dbward-server >/dev/null 2>&1
  sleep 3
  wait_for_server

  ADMIN_TOKEN=$(create_token "e2e-license-exp-$TS" admin)
  STATUS=$(api_status GET /health "$ADMIN_TOKEN")
  [ "$STATUS" = "200" ] && pass "Expired license: server starts (Free fallback)" || fail "Expired startup" "got $STATUS"

  # Restore
  echo "" > "$SCRIPT_DIR/../secrets/license.key"
  docker compose restart dbward-server >/dev/null 2>&1
  sleep 3
  wait_for_server
else
  skip "Expired license key not found"
fi

summary
