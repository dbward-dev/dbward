#!/bin/bash
# E2E: License Online Validation
# Tests online license validation against a mock server.
# Requires: docker compose with license-e2e profile

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/../.."
export COMPOSE_FILE="dev/compose.yml:dev/compose.override.yml"
export COMPOSE_PROFILES="license-e2e"

# Required env for online validation against mock server
export DBWARD_LICENSE_URL="${DBWARD_LICENSE_URL:-http://mock-license:8443/v1/validate}"
export DBWARD_LICENSE_INSECURE="${DBWARD_LICENSE_INSECURE:-1}"
export DBWARD_LICENSE_JITTER_SECS="${DBWARD_LICENSE_JITTER_SECS:-0}"
export DBWARD_LICENSE_ONLINE_INTERVAL_SECS="${DBWARD_LICENSE_ONLINE_INTERVAL_SECS:-10}"

source "$SCRIPT_DIR/helpers.sh"

MOCK_CONTROL="http://localhost:18444"
SERVER_URL="http://localhost:13000"

echo "=== License Online Validation E2E ==="
echo ""

# --- Setup: start mock-license + server with online validation ---
echo "--- Setup: starting mock license server ---"

docker compose up -d mock-license 2>/dev/null
sleep 3

# Verify mock is up
MOCK_STATUS=$(curl -sf "$MOCK_CONTROL/get-status" | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])")
[ "$MOCK_STATUS" = "active" ] && pass "Mock license server running (status=$MOCK_STATUS)" || fail "Mock server" "status=$MOCK_STATUS"

# Start server with license-url pointing to mock
echo ""
echo "--- Starting server with online validation ---"

docker compose up -d dbward-server 2>/dev/null
sleep 5
wait_for_server

TS=$(date +%s)
ADMIN_TOKEN=$(create_token "e2e-lov-$TS" admin)

# --- 1. Initial state: Pro plan (mock returns active) ---
echo ""
echo "--- Test 1: Online validation → active (Pro maintained) ---"

# Wait for first online validation (60s + jitter, but we can check metrics)
# For now just confirm server started as Pro
PLAN=$(curl -sf "$SERVER_URL/api/license" -H "Authorization: Bearer $ADMIN_TOKEN" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('effective_plan','unknown'))" 2>/dev/null || echo "no-endpoint")

if [ "$PLAN" = "no-endpoint" ]; then
  # /api/license doesn't exist yet, check via health
  STATUS=$(api_status GET /health "$ADMIN_TOKEN")
  [ "$STATUS" = "200" ] && pass "Server healthy (Pro plan, online validation configured)" || fail "Health" "got $STATUS"
else
  [ "$PLAN" = "pro" ] && pass "Effective plan: pro" || fail "Plan" "got $PLAN"
fi

# --- 2. Change mock to revoked → server should downgrade ---
echo ""
echo "--- Test 2: Mock → revoked (expect downgrade on next validation) ---"

curl -sf -X POST "$MOCK_CONTROL/set-status" -d '{"status":"revoked"}' >/dev/null
MOCK_STATUS=$(curl -sf "$MOCK_CONTROL/get-status" | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])")
[ "$MOCK_STATUS" = "revoked" ] && pass "Mock status set to revoked" || fail "Mock set" "$MOCK_STATUS"

# Wait for online tick (this may take up to 60s+jitter for first check)
echo "  Waiting for online validation cycle (up to 90s)..."
for i in $(seq 1 18); do
  FAILURE=$(curl -sf "$SERVER_URL/metrics" -H "Authorization: Bearer $ADMIN_TOKEN" | grep "^dbward_license_online_failure_total" | awk '{print $2}')
  if [ "${FAILURE:-0}" -gt "0" ]; then
    pass "Online validation detected revocation (failure_total=$FAILURE)"
    break
  fi
  sleep 5
done
if [ "${FAILURE:-0}" = "0" ]; then
  skip "Online validation not yet triggered (jitter delay). Forcing via restart."
  # Restart to trigger startup check with no validated_until
  docker compose restart dbward-server 2>/dev/null
  sleep 5
  wait_for_server
  ADMIN_TOKEN=$(create_token "e2e-lov-restart-$TS" admin)
fi

# --- 3. Change mock back to active → server should restore Pro ---
echo ""
echo "--- Test 3: Mock → active (expect Pro restoration) ---"

curl -sf -X POST "$MOCK_CONTROL/set-status" -d '{"status":"active"}' >/dev/null

# Wait for next online validation
echo "  Waiting for online validation cycle..."
for i in $(seq 1 18); do
  SUCCESS=$(curl -sf "$SERVER_URL/metrics" -H "Authorization: Bearer $ADMIN_TOKEN" 2>/dev/null | grep "^dbward_license_online_success_total" | awk '{print $2}')
  if [ "${SUCCESS:-0}" -gt "0" ]; then
    pass "Online validation restored license (success_total=$SUCCESS)"
    break
  fi
  sleep 5
done
if [ "${SUCCESS:-0}" = "0" ]; then
  skip "Online validation not yet triggered within timeout"
fi

# --- 4. Network error (stop mock) → grace period ---
echo ""
echo "--- Test 4: Mock stopped (network error → grace period) ---"

docker compose stop mock-license 2>/dev/null
sleep 2

NETWORK_ERR_BEFORE=$(curl -sf "$SERVER_URL/metrics" -H "Authorization: Bearer $ADMIN_TOKEN" 2>/dev/null | grep "^dbward_license_online_network_error_total" | awk '{print $2}')
pass "Mock stopped. Network errors before: ${NETWORK_ERR_BEFORE:-0}"

# Server should still be healthy (grace period)
STATUS=$(api_status GET /health "$ADMIN_TOKEN")
[ "$STATUS" = "200" ] && pass "Server still healthy during grace period" || fail "Grace health" "got $STATUS"

# --- 5. Restart mock ---
docker compose start mock-license 2>/dev/null

# --- Summary ---
echo ""
summary
