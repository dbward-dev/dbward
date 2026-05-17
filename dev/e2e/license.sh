#!/bin/bash
# E2E: License / Pro Plan Limits
# Tests Free plan limits and Pro plan unlock
# Requires: docker compose services running + test license keys generated
# Usage: ./dev/e2e/license.sh

set -euo pipefail
source "$(dirname "$0")/helpers.sh"

echo "=== License / Pro Plan E2E ==="
echo ""
wait_for_server

TS=$(date +%s)
ADMIN_TOKEN=$(create_token "e2e-license-admin-$TS" admin)
LICENSE_DIR="$(dirname "$0")/../testdata/licenses"

# --- 1. Free plan: workflow limit ---
echo "--- Free plan workflow limit ---"

# Create workflows up to the free limit (5)
for i in $(seq 1 5); do
  STATUS=$(api_status POST /api/workflows "$ADMIN_TOKEN" \
    -d "{\"database\":\"app\",\"environment\":\"lic-env-$i\",\"operations\":[\"execute_select\"],\"steps\":[]}")
  if [ "$STATUS" != "201" ]; then
    fail "Create workflow $i" "got $STATUS"
    summary
  fi
done
pass "Created 5 workflows (Free limit)"

# 6th should fail with 402
STATUS=$(api_status POST /api/workflows "$ADMIN_TOKEN" \
  -d "{\"database\":\"app\",\"environment\":\"lic-env-6\",\"operations\":[\"execute_select\"],\"steps\":[]}")
[ "$STATUS" = "402" ] && pass "6th workflow rejected (402 Payment Required)" || fail "Expected 402" "got $STATUS"

# --- 2. Pro plan: unlocks limit ---
echo ""
echo "--- Pro plan unlock ---"

if [ -f "$LICENSE_DIR/pro.key" ] && [ -f "$LICENSE_DIR/test.pub.hex" ]; then
  PUB_KEY=$(cat "$LICENSE_DIR/test.pub.hex" | tr -d '\n')
  PRO_KEY=$(cat "$LICENSE_DIR/pro.key" | tr -d '\n')

  # Restart server with Pro license
  DBWARD_LICENSE_KEY="$PRO_KEY" DBWARD_LICENSE_PUBLIC_KEY="$PUB_KEY" \
    docker compose -f dev/compose.yml -f dev/compose.override.yml up -d dbward-server 2>/dev/null
  sleep 3
  wait_for_server

  # Re-create admin token (server restarted)
  ADMIN_TOKEN=$(create_token "e2e-license-pro-$TS" admin)

  # Should now be able to create more workflows
  STATUS=$(api_status POST /api/workflows "$ADMIN_TOKEN" \
    -d "{\"database\":\"app\",\"environment\":\"lic-pro-1\",\"operations\":[\"execute_select\"],\"steps\":[]}")
  [ "$STATUS" = "201" ] && pass "Pro plan allows additional workflows (201)" || fail "Pro workflow" "got $STATUS"

  # --- 3. Expired license falls back to Free ---
  echo ""
  echo "--- Expired license fallback ---"
  EXPIRED_KEY=$(cat "$LICENSE_DIR/expired.key" | tr -d '\n')

  DBWARD_LICENSE_KEY="$EXPIRED_KEY" DBWARD_LICENSE_PUBLIC_KEY="$PUB_KEY" \
    docker compose -f dev/compose.yml -f dev/compose.override.yml up -d dbward-server 2>/dev/null
  sleep 3
  wait_for_server

  ADMIN_TOKEN=$(create_token "e2e-license-exp-$TS" admin)
  # Server should start (graceful degradation) - check it's running
  STATUS=$(api_status GET /health "$ADMIN_TOKEN")
  [ "$STATUS" = "200" ] && pass "Expired license: server starts (Free fallback)" || fail "Expired startup" "got $STATUS"

  # Restore original (no license)
  DBWARD_LICENSE_KEY="" DBWARD_LICENSE_PUBLIC_KEY="" \
    docker compose -f dev/compose.yml -f dev/compose.override.yml up -d dbward-server 2>/dev/null
  sleep 2
  wait_for_server
else
  skip "Pro license keys not found (run dev/scripts/generate-test-license.py)"
  skip "Expired license test skipped"
fi

summary
