#!/bin/bash
# E2E: License / Pro Plan Limits
# Tests Free plan limits and Pro plan unlock
# Requires: docker compose services running + test license keys generated
# Usage: ./dev/e2e/license.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."
source "$SCRIPT_DIR/helpers.sh"

echo "=== License / Pro Plan E2E ==="
echo ""
wait_for_server

TS=$(date +%s)
ADMIN_TOKEN=$(create_token "e2e-license-admin-$TS" admin)
LICENSE_DIR="$(dirname "$0")/../testdata/licenses"

# Regenerate test license keys to avoid expiration issues
python3 "$(dirname "$0")/../scripts/generate-test-license.py" > /dev/null 2>&1 || true

# --- 1. Free plan: workflow limit ---
echo "--- Free plan workflow limit ---"

# server.toml already syncs 3 workflows at startup.
# Free limit is 5, so we can create 2 more before hitting the limit.
for i in $(seq 1 2); do
  STATUS=$(api_status POST /api/workflows "$ADMIN_TOKEN" \
    -d "{\"database\":\"app\",\"environment\":\"lic-env-$i\",\"operations\":[\"execute_select\"],\"steps\":[]}")
  if [ "$STATUS" != "201" ]; then
    fail "Create workflow $i" "got $STATUS (Free limit may already be reached)"
    summary
  fi
done
pass "Created 2 additional workflows (total now at Free limit)"

# Next one should fail with 402
STATUS=$(api_status POST /api/workflows "$ADMIN_TOKEN" \
  -d "{\"database\":\"app\",\"environment\":\"lic-env-over\",\"operations\":[\"execute_select\"],\"steps\":[]}")
[ "$STATUS" = "402" ] && pass "Workflow over Free limit rejected (402 Payment Required)" || fail "Expected 402" "got $STATUS"

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

  # Cleanup: delete workflows created during this test
  ADMIN_TOKEN=$(create_token "e2e-license-cleanup-$TS" admin)
  for i in $(seq 1 2); do
    api DELETE "/api/workflows/app:lic-env-$i" "$ADMIN_TOKEN" > /dev/null 2>&1 || true
  done
  api DELETE "/api/workflows/app:lic-env-over" "$ADMIN_TOKEN" > /dev/null 2>&1 || true
  api DELETE "/api/workflows/app:lic-pro-1" "$ADMIN_TOKEN" > /dev/null 2>&1 || true
else
  skip "Pro license keys not found (run dev/scripts/generate-test-license.py)"
  skip "Expired license test skipped"
fi

summary
