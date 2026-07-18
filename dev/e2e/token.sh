#!/bin/bash
# E2E: Token management (list, revoke)
# Requires: docker compose services running (server + postgres)

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."
source "$SCRIPT_DIR/helpers.sh"

echo "=== Token Management E2E ==="
echo ""
wait_for_server

TS=$(date +%s)
# Use bootstrap admin token directly (V25: roles resolved from DB)
ADMIN_TOKEN=$(docker compose exec -T dbward-server cat /data/admin-token 2>/dev/null || echo "")

# --- 1. List tokens ---
echo "--- List tokens ---"
RESP=$(api GET /api/tokens "$ADMIN_TOKEN")
echo "$RESP" | python3 -c "import sys,json;json.load(sys.stdin)" 2>/dev/null \
  && pass "List tokens (200, valid JSON)" || fail "List" "invalid response"

# --- 2. Create + revoke ---
echo ""
echo "--- Create and revoke ---"
EXTRA_TOKEN=$(create_token "e2e-tok-extra-$TS" requester)
[ -n "$EXTRA_TOKEN" ] && pass "Created extra token" || fail "Create token" ""

# Find the token ID
RESP=$(api GET /api/tokens "$ADMIN_TOKEN")
TOKEN_ID=$(echo "$RESP" | python3 -c "
import sys,json
tokens = json.load(sys.stdin).get('tokens',[])
for t in tokens:
    if t.get('subject_id','') == 'e2e-tok-extra-$TS':
        print(t['id']); break
" 2>/dev/null || true)

if [ -n "$TOKEN_ID" ]; then
  pass "Found token ID: ${TOKEN_ID:0:8}..."

  # Revoke
  STATUS=$(api_status DELETE "/api/tokens/$TOKEN_ID" "$ADMIN_TOKEN")
  [ "$STATUS" = "200" ] && pass "Token revoked (200)" || fail "Revoke" "got $STATUS"

  # Verify revoked
  STATUS=$(api_status GET /api/requests "$EXTRA_TOKEN")
  [ "$STATUS" = "401" ] && pass "Revoked token rejected (401)" || fail "Revoked auth" "got $STATUS"
else
  fail "Token not found in list" ""
fi

summary
