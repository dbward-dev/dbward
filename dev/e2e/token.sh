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
ADMIN_TOKEN=$(create_token "e2e-tok-admin-$TS" admin)

# --- 1. List tokens ---
echo "--- List tokens ---"
STATUS=$(api_status GET /api/tokens "$ADMIN_TOKEN")
[ "$STATUS" = "200" ] && pass "List tokens (200)" || fail "List" "got $STATUS"
INITIAL_COUNT=$(echo "$LAST_RESPONSE_BODY" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('tokens',[])))")
pass "Initial token count: $INITIAL_COUNT"

# --- 2. Create additional token ---
echo ""
echo "--- Create token ---"
EXTRA_TOKEN=$(create_token "e2e-tok-extra-$TS" developer)
[ -n "$EXTRA_TOKEN" ] && pass "Created extra token" || fail "Create token" ""

# Verify count increased
STATUS=$(api_status GET /api/tokens "$ADMIN_TOKEN")
NEW_COUNT=$(echo "$LAST_RESPONSE_BODY" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('tokens',[])))")
[ "$NEW_COUNT" -gt "$INITIAL_COUNT" ] && pass "Token count increased ($INITIAL_COUNT → $NEW_COUNT)" || fail "Count unchanged" "$NEW_COUNT"

# --- 3. Find the extra token ID ---
echo ""
echo "--- Find token to revoke ---"
TOKEN_ID=$(echo "$LAST_RESPONSE_BODY" | python3 -c "
import sys,json
tokens = json.load(sys.stdin).get('tokens',[])
for t in tokens:
    if t.get('subject_id','') == 'e2e-tok-extra-$TS':
        print(t['id'])
        break
")
[ -n "$TOKEN_ID" ] && pass "Found token ID: $TOKEN_ID" || fail "Token not found in list" ""

# --- 4. Revoke token ---
echo ""
echo "--- Revoke token ---"
if [ -n "$TOKEN_ID" ]; then
  STATUS=$(api_status DELETE "/api/tokens/$TOKEN_ID" "$ADMIN_TOKEN")
  [ "$STATUS" = "200" ] && pass "Token revoked (200)" || fail "Revoke" "got $STATUS"

  # Verify revoked token can't authenticate
  STATUS=$(api_status GET /api/requests "$EXTRA_TOKEN")
  [ "$STATUS" = "401" ] && pass "Revoked token rejected (401)" || fail "Revoked auth" "got $STATUS"
else
  skip "Cannot test revoke (token ID not found)"
fi

summary
