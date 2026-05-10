#!/bin/bash
# E2E: User Management
# Tests users table, role enforcement, disable flow

set -euo pipefail
source "$(dirname "$0")/e2e-helpers.sh"

# Use unique names per run to avoid conflicts
TS=$(date +%s)

echo "=== User Management E2E ==="
echo ""

ADMIN_TOKEN=$(cat dev/tokens/bob.token)

# --- 1. Create readonly user ---
echo "--- Readonly user ---"
READONLY_TOKEN=$(curl -s -X POST "http://localhost:13000/api/tokens" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"subject_id":"um-ro-$TS","role":"readonly","subject_type":"user"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
[ -n "$READONLY_TOKEN" ] && pass "Created readonly token" || fail "Token creation failed"

# --- 2. Readonly can SELECT ---
echo ""
echo "--- Readonly SELECT ---"
STATUS=$(api_status POST /api/requests "$READONLY_TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"app","detail":"SELECT 1"}')
[ "$STATUS" = "201" ] && pass "Readonly can create SELECT (201)" || fail "Readonly SELECT" "got $STATUS"

# --- 3. Readonly cannot DML ---
echo ""
echo "--- Readonly DML rejected ---"
STATUS=$(api_status POST /api/requests "$READONLY_TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"app","detail":"DELETE FROM users"}')
[ "$STATUS" = "403" ] && pass "Readonly cannot create DML (403)" || fail "Readonly DML" "got $STATUS"

# --- 4. Readonly cannot migrate ---
echo ""
echo "--- Readonly migrate rejected ---"
STATUS=$(api_status POST /api/requests "$READONLY_TOKEN" \
  -d '{"operation":"migrate_up","environment":"development","database":"app","detail":"{}"}')
[ "$STATUS" = "403" ] && pass "Readonly cannot migrate (403)" || fail "Readonly migrate" "got $STATUS"

# --- 5. Readonly cannot share ---
echo ""
echo "--- Readonly share_with rejected ---"
STATUS=$(api_status POST /api/requests "$READONLY_TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"app","detail":"SELECT 1","share_with":["group:all"]}')
[ "$STATUS" = "403" ] && pass "Readonly cannot share_with (403)" || fail "Readonly share" "got $STATUS"

# --- 6. Readonly can read own audit ---
echo ""
echo "--- Readonly audit (self) ---"
STATUS=$(api_status GET "/api/audit?user=um-ro-$TS" "$READONLY_TOKEN")
[ "$STATUS" = "200" ] && pass "Readonly can read own audit (200)" || fail "Readonly audit" "got $STATUS"

# --- 7. Role change via PUT ---
echo ""
echo "--- Role change ---"
# Create a developer user
DEV_TOKEN=$(curl -s -X POST "http://localhost:13000/api/tokens" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"subject_id":"um-dv-$TS","role":"developer","subject_type":"user"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# Trigger auto-create by using the token once
curl -s "http://localhost:13000/api/requests" -H "Authorization: Bearer $DEV_TOKEN" > /dev/null

# Change to readonly
RESP=$(curl -s -X PUT "http://localhost:13000/api/users/user/um-dv-$TS" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"role":"readonly"}')
NEW_ROLE=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('role',''))")
[ "$NEW_ROLE" = "readonly" ] && pass "Role changed to readonly" || fail "Role change" "got $NEW_ROLE"

# Verify new role is enforced
STATUS=$(api_status POST /api/requests "$DEV_TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"app","detail":"DELETE FROM users"}')
[ "$STATUS" = "403" ] && pass "Changed user cannot DML (403)" || fail "Role enforcement" "got $STATUS"

# --- 8. Disable user ---
echo ""
echo "--- Disable user ---"
# Create a user to disable
DISABLE_TOKEN=$(curl -s -X POST "http://localhost:13000/api/tokens" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"subject_id":"um-dis-$TS","role":"developer","subject_type":"user"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# Trigger auto-create
curl -s "http://localhost:13000/api/requests" -H "Authorization: Bearer $DISABLE_TOKEN" > /dev/null

# Disable
RESP=$(curl -s -X DELETE "http://localhost:13000/api/users/user/um-dis-$TS" \
  -H "Authorization: Bearer $ADMIN_TOKEN")
DISABLED=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('disabled',False))")
[ "$DISABLED" = "True" ] && pass "User disabled" || fail "Disable" "got $DISABLED"

# Verify disabled user gets 401
STATUS=$(api_status GET /api/requests "$DISABLE_TOKEN")
[ "$STATUS" = "401" ] && pass "Disabled user rejected (401)" || fail "Disabled auth" "got $STATUS"

# --- 9. Cannot create token for disabled user ---
echo ""
echo "--- Token for disabled user ---"
STATUS=$(api_status POST /api/tokens "$ADMIN_TOKEN" \
  -d '{"subject_id":"um-dis-$TS","role":"developer","subject_type":"user"}')
[ "$STATUS" = "403" ] && pass "Cannot create token for disabled user (403)" || fail "Disabled token" "got $STATUS"

# --- 10. Role mismatch token creation ---
echo ""
echo "--- Role mismatch token ---"
STATUS=$(api_status POST /api/tokens "$ADMIN_TOKEN" \
  -d '{"subject_id":"um-ro-$TS","role":"admin","subject_type":"user"}')
[ "$STATUS" = "409" ] && pass "Role mismatch rejected (409)" || fail "Role mismatch" "got $STATUS"

# --- 11. GET /api/users ---
echo ""
echo "--- List users ---"
RESP=$(curl -s "http://localhost:13000/api/users" -H "Authorization: Bearer $ADMIN_TOKEN")
COUNT=$(echo "$RESP" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['users']))")
[ "$COUNT" -gt 0 ] && pass "GET /api/users returns $COUNT users" || fail "List users" "empty"

echo ""
echo "=== Results ==="
print_results
