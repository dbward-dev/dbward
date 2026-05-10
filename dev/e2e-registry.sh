#!/bin/bash
# E2E: Database Registry validation
# Tests that unregistered databases/environments are rejected

set -euo pipefail
source "$(dirname "$0")/e2e-helpers.sh"

echo "=== Database Registry E2E ==="
echo ""

DEV_TOKEN=$(cat dev/tokens/alice.token)

# --- 1. List databases ---
echo "--- List databases ---"
RESP=$(api GET /api/databases "$DEV_TOKEN")
DB_COUNT=$(echo "$RESP" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['databases']))")
[ "$DB_COUNT" -gt 0 ] && pass "GET /api/databases returns $DB_COUNT databases" || fail "No databases registered"

# --- 2. Registered DB+env succeeds ---
echo ""
echo "--- Registered DB+env ---"
STATUS=$(api_status POST /api/requests "$DEV_TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"app","detail":"SELECT 1"}')
[ "$STATUS" = "201" ] && pass "Registered DB+env accepted (201)" || fail "Expected 201" "got $STATUS"

# --- 3. Unregistered database rejected ---
echo ""
echo "--- Unregistered database ---"
RESP=$(curl -s -X POST "http://localhost:13000/api/requests" \
  -H "Authorization: Bearer $DEV_TOKEN" -H "Content-Type: application/json" \
  -d '{"operation":"execute_query","environment":"development","database":"nonexistent_db","detail":"SELECT 1"}')
ERROR=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('error',''))" 2>/dev/null)
echo "$ERROR" | grep -q "not registered" && pass "Unregistered DB rejected: $ERROR" || fail "Expected rejection" "got: $ERROR"

# --- 4. Unregistered environment rejected ---
echo ""
echo "--- Unregistered environment ---"
RESP=$(curl -s -X POST "http://localhost:13000/api/requests" \
  -H "Authorization: Bearer $DEV_TOKEN" -H "Content-Type: application/json" \
  -d '{"operation":"execute_query","environment":"nonexistent_env","database":"app","detail":"SELECT 1"}')
ERROR=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('error',''))" 2>/dev/null)
echo "$ERROR" | grep -q "not registered" && pass "Unregistered env rejected: $ERROR" || fail "Expected rejection" "got: $ERROR"

# --- 5. Detail size limit ---
echo ""
echo "--- Detail size limit (5MB) ---"
STATUS=$(python3 -c "
import urllib.request, json, os
detail = 'X' * 6_000_000
token = open('dev/tokens/alice.token').read().strip()
data = json.dumps({'operation':'execute_query','environment':'development','database':'app','detail':detail}).encode()
req = urllib.request.Request('http://localhost:13000/api/requests', data=data,
    headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'})
try:
    urllib.request.urlopen(req)
    print('200')
except urllib.error.HTTPError as e:
    print(e.code)
")
[ "$STATUS" = "400" ] && pass "6MB detail rejected (400)" || fail "Expected 400" "got $STATUS"

# --- 6. Unauthenticated /api/databases rejected ---
echo ""
echo "--- Auth required for /api/databases ---"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:13000/api/databases")
[ "$STATUS" = "401" ] && pass "/api/databases requires auth (401)" || fail "Expected 401" "got $STATUS"

echo ""
echo "=== Results ==="
print_results
