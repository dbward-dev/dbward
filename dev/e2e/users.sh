#!/bin/bash
# E2E: User Management
# Tests users table, role enforcement, disable flow
# Requires: docker compose services running (server + postgres + dev-init)

set -euo pipefail
source "$(dirname "$0")/helpers.sh"

TS=$(date +%s)

echo "=== User Management E2E ==="
echo ""
wait_for_server

ADMIN_TOKEN=$(create_token "e2e-admin-$TS" admin)

# --- 1. Create readonly user ---
echo "--- Readonly user ---"
READONLY_TOKEN=$(create_token "um-ro-$TS" readonly)
[ -n "$READONLY_TOKEN" ] && pass "Created readonly token" || fail "Token creation failed" ""

# --- 2. Readonly can SELECT ---
STATUS=$(api_status POST /api/requests "$READONLY_TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"app","detail":"SELECT 1"}')
[ "$STATUS" = "201" ] && pass "Readonly can create SELECT (201)" || fail "Readonly SELECT" "got $STATUS"

# --- 3. Readonly cannot DML ---
STATUS=$(api_status POST /api/requests "$READONLY_TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"app","detail":"DELETE FROM users"}')
[ "$STATUS" = "403" ] && pass "Readonly cannot create DML (403)" || fail "Readonly DML" "got $STATUS"

# --- 4. Readonly cannot migrate ---
STATUS=$(api_status POST /api/requests "$READONLY_TOKEN" \
  -d '{"operation":"migrate_up","environment":"development","database":"app","detail":"{}"}')
[ "$STATUS" = "403" ] && pass "Readonly cannot migrate (403)" || fail "Readonly migrate" "got $STATUS"

# --- 5. Readonly cannot share ---
STATUS=$(api_status POST /api/requests "$READONLY_TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"app","detail":"SELECT 1","share_with":["group:all"]}')
[ "$STATUS" = "403" ] && pass "Readonly cannot share_with (403)" || fail "Readonly share" "got $STATUS"

# --- 6. Readonly can read own audit ---
STATUS=$(api_status GET "/api/audit?user=um-ro-$TS" "$READONLY_TOKEN")
[ "$STATUS" = "200" ] && pass "Readonly can read own audit (200)" || fail "Readonly audit" "got $STATUS"

# --- 7. Suspend user ---
echo ""
echo "--- Suspend user ---"
SUSPEND_TOKEN=$(create_token "um-sus-$TS" developer)
# Trigger auto-create by using the token
api GET /api/requests "$SUSPEND_TOKEN" > /dev/null

STATUS=$(api_status POST "/api/users/um-sus-$TS/suspend" "$ADMIN_TOKEN")
[ "$STATUS" = "200" ] && pass "User suspended (200)" || fail "Suspend" "got $STATUS"

# Verify suspended user gets 401
STATUS=$(api_status GET /api/requests "$SUSPEND_TOKEN")
[ "$STATUS" = "401" ] && pass "Suspended user rejected (401)" || fail "Suspended auth" "got $STATUS"

# --- 8. Activate user ---
echo ""
echo "--- Activate user ---"
STATUS=$(api_status POST "/api/users/um-sus-$TS/activate" "$ADMIN_TOKEN")
[ "$STATUS" = "200" ] && pass "User activated (200)" || fail "Activate" "got $STATUS"

STATUS=$(api_status GET /api/requests "$SUSPEND_TOKEN")
[ "$STATUS" = "200" ] && pass "Activated user can access (200)" || fail "Activated auth" "got $STATUS"

# --- 9. GET /api/users ---
echo ""
echo "--- List users ---"
STATUS=$(api_status GET /api/users "$ADMIN_TOKEN")
[ "$STATUS" = "200" ] && pass "GET /api/users returns 200" || fail "List users" "got $STATUS"

summary
