#!/bin/bash
# E2E Security: Data leakage prevention
# Tests that error messages, token hashes, and internal state don't leak.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."
source "$SCRIPT_DIR/helpers.sh"

echo ""
echo "=== Data Leakage Tests ==="
echo ""

ADMIN_TOKEN=$(create_token e2e-leak-admin admin)
DEV_TOKEN=$(create_token e2e-leak-dev requester)
[ -z "$ADMIN_TOKEN" ] && { echo "Failed to create tokens"; exit 1; }

# --- Token hash not exposed in list API (SEC-1) ---
echo "--- Token hash leakage (SEC-1) ---"

RESP=$(api GET /api/tokens "$ADMIN_TOKEN")
if echo "$RESP" | python3 -c "
import sys, json
data = json.load(sys.stdin)
tokens = data if isinstance(data, list) else data.get('tokens', [])
for t in tokens:
    if 'token_hash' in t or 'hash' in t:
        print('LEAK: token_hash found in response')
        sys.exit(1)
sys.exit(0)" 2>/dev/null; then
  pass "Token hash not exposed in list API"
else
  fail "Token hash leak (SEC-1)" "token_hash field found in GET /api/tokens response"
fi

# --- Error messages don't leak internals ---
echo ""
echo "--- Error message sanitization ---"

# Invalid request should not expose stack traces or internal paths
STATUS=$(api_status POST /api/requests "$DEV_TOKEN" \
  -d '{"detail":"","database":"nonexistent_db","environment":"development"}')
if ! echo "$LAST_RESPONSE_BODY" | grep -qi "panic\|stack\|/app/\|/home/\|\.rs:"; then
  pass "Error response does not leak internals"
else
  fail "Error info leak" "response contains internal details"
fi

# Auth failure should not reveal whether token exists
STATUS=$(api_status GET /api/requests "dbw_doesnotexist1")
if ! echo "$LAST_RESPONSE_BODY" | grep -qi "not found\|no such token\|prefix"; then
  pass "Auth error does not reveal token existence"
else
  fail "Token oracle" "response reveals token lookup details"
fi

# --- Audit log does not expose sensitive data to non-admin ---
echo ""
echo "--- Audit access control ---"

STATUS=$(api_status GET /api/audit/events "$DEV_TOKEN")
[ "$STATUS" = "403" ] && pass "Developer cannot access audit log" || fail "Audit access" "got $STATUS"

# --- Request detail not visible to unrelated users ---
echo ""
echo "--- Cross-user request visibility ---"

# Create a request as dev
RESP=$(api POST /api/requests "$DEV_TOKEN" \
  -d '{"detail":"SELECT secret_column FROM internal_table","database":"app","environment":"development"}')
REQ_ID=$(echo "$RESP" | json_field id)

if [ -n "$REQ_ID" ]; then
  # Another requester should see it (same org) but approver should have limited view
  # Admin should see full detail
  ADMIN_VIEW=$(api GET "/api/requests/$REQ_ID" "$ADMIN_TOKEN" | json_field detail)
  [ -n "$ADMIN_VIEW" ] && pass "Admin can view request detail" || fail "Admin view" "no detail field"
fi

# --- Health endpoint does not leak version details beyond header ---
echo ""
echo "--- Minimal info exposure ---"

HEALTH_BODY=$(curl -s "${SERVER_URL}/health")
if ! echo "$HEALTH_BODY" | grep -qi "debug\|commit\|build_date\|internal"; then
  pass "Health endpoint minimal info"
else
  fail "Health info leak" "exposes debug/build info"
fi

summary
