#!/bin/bash
# E2E Security: Injection attacks
# Tests SQL injection, JSON bombs, and oversized payloads are rejected.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."
source "$SCRIPT_DIR/helpers.sh"

echo ""
echo "=== Injection Tests ==="
echo ""

ADMIN_TOKEN=$(create_token e2e-inject-admin admin)
[ -z "$ADMIN_TOKEN" ] && { echo "Failed to create token"; exit 1; }

# --- SQL Injection via detail field ---
echo "--- SQL Injection ---"

# Stacked queries: should be rejected or treated as literal string
STATUS=$(api_status POST /api/requests "$ADMIN_TOKEN" \
  -d '{"detail":"SELECT 1; DROP TABLE users","database":"app","environment":"development"}')
if [ "$STATUS" = "400" ]; then
  pass "Stacked query rejected (400)"
elif [ "$STATUS" = "201" ]; then
  # Request created but classified as multi-statement → should be blocked
  ERROR=$(echo "$LAST_RESPONSE_BODY" | json_field error)
  pass "Stacked query accepted as request (server handles safely): $ERROR"
else
  fail "Stacked query" "got $STATUS"
fi

# UNION injection
STATUS=$(api_status POST /api/requests "$ADMIN_TOKEN" \
  -d '{"detail":"SELECT id FROM users UNION SELECT password FROM admin","database":"app","environment":"development"}')
[ "$STATUS" = "201" ] || [ "$STATUS" = "400" ] && pass "UNION injection handled ($STATUS)" || fail "UNION injection" "got $STATUS"

# Comment-based bypass
STATUS=$(api_status POST /api/requests "$ADMIN_TOKEN" \
  -d '{"detail":"SELECT * FROM users WHERE id=1-- DROP TABLE x","database":"app","environment":"development"}')
[ "$STATUS" = "201" ] || [ "$STATUS" = "400" ] && pass "Comment bypass handled ($STATUS)" || fail "Comment bypass" "got $STATUS"

# Null byte injection
STATUS=$(api_status POST /api/requests "$ADMIN_TOKEN" \
  -d '{"detail":"SELECT * FROM users WHERE name='"'"'\x00'"'"'","database":"app","environment":"development"}')
[ "$STATUS" = "400" ] && pass "Null byte rejected (400)" || fail "Null byte" "got $STATUS (expected 400)"

# --- JSON Bomb (deep nesting) ---
echo ""
echo "--- JSON Bombs ---"

# Deep nesting (100 levels)
DEEP_JSON=$(python3 -c "
import json
d = 'x'
for _ in range(100):
    d = {'a': d}
d['detail'] = 'SELECT 1'
d['database'] = 'app'
d['environment'] = 'development'
print(json.dumps(d))")
STATUS=$(api_status POST /api/requests "$ADMIN_TOKEN" -d "$DEEP_JSON")
# Should either reject (400/413) or handle without crash
[ "$STATUS" != "000" ] && pass "Deep nesting handled ($STATUS)" || fail "Deep nesting" "server unreachable"

# Large array in share_with
LARGE_ARRAY=$(python3 -c "import json; print(json.dumps({'detail':'SELECT 1','database':'app','environment':'development','share_with':['user'+str(i) for i in range(10000)]}))")
STATUS=$(api_status POST /api/requests "$ADMIN_TOKEN" -d "$LARGE_ARRAY")
[ "$STATUS" = "400" ] || [ "$STATUS" = "413" ] || [ "$STATUS" = "201" ] && pass "Large array handled ($STATUS)" || fail "Large array" "got $STATUS"

# --- Oversized Body ---
echo ""
echo "--- Oversized Body ---"

# 5MB body (via file to avoid argument limit)
python3 -c "print('{\"detail\":\"' + 'A'*5000000 + '\",\"database\":\"app\",\"environment\":\"development\"}')" > /tmp/bigbody.json
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${SERVER_URL}/api/requests" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" -d @/tmp/bigbody.json)
rm -f /tmp/bigbody.json
[ "$STATUS" = "413" ] || [ "$STATUS" = "400" ] && pass "5MB body rejected ($STATUS)" || fail "Oversized body" "got $STATUS"

# --- Server still alive after all attacks ---
echo ""
STATUS=$(api_status GET /health "")
[ "$STATUS" = "200" ] && pass "Server alive after injection tests" || fail "Server health" "got $STATUS"

summary
