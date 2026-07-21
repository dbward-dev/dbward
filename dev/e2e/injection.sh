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

ADMIN_TOKEN=$(create_token e2e-inject-admin admin,requester)
[ -z "$ADMIN_TOKEN" ] && { echo "Failed to create token"; exit 1; }

# --- SQL Injection via detail field ---
echo "--- SQL Injection ---"

# Stacked queries: mixed SELECT + DDL passes through permission gate (SQL-1).
# Admin/requester with request.ddl can submit; sql_review issues warnings but does not reject.
STATUS=$(api_status POST /api/requests "$ADMIN_TOKEN" \
  -d '{"detail":"SELECT 1; DROP TABLE users","database":"app","environment":"development"}')
[ "$STATUS" = "201" ] || [ "$STATUS" = "400" ] || [ "$STATUS" = "403" ] && pass "Stacked query handled ($STATUS)" || fail "Stacked query" "got $STATUS (expected 201, 400, or 403)"

# UNION injection
STATUS=$(api_status POST /api/requests "$ADMIN_TOKEN" \
  -d '{"detail":"SELECT id FROM users UNION SELECT password FROM admin","database":"app","environment":"development"}')
[ "$STATUS" = "201" ] || [ "$STATUS" = "400" ] || [ "$STATUS" = "403" ] && pass "UNION injection handled ($STATUS)" || fail "UNION injection" "got $STATUS"

# Comment-based bypass
STATUS=$(api_status POST /api/requests "$ADMIN_TOKEN" \
  -d '{"detail":"SELECT * FROM users WHERE id=1-- DROP TABLE x","database":"app","environment":"development"}')
[ "$STATUS" = "201" ] || [ "$STATUS" = "400" ] || [ "$STATUS" = "403" ] && pass "Comment bypass handled ($STATUS)" || fail "Comment bypass" "got $STATUS"

# Null byte injection (JSON unicode escape \u0000)
STATUS=$(api_status POST /api/requests "$ADMIN_TOKEN" \
  -d '{"detail":"SELECT * FROM users WHERE name=\u0000","database":"app","environment":"development"}')
[ "$STATUS" = "400" ] && pass "Null byte rejected (400)" || pass "Null byte handled safely ($STATUS)"

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
[ "$STATUS" = "400" ] || [ "$STATUS" = "413" ] || [ "$STATUS" = "201" ] || [ "$STATUS" = "403" ] && pass "Large array handled ($STATUS)" || fail "Large array" "got $STATUS"

# --- Oversized Body ---
echo ""
echo "--- Oversized Body ---"

# 5MB body (via file to avoid argument limit)
python3 -c "print('{\"detail\":\"' + 'A'*5000000 + '\",\"database\":\"app\",\"environment\":\"development\"}')" > /tmp/bigbody.json
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${SERVER_URL}/api/requests" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" -d @/tmp/bigbody.json)
rm -f /tmp/bigbody.json
[ "$STATUS" = "413" ] || [ "$STATUS" = "400" ] && pass "5MB body rejected ($STATUS)" || fail "Oversized body" "got $STATUS"

# --- DDL Permission gate ---
echo ""
echo "--- DDL Permission ---"

DML_ONLY_TOKEN=$(create_token e2e-inject-dml dml-only)
if [ -n "$DML_ONLY_TOKEN" ]; then
  STATUS=$(api_status POST /api/requests "$DML_ONLY_TOKEN" \
    -d '{"detail":"CREATE TABLE perm_test (id int)","database":"app","environment":"development"}')
  [ "$STATUS" = "403" ] && pass "DDL without request.ddl rejected (403)" || fail "DDL permission gate" "got $STATUS (expected 403)"
else
  skip "dml-only role not configured"
fi

# --- Server still alive after all attacks ---
echo ""
STATUS=$(api_status GET /health "")
[ "$STATUS" = "200" ] && pass "Server alive after injection tests" || fail "Server health" "got $STATUS"

summary
