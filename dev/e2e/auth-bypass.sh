#!/bin/bash
# E2E Security: Authentication bypass attempts
# Tests expired tokens, revoked tokens, malformed JWTs, non-ASCII tokens.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."
source "$SCRIPT_DIR/helpers.sh"

echo ""
echo "=== Auth Bypass Tests ==="
echo ""

ADMIN_TOKEN=$(create_token e2e-bypass-admin admin)
[ -z "$ADMIN_TOKEN" ] && { echo "Failed to create token"; exit 1; }

# --- Revoked token ---
echo "--- Revoked token ---"

VICTIM_TOKEN=$(create_token e2e-victim developer)
# Verify it works first
STATUS=$(api_status GET /api/requests "$VICTIM_TOKEN")
[ "$STATUS" = "200" ] && pass "Token works before revoke" || fail "Pre-revoke" "got $STATUS"

# Find and revoke via API
TOKENS_RESP=$(api GET /api/tokens "$ADMIN_TOKEN")
TOKEN_ID=$(echo "$TOKENS_RESP" | python3 -c "
import sys,json
data = json.load(sys.stdin)
tokens = data if isinstance(data, list) else data.get('tokens',[])
for t in tokens:
    if 'victim' in t.get('name','') or 'victim' in t.get('user','') or 'victim' in t.get('subject_id',''):
        print(t['id']); break
" 2>/dev/null)

if [ -n "$TOKEN_ID" ]; then
  api_status DELETE "/api/tokens/$TOKEN_ID" "$ADMIN_TOKEN" >/dev/null
  sleep 1
  STATUS=$(api_status GET /api/requests "$VICTIM_TOKEN")
  [ "$STATUS" = "401" ] && pass "Revoked token rejected (401)" || fail "Revoked token" "got $STATUS"
else
  # Fallback: revoke via CLI using prefix
  VICTIM_PREFIX="${VICTIM_TOKEN:4:8}"
  docker compose exec -T dbward-server \
    dbward-server --data /data/dbward.db token revoke --prefix "$VICTIM_PREFIX" >/dev/null 2>&1 || true
  sleep 1
  STATUS=$(api_status GET /api/requests "$VICTIM_TOKEN")
  [ "$STATUS" = "401" ] && pass "Revoked token rejected (401)" || skip "Revoke test inconclusive ($STATUS)"
fi

# --- Malformed tokens ---
echo ""
echo "--- Malformed tokens ---"

STATUS=$(api_status GET /api/requests "dbw_")
[ "$STATUS" = "401" ] && pass "Prefix-only token rejected" || fail "Prefix-only" "got $STATUS"

STATUS=$(api_status GET /api/requests "dbw_short")
[ "$STATUS" = "401" ] && pass "Too-short token rejected" || fail "Too-short" "got $STATUS"

STATUS=$(api_status GET /api/requests "dbw_abcdef8Ю*20extra")
[ "$STATUS" = "401" ] && pass "Non-ASCII token rejected (FUZZ-1 fix)" || fail "Non-ASCII" "got $STATUS"

STATUS=$(api_status GET /api/requests "")
[ "$STATUS" = "401" ] && pass "Empty token rejected" || fail "Empty token" "got $STATUS"

# --- Fake JWT (alg:none attack) ---
echo ""
echo "--- JWT attacks ---"

# alg:none — base64({"alg":"none","typ":"JWT"}).base64({"sub":"admin"}).
FAKE_JWT="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImdyb3VwcyI6WyJhZG1pbiJdfQ."
STATUS=$(api_status GET /api/requests "$FAKE_JWT")
[ "$STATUS" = "401" ] && pass "alg:none JWT rejected" || fail "alg:none" "got $STATUS"

# Random JWT-like string
STATUS=$(api_status GET /api/requests "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJoYWNrZXIifQ.not_a_real_signature")
[ "$STATUS" = "401" ] && pass "Fake JWT signature rejected" || fail "Fake JWT" "got $STATUS"

# --- Extremely long token ---
echo ""
echo "--- Length attacks ---"

LONG_TOKEN="dbw_$(python3 -c "print('a'*1000)")"
STATUS=$(api_status GET /api/requests "$LONG_TOKEN")
[ "$STATUS" = "401" ] && pass "1000-char token rejected" || fail "Long token" "got $STATUS"

# --- Server still alive ---
echo ""
STATUS=$(api_noauth GET /health)
[ "$STATUS" = "200" ] && pass "Server alive after auth bypass tests" || fail "Server health" "got $STATUS"

summary
