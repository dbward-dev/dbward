#!/bin/bash
# E2E Security Tests — Authorization, token validation, role enforcement
# Requires: docker compose services running (server + postgres + dev-init)
# Usage: ./dev/e2e-security.sh

set -euo pipefail
cd "$(dirname "$0")/.."
source "$(dirname "$0")/helpers.sh"

echo ""
echo "=== E2E Security Tests ==="
echo ""

# Create tokens via docker compose exec (tokens live in Docker volume, not host filesystem)
ADMIN_TOKEN=$(docker compose exec -T dbward-server dbward server token create --user e2e-admin --role admin --data /data/dbward.db 2>/dev/null | grep -o 'dbw_[a-z0-9]*')
DEV_TOKEN=$(docker compose exec -T dbward-server dbward server token create --user e2e-dev --role developer --data /data/dbward.db 2>/dev/null | grep -o 'dbw_[a-z0-9]*')
READONLY_TOKEN=$(docker compose exec -T dbward-server dbward server token create --user e2e-readonly --role readonly --data /data/dbward.db 2>/dev/null | grep -o 'dbw_[a-z0-9]*')
AGENT_TOKEN=$(docker compose exec -T dbward-server dbward server token create --user agent1 --role admin --agent --data /data/dbward.db 2>/dev/null | grep -o 'dbw_[a-z0-9]*')

[ -z "$ADMIN_TOKEN" ] && { echo "Failed to create admin token"; exit 1; }
[ -z "$DEV_TOKEN" ] && { echo "Failed to create dev token"; exit 1; }

# --- 1. No auth → 401 ---
echo "--- Authentication tests ---"

STATUS=$(api_noauth GET /api/requests)
[ "$STATUS" = "401" ] && pass "GET /api/requests without auth → 401" || fail "No auth" "got $STATUS"

STATUS=$(api_noauth POST /api/requests -d '{}')
[ "$STATUS" = "401" ] && pass "POST /api/requests without auth → 401" || fail "No auth POST" "got $STATUS"

STATUS=$(api_noauth GET /api/audit)
[ "$STATUS" = "401" ] && pass "GET /api/audit without auth → 401" || fail "No auth audit" "got $STATUS"

STATUS=$(api_noauth GET /api/workflows)
[ "$STATUS" = "401" ] && pass "GET /api/workflows without auth → 401" || fail "No auth workflows" "got $STATUS"

# --- 2. Invalid token → 401 ---
echo ""
echo "--- Invalid token tests ---"

STATUS=$(api_status GET /api/requests "dbw_invalidtoken12345678")
[ "$STATUS" = "401" ] && pass "Invalid token → 401" || fail "Invalid token" "got $STATUS"

STATUS=$(api_status GET /api/requests "not_a_token_at_all")
[ "$STATUS" = "401" ] && pass "Malformed token → 401" || fail "Malformed token" "got $STATUS"

# --- 3. Role enforcement ---
echo ""
echo "--- Role enforcement tests ---"

if [ -n "$ADMIN_TOKEN" ]; then
  # Admin can list all
  STATUS=$(api_status GET /api/requests "$ADMIN_TOKEN")
  [ "$STATUS" = "200" ] && pass "Admin can list requests" || fail "Admin list" "got $STATUS"

  # Admin can CRUD policies
  STATUS=$(api_status GET /api/workflows "$ADMIN_TOKEN")
  [ "$STATUS" = "200" ] && pass "Admin can list workflows" || fail "Admin workflows" "got $STATUS"

  # Admin cannot use agent endpoints
  STATUS=$(api_status POST /api/agent/poll "$ADMIN_TOKEN" -d '{}')
  [ "$STATUS" = "403" ] && pass "Admin (user) cannot poll agent endpoint" || fail "Admin agent poll" "got $STATUS"
fi

if [ -n "$DEV_TOKEN" ]; then
  # Developer cannot CRUD policies
  STATUS=$(api_status GET /api/workflows "$DEV_TOKEN")
  [ "$STATUS" = "403" ] && pass "Developer cannot list workflows" || fail "Dev workflows" "got $STATUS"

  STATUS=$(api_status POST /api/workflows "$DEV_TOKEN" -d '{"database":"x","environment":"y"}')
  [ "$STATUS" = "403" ] && pass "Developer cannot create workflow" || fail "Dev create workflow" "got $STATUS"
fi

if [ -n "${READONLY_TOKEN:-}" ]; then
  # Readonly can create SELECT request
  STATUS=$(api_status POST /api/requests "$READONLY_TOKEN" -d '{"operation":"execute_query","environment":"development","database":"app","detail":"SELECT 1"}')
  [ "$STATUS" = "201" ] && pass "Readonly can create SELECT request" || fail "Readonly create SELECT" "got $STATUS"

  # Readonly cannot create DML request
  STATUS=$(api_status POST /api/requests "$READONLY_TOKEN" -d '{"operation":"execute_query","environment":"development","database":"app","detail":"DELETE FROM users"}')
  [ "$STATUS" = "403" ] && pass "Readonly cannot create DML request" || fail "Readonly create DML" "got $STATUS"

  # Readonly can read own audit
  STATUS=$(api_status GET "/api/audit?user=e2e-readonly" "$READONLY_TOKEN")
  [ "$STATUS" = "200" ] && pass "Readonly can read own audit" || fail "Readonly audit" "got $STATUS"
fi

if [ -n "${AGENT_TOKEN:-}" ]; then
  # Agent can poll
  STATUS=$(api_status POST /api/agent/poll "$AGENT_TOKEN" -d '{"databases":["*"],"environments":["*"],"operations":["*"]}')
  [ "$STATUS" = "200" ] && pass "Agent can poll" || fail "Agent poll" "got $STATUS"

  # Agent cannot create request
  STATUS=$(api_status POST /api/requests "$AGENT_TOKEN" -d '{"operation":"execute_query","environment":"development","detail":"SELECT 1"}')
  [ "$STATUS" = "403" ] && pass "Agent cannot create request" || fail "Agent create" "got $STATUS"

  # Agent cannot list requests
  STATUS=$(api_status GET /api/requests "$AGENT_TOKEN")
  [ "$STATUS" = "403" ] && pass "Agent cannot list requests" || fail "Agent list" "got $STATUS"

  # Agent cannot read audit
  STATUS=$(api_status GET /api/audit "$AGENT_TOKEN")
  [ "$STATUS" = "403" ] && pass "Agent cannot read audit" || fail "Agent audit" "got $STATUS"
fi

# --- 4. Cross-role isolation ---
echo ""
echo "--- Cross-role isolation ---"

if [ -n "$ADMIN_TOKEN" ] && [ -n "$DEV_TOKEN" ]; then
  # Dev creates request, other dev cannot see it
  REQ_ID=$(api POST /api/requests "$DEV_TOKEN" -d '{"operation":"execute_query","environment":"production","detail":"SELECT 1","database":"default","reason":"security test"}' | json_field id)
  if [ -n "$REQ_ID" ]; then
    pass "Developer created request: ${REQ_ID:0:8}"

    # Admin can see it
    STATUS=$(api_status GET "/api/requests/$REQ_ID" "$ADMIN_TOKEN")
    [ "$STATUS" = "200" ] && pass "Admin can see developer's request" || fail "Admin get dev request" "got $STATUS"
  fi
fi

summary
