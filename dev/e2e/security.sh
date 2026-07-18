#!/bin/bash
# E2E Security Tests — Authorization, token validation, role enforcement
# Requires: docker compose services running (server + postgres + dev-init)
# Usage: ./dev/e2e-security.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."
source "$SCRIPT_DIR/helpers.sh"

echo ""
echo "=== E2E Security Tests ==="
echo ""

# Create tokens via docker compose exec (tokens live in Docker volume, not host filesystem)
ADMIN_TOKEN=$(create_token e2e-admin admin)
DEV_TOKEN=$(create_token e2e-dev requester)
READONLY_TOKEN=$(create_token e2e-readonly approver)
AGENT_TOKEN=$(create_token agent1 agent-default --agent)

[ -z "$ADMIN_TOKEN" ] && { echo "Failed to create admin token"; exit 1; }
[ -z "$DEV_TOKEN" ] && { echo "Failed to create dev token"; exit 1; }

# --- 1. No auth → 401 ---
echo "--- Authentication tests ---"

STATUS=$(api_noauth GET /api/requests)
[ "$STATUS" = "401" ] && pass "GET /api/requests without auth → 401" || fail "No auth" "got $STATUS"

STATUS=$(api_noauth POST /api/requests -d '{}')
[ "$STATUS" = "401" ] && pass "POST /api/requests without auth → 401" || fail "No auth POST" "got $STATUS"

STATUS=$(api_noauth GET /api/audit/events)
[ "$STATUS" = "401" ] && pass "GET /api/audit/events without auth → 401" || fail "No auth audit" "got $STATUS"

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
  # Admin cannot list requests (no request.view in new model)
  STATUS=$(api_status GET /api/requests "$ADMIN_TOKEN")
  [ "$STATUS" = "403" ] && pass "Admin cannot list requests (no request.view)" || fail "Admin list" "got $STATUS"

  # Admin can CRUD policies/workflows
  STATUS=$(api_status GET /api/workflows "$ADMIN_TOKEN")
  [ "$STATUS" = "200" ] && pass "Admin can list workflows" || fail "Admin workflows" "got $STATUS"

  # Admin cannot use agent endpoints
  STATUS=$(api_status POST /api/agent/poll "$ADMIN_TOKEN" -d '{"capabilities":{"scopes":[{"database":"app","environment":"development"}]}}')
  [ "$STATUS" = "403" ] && pass "Admin (user) cannot poll agent endpoint" || fail "Admin agent poll" "got $STATUS"
fi

if [ -n "$DEV_TOKEN" ]; then
  # Developer can list workflows (has workflow.read) but cannot create
  STATUS=$(api_status GET /api/workflows "$DEV_TOKEN")
  [ "$STATUS" = "200" ] && pass "Developer can list workflows" || fail "Dev workflows" "got $STATUS"

  STATUS=$(api_status POST /api/workflows "$DEV_TOKEN" -d '{"database":"x","environment":"y"}')
  [ "$STATUS" = "405" ] && pass "Developer cannot create workflow (405 config-managed)" || fail "Dev create workflow" "got $STATUS"
fi

if [ -n "${READONLY_TOKEN:-}" ]; then
  # Approver cannot create SELECT request (no request.query permission)
  STATUS=$(api_status POST /api/requests "$READONLY_TOKEN" -d '{"operation":"execute_query","environment":"development","database":"app","detail":"SELECT 1"}')
  [ "$STATUS" = "403" ] && pass "Approver cannot create SELECT request (no request.query)" || fail "Approver create SELECT" "got $STATUS"

  # Approver cannot create DML request
  STATUS=$(api_status POST /api/requests "$READONLY_TOKEN" -d '{"operation":"execute_dml","environment":"development","database":"app","detail":"DELETE FROM users WHERE id = 999"}')
  [ "$STATUS" = "403" ] && pass "Approver cannot create DML request" || fail "Approver create DML" "got $STATUS"

  # Approver cannot read audit (no audit.read)
  STATUS=$(api_status GET "/api/audit/events?user=e2e-readonly" "$READONLY_TOKEN")
  [ "$STATUS" = "403" ] && pass "Approver cannot read audit (no audit.read)" || fail "Approver audit" "got $STATUS"
fi

if [ -n "${AGENT_TOKEN:-}" ]; then
  # Agent can poll
  STATUS=$(api_status POST /api/agent/poll "$AGENT_TOKEN" -d '{"capabilities":{"scopes":[{"database":"app","environment":"development"}]}}')
  [ "$STATUS" = "200" ] && pass "Agent can poll" || fail "Agent poll" "got $STATUS"

  # Agent cannot create request
  STATUS=$(api_status POST /api/requests "$AGENT_TOKEN" -d '{"operation":"execute_query","environment":"development","database":"app","detail":"SELECT 1"}')
  [ "$STATUS" = "403" ] && pass "Agent cannot create request" || fail "Agent create" "got $STATUS"

  # Agent cannot list requests
  STATUS=$(api_status GET /api/requests "$AGENT_TOKEN")
  [ "$STATUS" = "403" ] && pass "Agent cannot list requests" || fail "Agent list" "got $STATUS"

  # Agent cannot read audit
  STATUS=$(api_status GET /api/audit/events "$AGENT_TOKEN")
  [ "$STATUS" = "403" ] && pass "Agent cannot read audit" || fail "Agent audit" "got $STATUS"
fi

# --- 4. Cross-role isolation ---
echo ""
echo "--- Cross-role isolation ---"

# Create an operator token to test request visibility (operator has request.view:Any)
OPERATOR_TOKEN=$(create_token e2e-operator operator)

if [ -n "${OPERATOR_TOKEN:-}" ] && [ -n "$DEV_TOKEN" ]; then
  # Dev creates request, operator can see it (request.view:Any)
  REQ_ID=$(api POST /api/requests "$DEV_TOKEN" -d '{"operation":"execute_query","environment":"production","detail":"SELECT 1","database":"default","reason":"security test"}' | json_field id)
  if [ -n "$REQ_ID" ]; then
    pass "Developer created request: ${REQ_ID:0:8}"

    # Operator can see it (has request.view:Any)
    STATUS=$(api_status GET "/api/requests/$REQ_ID" "$OPERATOR_TOKEN")
    [ "$STATUS" = "200" ] && pass "Operator can see requester's request (request.view:Any)" || fail "Operator get dev request" "got $STATUS"

    # Admin cannot see it (no request.view)
    STATUS=$(api_status GET "/api/requests/$REQ_ID" "$ADMIN_TOKEN")
    [ "$STATUS" = "403" ] && pass "Admin cannot see requester's request (no request.view)" || fail "Admin get dev request" "got $STATUS"
  fi
fi

# --- 5. Break-glass boundary: operator vs admin ---
echo ""
echo "--- Break-glass boundary ---"

# Admin alone cannot break-glass (no request.break_glass_*)
ADMIN_ONLY_TOKEN=$(create_token "sec-admin-only" admin)
if [ -n "$ADMIN_ONLY_TOKEN" ]; then
  STATUS=$(api_status POST /api/requests "$ADMIN_ONLY_TOKEN" \
    -d '{"operation":"execute_select","environment":"production","database":"app","detail":"SELECT 1","emergency":true,"reason":"admin emergency"}')
  [ "$STATUS" = "403" ] && pass "Admin alone cannot break-glass (403)" || fail "Admin break-glass" "got $STATUS"
fi

# Operator alone can break-glass
OPERATOR_ONLY_TOKEN=$(create_token "sec-operator-only" operator)
if [ -n "$OPERATOR_ONLY_TOKEN" ]; then
  STATUS=$(api_status POST /api/requests "$OPERATOR_ONLY_TOKEN" \
    -d '{"operation":"execute_select","environment":"production","database":"app","detail":"SELECT 1","emergency":true,"reason":"operator emergency"}')
  [ "$STATUS" = "201" ] && pass "Operator alone can break-glass (201)" || fail "Operator break-glass" "got $STATUS"
fi

# --- 6. Approval is selector-only (no system role dependency) ---
echo ""
echo "--- Selector-only approval ---"

# Create a request from dev
REQ_FOR_APPROVAL=$(api POST /api/requests "$DEV_TOKEN" \
  -d '{"operation":"execute_query","environment":"production","database":"app","detail":"SELECT 2","reason":"selector test"}' | json_field id)

if [ -n "$REQ_FOR_APPROVAL" ]; then
  # User with NO system role but matching group selector can approve
  # workflow for production requires group:backend-team or group:dba-team
  PLAIN_USER_TOKEN=$(create_token "sec-plain-approver" requester --groups backend-team)
  if [ -n "$PLAIN_USER_TOKEN" ]; then
    STATUS=$(api_status POST "/api/requests/$REQ_FOR_APPROVAL/approve" "$PLAIN_USER_TOKEN" \
      -d '{"comment":"selector-only"}')
    [ "$STATUS" = "200" ] && pass "Plain user with matching selector can approve" || fail "Selector approve" "got $STATUS"
  fi

  # User with admin role but NO matching selector cannot approve
  REQ2=$(api POST /api/requests "$DEV_TOKEN" \
    -d '{"operation":"execute_query","environment":"production","database":"app","detail":"SELECT 3","reason":"selector test 2"}' | json_field id)
  if [ -n "$REQ2" ]; then
    # admin without backend-team or dba-team group
    ADMIN_NO_GROUP_TOKEN=$(create_token "sec-admin-no-group" admin)
    if [ -n "$ADMIN_NO_GROUP_TOKEN" ]; then
      STATUS=$(api_status POST "/api/requests/$REQ2/approve" "$ADMIN_NO_GROUP_TOKEN" \
        -d '{"comment":"should fail"}')
      [ "$STATUS" = "403" ] && pass "Admin without matching selector cannot approve (403)" || fail "Admin no-selector approve" "got $STATUS"
    fi
  fi
fi

summary
