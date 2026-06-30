#!/bin/bash
# E2E Security: Authorization escalation
# Tests self-approval, cross-environment access, agent impersonation.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."
source "$SCRIPT_DIR/helpers.sh"

echo ""
echo "=== Authorization Escalation Tests ==="
echo ""

ADMIN_TOKEN=$(docker compose exec -T dbward-server cat /data/admin-token 2>/dev/null || echo "")
DEV_TOKEN=$(create_token e2e-authz-dev developer)
AGENT_TOKEN=$(create_token e2e-authz-agent agent-default --agent)
[ -z "$ADMIN_TOKEN" ] && { echo "Failed to create tokens"; exit 1; }

# --- Self-approval ---
echo "--- Self-approval prevention ---"

# Developer creates a request
RESP=$(api POST /api/requests "$DEV_TOKEN" \
  -d '{"detail":"DELETE FROM logs","database":"app","environment":"staging"}')
REQ_ID=$(echo "$RESP" | json_field id)

if [ -n "$REQ_ID" ]; then
  # Same user tries to approve their own request
  STATUS=$(api_status POST "/api/requests/$REQ_ID/approve" "$DEV_TOKEN" -d '{"comment":"self-approve"}')
  [ "$STATUS" = "403" ] || [ "$STATUS" = "409" ] && pass "Self-approval rejected ($STATUS)" || fail "Self-approval" "got $STATUS"
else
  skip "Could not create request for self-approval test"
fi

# --- Agent cannot create requests ---
echo ""
echo "--- Agent impersonation ---"

STATUS=$(api_status POST /api/requests "$AGENT_TOKEN" \
  -d '{"detail":"SELECT 1","database":"app","environment":"development"}')
[ "$STATUS" = "403" ] && pass "Agent cannot create requests" || fail "Agent create request" "got $STATUS"

# Agent cannot approve
if [ -n "$REQ_ID" ]; then
  STATUS=$(api_status POST "/api/requests/$REQ_ID/approve" "$AGENT_TOKEN" -d '{}')
  [ "$STATUS" = "403" ] && pass "Agent cannot approve requests" || fail "Agent approve" "got $STATUS"
fi

# --- Developer cannot manage workflows ---
echo ""
echo "--- Developer privilege boundaries ---"

STATUS=$(api_status POST /api/workflows "$DEV_TOKEN" \
  -d '{"database":"*","environment":"*","steps":[]}')
[ "$STATUS" = "405" ] && pass "Developer cannot create workflow (405 config-managed)" || fail "Dev workflow create" "got $STATUS"

STATUS=$(api_status GET /api/workflows "$DEV_TOKEN")
[ "$STATUS" = "403" ] || [ "$STATUS" = "200" ] && pass "Developer workflow list ($STATUS)" || fail "Dev workflow list" "got $STATUS"

# --- Developer cannot manage users ---
echo ""
echo "--- User management boundaries ---"

STATUS=$(api_status POST /api/users/someone/suspend "$DEV_TOKEN")
[ "$STATUS" = "403" ] && pass "Developer cannot suspend users" || fail "Dev suspend" "got $STATUS"

STATUS=$(api_status GET /api/tokens "$DEV_TOKEN")
[ "$STATUS" = "403" ] && pass "Developer cannot list tokens" || fail "Dev list tokens" "got $STATUS"

# --- Cross-role: readonly cannot execute DML ---
echo ""
echo "--- Readonly boundaries ---"

READONLY_TOKEN=$(create_token e2e-authz-ro readonly)
STATUS=$(api_status POST /api/requests "$READONLY_TOKEN" \
  -d '{"detail":"DELETE FROM users","database":"app","environment":"development"}')
[ "$STATUS" = "403" ] || [ "$STATUS" = "400" ] && pass "Readonly cannot execute DML ($STATUS)" || fail "Readonly DML" "got $STATUS"

# --- Bootstrap agent token cannot access non-agent endpoints ---
echo ""
echo "--- Bootstrap agent token isolation ---"

# Read bootstrap agent token directly (this is the token auto_bootstrap creates)
BOOTSTRAP_AGENT_TOKEN=$(docker compose exec -T dbward-server cat /data/agent-token 2>/dev/null || echo "")
if [ -n "$BOOTSTRAP_AGENT_TOKEN" ]; then
  # /api/me has no authorizer call — proves middleware path restriction works
  STATUS=$(api_status GET /api/me "$BOOTSTRAP_AGENT_TOKEN")
  [ "$STATUS" = "403" ] && pass "Bootstrap agent token cannot GET /api/me" || fail "Agent /api/me" "got $STATUS"

  STATUS=$(api_status POST /api/requests "$BOOTSTRAP_AGENT_TOKEN" \
    -d '{"detail":"SELECT 1","database":"app","environment":"development"}')
  [ "$STATUS" = "403" ] && pass "Bootstrap agent token cannot create requests" || fail "Agent create request" "got $STATUS"

  STATUS=$(api_status GET /api/workflows "$BOOTSTRAP_AGENT_TOKEN")
  [ "$STATUS" = "403" ] && pass "Bootstrap agent token cannot list workflows" || fail "Agent list workflows" "got $STATUS"

  STATUS=$(api_status GET /api/tokens "$BOOTSTRAP_AGENT_TOKEN")
  [ "$STATUS" = "403" ] && pass "Bootstrap agent token cannot list tokens" || fail "Agent list tokens" "got $STATUS"

  STATUS=$(api_status POST /api/users/someone/suspend "$BOOTSTRAP_AGENT_TOKEN")
  [ "$STATUS" = "403" ] && pass "Bootstrap agent token cannot suspend users" || fail "Agent suspend user" "got $STATUS"

  # Agent endpoint should still work (poll returns 200 even with empty capabilities)
  STATUS=$(api_status POST /api/agent/poll "$BOOTSTRAP_AGENT_TOKEN" \
    -d '{"capabilities":{"scopes":[{"database":"app","environment":"development"}]},"limit":1}')
  [ "$STATUS" = "200" ] && pass "Bootstrap agent token can still poll" || fail "Agent poll" "got $STATUS"

  # Public key endpoint should work for agents
  STATUS=$(api_status GET /api/public-key "$BOOTSTRAP_AGENT_TOKEN")
  [ "$STATUS" = "200" ] && pass "Bootstrap agent token can get public key" || fail "Agent public-key" "got $STATUS"
else
  skip "Bootstrap agent token not found (skipping agent isolation tests)"
fi

# --- Agent token creation with scope_ceiling ---
echo ""
echo "--- Agent token scope enforcement ---"

# Agent token with admin scope_ceiling should be rejected (agents cannot have user-level scope)
STATUS=$(api_status POST /api/tokens "$ADMIN_TOKEN" \
  -d '{"subject_id":"evil-agent","scope_ceiling":{"roles":["admin"]},"subject_type":"agent"}')
[ "$STATUS" = "400" ] && pass "Cannot create agent token with scope_ceiling" || fail "Agent scope_ceiling rejected" "got $STATUS"

# Agent token without scope_ceiling should succeed (agents don't need scope_ceiling)
STATUS=$(api_status POST /api/tokens "$ADMIN_TOKEN" \
  -d '{"subject_id":"good-agent","subject_type":"agent"}')
[ "$STATUS" = "200" ] || [ "$STATUS" = "201" ] && pass "Can create agent token without scope_ceiling" || fail "Agent token creation" "got $STATUS"

summary
