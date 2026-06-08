#!/bin/bash
# E2E Policy Tests — Config-managed workflows + execution policy effects
# CFG-24: Workflows are config-managed. POST/DELETE return 405.
# Requires: docker compose services running (server + agent + postgres)

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."
source "$SCRIPT_DIR/helpers.sh"

echo ""
echo "=== E2E Policy Tests (CFG-24: Config-managed) ==="
echo ""

ADMIN_TOKEN=$(create_token e2e-admin admin)
DEV_TOKEN=$(create_token e2e-dev developer)
[ -z "$ADMIN_TOKEN" ] && { echo "Failed to create admin token"; exit 1; }

# --- 1. All Tier 1 write API returns 405 ---
echo "--- All Tier 1 write API → 405 ---"

STATUS=$(api_status POST /api/workflows "$ADMIN_TOKEN" \
  -d '{"database":"e2edb","environment":"staging","operations":["execute_select"],"steps":[]}')
[ "$STATUS" = "405" ] && pass "POST /api/workflows → 405" || fail "POST workflows" "got $STATUS"

STATUS=$(api_status DELETE /api/workflows/any-id "$ADMIN_TOKEN")
[ "$STATUS" = "405" ] && pass "DELETE /api/workflows/{id} → 405" || fail "DELETE workflows" "got $STATUS"

STATUS=$(api_status POST /api/execution-policies "$ADMIN_TOKEN" -d '{}')
[ "$STATUS" = "405" ] && pass "POST /api/execution-policies → 405" || fail "POST ep" "got $STATUS"

STATUS=$(api_status DELETE /api/execution-policies/any-id "$ADMIN_TOKEN")
[ "$STATUS" = "405" ] && pass "DELETE /api/execution-policies/{id} → 405" || fail "DELETE ep" "got $STATUS"

STATUS=$(api_status POST /api/result-policies "$ADMIN_TOKEN" -d '{}')
[ "$STATUS" = "405" ] && pass "POST /api/result-policies → 405" || fail "POST rp" "got $STATUS"

STATUS=$(api_status POST /api/notification-policies "$ADMIN_TOKEN" -d '{}')
[ "$STATUS" = "405" ] && pass "POST /api/notification-policies → 405" || fail "POST np" "got $STATUS"

STATUS=$(api_status POST /api/roles "$ADMIN_TOKEN" -d '{}')
[ "$STATUS" = "405" ] && pass "POST /api/roles → 405" || fail "POST roles" "got $STATUS"

STATUS=$(api_status DELETE /api/roles/any-name "$ADMIN_TOKEN")
[ "$STATUS" = "405" ] && pass "DELETE /api/roles/{name} → 405" || fail "DELETE roles" "got $STATUS"

# --- 2. Config-synced workflows appear in list ---
echo ""
echo "--- Config-synced workflows visible via GET ---"

RESP=$(api GET /api/workflows "$ADMIN_TOKEN")
STATUS=$(echo "$RESP" | python3 -c "import sys,json; json.load(sys.stdin); print('200')" 2>/dev/null || echo "error")
[ "$STATUS" = "200" ] && pass "GET /api/workflows → 200" || fail "GET workflows" "got non-JSON response"

# server.toml defines at least one workflow
COUNT=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('workflows',[])))" 2>/dev/null || echo "0")
[ "$COUNT" -ge 1 ] && pass "At least 1 config-synced workflow listed ($COUNT)" || fail "Workflow count" "$COUNT"

# --- 3. Execution Policy effect ---
echo ""
echo "--- Execution Policy effect ---"

# Production has max_executions=1. Create, approve, wait for execution, then try re-resume.
REQ=$(api POST /api/requests "$ADMIN_TOKEN" \
  -d '{"database":"app","environment":"production","detail":"SELECT 1","reason":"e2e policy test"}')
REQ_ID=$(echo "$REQ" | json_field id)

if [ -n "$REQ_ID" ]; then
  # Approve (admin has approver role)
  api POST "/api/requests/$REQ_ID/approve" "$ADMIN_TOKEN" -d '{}' >/dev/null
  sleep 5

  # Try to re-resume → should be blocked by max_executions=1 (already executed once)
  STATUS=$(api_status POST "/api/requests/$REQ_ID/resume" "$ADMIN_TOKEN" -d '{}')
  if [ "$STATUS" = "409" ] || [ "$STATUS" = "410" ]; then
    pass "Re-resume blocked by execution policy ($STATUS)"
  else
    fail "Execution policy" "got $STATUS (expected 409 or 410)"
  fi
else
  skip "Could not create request for execution policy test"
fi

# --- 4. Developer: POST still returns 405 (not 403, because 405 takes precedence) ---
echo ""
echo "--- Developer workflow access ---"

STATUS=$(api_status POST /api/workflows "$DEV_TOKEN" -d '{"database":"x","environment":"y","operations":["execute_select"],"steps":[]}')
[ "$STATUS" = "405" ] && pass "Developer POST /api/workflows → 405" || fail "Dev workflow create" "got $STATUS"

summary
