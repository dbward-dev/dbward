#!/bin/bash
# E2E Policy Tests — CRUD operations and policy effects
# Requires: docker compose services running (server + agent + postgres)

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."
source "$SCRIPT_DIR/helpers.sh"

echo ""
echo "=== E2E Policy Tests ==="
echo ""

ADMIN_TOKEN=$(create_token e2e-admin admin)
DEV_TOKEN=$(create_token e2e-dev developer)
[ -z "$ADMIN_TOKEN" ] && { echo "Failed to create admin token"; exit 1; }

# --- 1. Workflow CRUD ---
echo "--- Workflow CRUD ---"

# Create
RESP=$(api POST /api/workflows "$ADMIN_TOKEN" \
  -d '{"database":"e2edb","environment":"staging","operations":["execute_select"],"steps":[]}')
WF_ID=$(echo "$RESP" | json_field id)
[ -n "$WF_ID" ] && pass "Create workflow → $WF_ID" || fail "Create workflow" "no id"

# List
RESP=$(api GET /api/workflows "$ADMIN_TOKEN")
HAS=$(echo "$RESP" | python3 -c "import sys,json; ws=json.load(sys.stdin).get('workflows',[]); print('yes' if any(w.get('database')=='e2edb' and w.get('environment')=='staging' for w in ws) else 'no')")
[ "$HAS" = "yes" ] && pass "Workflow appears in list" || fail "Workflow list" "not found"

# Get single → 501 (not implemented yet)
STATUS=$(api_status GET "/api/workflows/$WF_ID" "$ADMIN_TOKEN")
[ "$STATUS" = "501" ] && pass "Get single workflow → 501 (not implemented)" || fail "Get workflow" "got $STATUS"

# Delete
STATUS=$(api_status DELETE "/api/workflows/$WF_ID" "$ADMIN_TOKEN")
[ "$STATUS" = "204" ] && pass "Delete workflow → 204" || fail "Delete workflow" "got $STATUS"

# Verify deleted (not in list)
RESP=$(api GET /api/workflows "$ADMIN_TOKEN")
GONE=$(echo "$RESP" | python3 -c "import sys,json; ws=json.load(sys.stdin).get('workflows',[]); print('yes' if not any(w.get('id')=='$WF_ID' for w in ws) else 'no')")
[ "$GONE" = "yes" ] && pass "Deleted workflow gone from list" || fail "Deleted still visible" ""

# --- 2. Execution Policy effect ---
echo ""
echo "--- Execution Policy effect ---"

# Create and execute a request (dev env auto-approves)
REQ=$(api POST /api/requests "$DEV_TOKEN" \
  -d '{"database":"app","environment":"development","detail":"SELECT 1"}')
REQ_ID=$(echo "$REQ" | json_field id)
sleep 4

# Try to re-resume → should be blocked by max_executions (config default=3, already used)
STATUS=$(api_status POST "/api/requests/$REQ_ID/resume" "$ADMIN_TOKEN" -d '{}')
if [ "$STATUS" = "409" ] || [ "$STATUS" = "410" ]; then
  pass "Re-resume blocked by execution policy ($STATUS)"
else
  fail "Execution policy" "got $STATUS (expected 409 or 410)"
fi

# --- 3. Developer cannot CRUD policies ---
echo ""
echo "--- Developer policy access denied ---"

STATUS=$(api_status GET /api/workflows "$DEV_TOKEN")
[ "$STATUS" = "403" ] && pass "Developer cannot list workflows" || fail "Dev workflow access" "got $STATUS"

STATUS=$(api_status POST /api/workflows "$DEV_TOKEN" -d '{"database":"x","environment":"y","operations":["execute_select"],"steps":[]}')
[ "$STATUS" = "403" ] && pass "Developer cannot create workflow" || fail "Dev workflow create" "got $STATUS"

# --- 4. Duplicate creation → 409 ---
echo ""
echo "--- Duplicate policy creation ---"

api POST /api/workflows "$ADMIN_TOKEN" -d '{"database":"dupdb","environment":"staging","operations":["execute_select"],"steps":[]}' >/dev/null
STATUS=$(api_status POST /api/workflows "$ADMIN_TOKEN" -d '{"database":"dupdb","environment":"staging","operations":["execute_select"],"steps":[]}')
[ "$STATUS" = "409" ] && pass "Duplicate workflow → 409" || fail "Duplicate" "got $STATUS"

summary
