#!/bin/bash
# E2E Policy Tests — CRUD operations and policy effects
# Requires: docker compose services running (server + agent + postgres)
# Usage: ./dev/e2e-policy.sh

set -euo pipefail
cd "$(dirname "$0")/.."
source dev/e2e-helpers.sh

echo ""
echo "=== E2E Policy Tests ==="
echo ""

ADMIN_TOKEN=$(docker compose exec -T dbward-server /app/dbward server token create --user alice --role admin --data /data 2>/dev/null | grep -o 'dbw_[a-z0-9]*')
DEV_TOKEN=$(docker compose exec -T dbward-server /app/dbward server token create --user bob --role developer --data /data 2>/dev/null | grep -o 'dbw_[a-z0-9]*')
[ -z "$ADMIN_TOKEN" ] && { echo "Failed to create admin token"; exit 1; }

# --- 1. Workflow CRUD ---
echo "--- Workflow CRUD ---"

# Create
STATUS=$(api_status POST /api/workflows "$ADMIN_TOKEN" \
  -d '{"database":"e2edb","environment":"staging","steps":[]}')
[ "$STATUS" = "201" ] && pass "Create workflow → 201" || fail "Create workflow" "got $STATUS"

# List
RESP=$(api GET /api/workflows "$ADMIN_TOKEN")
HAS=$(echo "$RESP" | python3 -c "import sys,json; ws=json.load(sys.stdin).get('workflows',[]); print('yes' if any(w['id']=='e2edb:staging' for w in ws) else 'no')")
[ "$HAS" = "yes" ] && pass "Workflow appears in list" || fail "Workflow list" "not found"

# Get
STATUS=$(api_status GET /api/workflows/e2edb:staging "$ADMIN_TOKEN")
[ "$STATUS" = "200" ] && pass "Get workflow → 200" || fail "Get workflow" "got $STATUS"

# Update
STATUS=$(api_status PUT /api/workflows/e2edb:staging "$ADMIN_TOKEN" \
  -d '{"require_reason":true}')
[ "$STATUS" = "200" ] && pass "Update workflow → 200" || fail "Update workflow" "got $STATUS"

# Delete
STATUS=$(api_status DELETE /api/workflows/e2edb:staging "$ADMIN_TOKEN")
[ "$STATUS" = "200" ] && pass "Delete workflow → 200" || fail "Delete workflow" "got $STATUS"

# Get after delete → 404
STATUS=$(api_status GET /api/workflows/e2edb:staging "$ADMIN_TOKEN")
[ "$STATUS" = "404" ] && pass "Deleted workflow → 404" || fail "Deleted workflow" "got $STATUS"

# --- 2. Execution Policy effect ---
echo ""
echo "--- Execution Policy effect ---"

# Create execution policy: max_executions=1
api POST /api/execution-policies "$ADMIN_TOKEN" \
  -d '{"database":"app","environment":"development","max_executions":1,"retry_on_failure":false}' >/dev/null

# Create and execute a request
REQ=$(api POST /api/requests "$DEV_TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"app","detail":"SELECT 1"}')
REQ_ID=$(echo "$REQ" | json_field id)
sleep 4

# Try to re-dispatch → should be blocked by max_executions
STATUS=$(api_status POST "/api/requests/$REQ_ID/dispatch" "$DEV_TOKEN" -d '{}')
if [ "$STATUS" = "409" ] || [ "$STATUS" = "410" ]; then
  pass "Re-dispatch blocked by execution policy ($STATUS)"
else
  fail "Execution policy" "got $STATUS (expected 409 or 410)"
fi

# Cleanup
api DELETE /api/execution-policies/default:development "$ADMIN_TOKEN" >/dev/null 2>&1

# --- 3. Developer cannot CRUD policies ---
echo ""
echo "--- Developer policy access denied ---"

STATUS=$(api_status GET /api/workflows "$DEV_TOKEN")
[ "$STATUS" = "403" ] && pass "Developer cannot list workflows" || fail "Dev policy access" "got $STATUS"

STATUS=$(api_status POST /api/execution-policies "$DEV_TOKEN" -d '{"database":"x","environment":"y"}')
[ "$STATUS" = "403" ] && pass "Developer cannot create execution policy" || fail "Dev exec policy" "got $STATUS"

# --- 4. Duplicate creation → 409 ---
echo ""
echo "--- Duplicate policy creation ---"

api POST /api/workflows "$ADMIN_TOKEN" -d '{"database":"dupdb","environment":"prod"}' >/dev/null
STATUS=$(api_status POST /api/workflows "$ADMIN_TOKEN" -d '{"database":"dupdb","environment":"prod"}')
[ "$STATUS" = "409" ] && pass "Duplicate workflow → 409" || fail "Duplicate" "got $STATUS"

# Cleanup
api DELETE /api/workflows/dupdb:prod "$ADMIN_TOKEN" >/dev/null 2>&1

summary
