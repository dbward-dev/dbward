#!/bin/bash
# E2E PRE-1 Preflight Tests
# Requires: docker compose services running (server + agent + postgres)
# Usage: ./dev/e2e/preflight.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

echo ""
echo "=== E2E PRE-1: Preflight Tests ==="
echo ""

TOKEN=$(create_token preflight-tester admin)
[ -z "$TOKEN" ] && { echo "Failed to create token"; exit 1; }

# --- 1. SELECT → requestable (no EXPLAIN needed for read-only auto-approve) ---
echo "--- 1. SELECT → requestable ---"

RESP=$(api POST /api/preflight "$TOKEN" \
  -d '{"database":"app","environment":"development","sql":"SELECT * FROM users WHERE id = 1","include_explain":false}')
STATUS=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])")
RISK=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['risk'])")
[ "$STATUS" = "requestable" ] && pass "SELECT → requestable" || fail "SELECT preflight" "status=$STATUS"
[ "$RISK" = "low" ] && pass "SELECT → risk=low" || fail "SELECT risk" "risk=$RISK"

# --- 2. UPDATE without WHERE → blocked with hints ---
echo ""
echo "--- 2. UPDATE without WHERE → blocked ---"

RESP=$(api POST /api/preflight "$TOKEN" \
  -d '{"database":"app","environment":"development","sql":"UPDATE users SET name = '\''x'\''","include_explain":false}')
STATUS=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])")
HINTS=$(echo "$RESP" | python3 -c "import sys,json; h=json.load(sys.stdin).get('fix_hints',[]); print(len(h))")
[ "$STATUS" = "blocked" ] && pass "UPDATE no WHERE → blocked" || fail "UPDATE preflight" "status=$STATUS"
[ "$HINTS" -gt 0 ] && pass "fix_hints populated ($HINTS hints)" || fail "fix_hints" "count=$HINTS"

# --- 3. include_explain=false → impact.status=skipped, fast response ---
echo ""
echo "--- 3. include_explain=false → skipped ---"

RESP=$(api POST /api/preflight "$TOKEN" \
  -d '{"database":"app","environment":"development","sql":"SELECT 1","include_explain":false}')
IMPACT_STATUS=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['impact']['status'])")
[ "$IMPACT_STATUS" = "skipped" ] && pass "include_explain=false → skipped" || fail "impact skipped" "status=$IMPACT_STATUS"

# --- 4. UPDATE with WHERE + EXPLAIN (agent running) ---
echo ""
echo "--- 4. UPDATE with WHERE + EXPLAIN ---"

RESP=$(api POST /api/preflight "$TOKEN" \
  -d '{"database":"app","environment":"development","sql":"UPDATE users SET name = '\''y'\'' WHERE id = 1","include_explain":true,"explain_timeout_ms":8000}')
STATUS=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])")
IMPACT_STATUS=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['impact']['status'])")
STMT_TYPE=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['classification']['statement_type'])")
# Status should be requestable or warning (depends on risk assessment)
[[ "$STATUS" = "requestable" || "$STATUS" = "warning" ]] && pass "UPDATE with WHERE → $STATUS" || fail "UPDATE+WHERE preflight" "status=$STATUS"
# EXPLAIN should complete or timeout (depends on agent speed)
[[ "$IMPACT_STATUS" = "completed" || "$IMPACT_STATUS" = "timeout" ]] && pass "EXPLAIN impact → $IMPACT_STATUS" || fail "EXPLAIN impact" "status=$IMPACT_STATUS"
[ "$STMT_TYPE" = "UPDATE" ] && pass "statement_type=UPDATE" || fail "statement_type" "got=$STMT_TYPE"

# --- 5. Short timeout → timeout status ---
echo ""
echo "--- 5. Short timeout → timeout ---"

RESP=$(api POST /api/preflight "$TOKEN" \
  -d '{"database":"app","environment":"development","sql":"UPDATE users SET name = '\''z'\'' WHERE id = 1","include_explain":true,"explain_timeout_ms":1}')
IMPACT_STATUS=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['impact']['status'])")
[ "$IMPACT_STATUS" = "timeout" ] && pass "1ms timeout → timeout" || fail "timeout" "status=$IMPACT_STATUS"

# --- 6. 401 without auth ---
echo ""
echo "--- 6. Auth required ---"

HTTP_STATUS=$(api_noauth POST /api/preflight \
  -d '{"database":"app","environment":"development","sql":"SELECT 1","include_explain":false}')
[ "$HTTP_STATUS" = "401" ] && pass "No auth → 401" || fail "No auth" "http=$HTTP_STATUS"

# --- 7. Invalid body → 422 ---
echo ""
echo "--- 7. Invalid body ---"

HTTP_STATUS=$(api_status POST /api/preflight "$TOKEN" \
  -d '{"invalid":"body"}')
[[ "$HTTP_STATUS" = "400" || "$HTTP_STATUS" = "422" ]] && pass "Invalid body → $HTTP_STATUS" || fail "Invalid body" "http=$HTTP_STATUS"

# --- 8. Classification fields ---
echo ""
echo "--- 8. Classification fields ---"

RESP=$(api POST /api/preflight "$TOKEN" \
  -d '{"database":"app","environment":"development","sql":"SELECT * FROM users","include_explain":false}')
MUTATING=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['classification']['mutating'])")
OPERATION=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['classification']['operation'])")
[ "$MUTATING" = "False" ] && pass "SELECT mutating=false" || fail "mutating" "got=$MUTATING"
[ "$OPERATION" = "execute_select" ] && pass "operation=execute_select" || fail "operation" "got=$OPERATION"

# --- 9. Policy simulation ---
echo ""
echo "--- 9. Policy fields ---"

RESP=$(api POST /api/preflight "$TOKEN" \
  -d '{"database":"app","environment":"development","sql":"SELECT 1","include_explain":false}')
CAN_SUBMIT=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['policy']['caller_can_submit'])")
[ "$CAN_SUBMIT" = "True" ] && pass "caller_can_submit=true" || fail "caller_can_submit" "got=$CAN_SUBMIT"

# --- 10. preview_impact removed ---
echo ""
echo "--- 10. preview_impact tool removed ---"

HTTP_STATUS=$(api_status POST /api/mcp "$TOKEN" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"dbward_preview_impact","arguments":{"sql":"SELECT 1"}}}')
RESP_ERR=$(echo "$LAST_RESPONSE_BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error',{}).get('message',''))" 2>/dev/null || echo "")
[[ -n "$RESP_ERR" || "$HTTP_STATUS" != "200" ]] && pass "preview_impact tool removed" || fail "preview_impact" "still exists?"

# --- Summary ---
echo ""
cleanup_tokens
echo "=== Results: $PASS passed, $FAIL failed ==="
[ $FAIL -gt 0 ] && exit 1 || exit 0
