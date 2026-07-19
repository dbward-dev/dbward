#!/bin/bash
# Verification checklist for SLACK-10 authz redesign
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."
source "$SCRIPT_DIR/helpers.sh"

echo ""
echo "=== Verification Checklist: 権限モデル再設計 ==="
echo ""

# Setup tokens
ADMIN_TOKEN_RAW=$(docker compose exec -T dbward-server cat /data/admin-token)
REQUESTER_TOKEN=$(create_token "vc-req" requester)
OPERATOR_TOKEN=$(create_token "vc-op" operator)
APPROVER_TOKEN=$(create_token "vc-app" approver --groups backend-team)
ADMIN_ONLY_TOKEN=$(create_token "vc-adm" admin)

[ -z "$REQUESTER_TOKEN" ] && { echo "FATAL: requester token"; exit 1; }
[ -z "$OPERATOR_TOKEN" ] && { echo "FATAL: operator token"; exit 1; }
[ -z "$APPROVER_TOKEN" ] && { echo "FATAL: approver token"; exit 1; }
[ -z "$ADMIN_ONLY_TOKEN" ] && { echo "FATAL: admin token"; exit 1; }

echo "--- §1 Layer 1: Scope check ---"
STATUS=$(api_status POST /api/requests "$REQUESTER_TOKEN" \
  -d '{"operation":"execute_query","environment":"production","database":"nonexistent_db","detail":"SELECT 1"}')
[ "$STATUS" = "403" ] || [ "$STATUS" = "400" ] && pass "Scope外DB → rejected ($STATUS)" || fail "Scope外DB" "got $STATUS"

echo ""
echo "--- §1 Layer 2: Admin cannot bypass ---"
REQ=$(api POST /api/requests "$REQUESTER_TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"app","detail":"SELECT 1"}')
REQ_ID=$(echo "$REQ" | json_field id)
STATUS=$(api_status GET "/api/requests/$REQ_ID" "$ADMIN_ONLY_TOKEN")
[ "$STATUS" = "403" ] && pass "Admin(no request.view) cannot view request" || fail "Admin view" "got $STATUS"

echo ""
echo "--- §2.1 Ownership: request.view ---"
STATUS=$(api_status GET "/api/requests/$REQ_ID" "$OPERATOR_TOKEN")
[ "$STATUS" = "200" ] && pass "Operator(view:Any) views other's request" || fail "Op view" "got $STATUS"

STATUS=$(api_status GET "/api/requests/$REQ_ID" "$REQUESTER_TOKEN")
[ "$STATUS" = "200" ] && pass "Requester views own request" || fail "Req view own" "got $STATUS"

# Create operator's request, requester cannot view it
REQ_OP=$(api POST /api/requests "$OPERATOR_TOKEN" \
  -d '{"operation":"execute_select","environment":"development","database":"app","detail":"SELECT 99","emergency":true,"reason":"test"}')
REQ_OP_ID=$(echo "$REQ_OP" | json_field id)
STATUS=$(api_status GET "/api/requests/$REQ_OP_ID" "$REQUESTER_TOKEN")
[ "$STATUS" = "403" ] && pass "Requester(view:Own) cannot view other's request" || fail "Req view other" "got $STATUS"

echo ""
echo "--- §2.2 Ownership: request.cancel ---"
REQ_C=$(api POST /api/requests "$REQUESTER_TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"app","detail":"SELECT cancel"}')
REQ_C_ID=$(echo "$REQ_C" | json_field id)

STATUS=$(api_status POST "/api/requests/$REQ_C_ID/cancel" "$REQUESTER_TOKEN" -d '{}')
[ "$STATUS" = "200" ] && pass "Requester cancels own request" || fail "Req cancel own" "got $STATUS"

REQ_C2=$(api POST /api/requests "$REQUESTER_TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"app","detail":"SELECT cancel2"}')
REQ_C2_ID=$(echo "$REQ_C2" | json_field id)
STATUS=$(api_status POST "/api/requests/$REQ_C2_ID/cancel" "$OPERATOR_TOKEN" \
  -d '{"reason":"operator cancel"}')
[ "$STATUS" = "200" ] && pass "Operator(cancel:Any) cancels other's request" || fail "Op cancel" "got $STATUS"

echo ""
echo "--- §3 Approve: selector only ---"
REQ_A=$(api POST /api/requests "$REQUESTER_TOKEN" \
  -d '{"operation":"execute_query","environment":"production","database":"app","detail":"SELECT approve","reason":"test"}')
REQ_A_ID=$(echo "$REQ_A" | json_field id)

STATUS=$(api_status POST "/api/requests/$REQ_A_ID/approve" "$APPROVER_TOKEN" -d '{"comment":"ok"}')
[ "$STATUS" = "200" ] && pass "Approver(selector:backend-team) can approve" || fail "Approver approve" "got $STATUS"

REQ_A2=$(api POST /api/requests "$REQUESTER_TOKEN" \
  -d '{"operation":"execute_query","environment":"production","database":"app","detail":"SELECT approve2","reason":"test2"}')
REQ_A2_ID=$(echo "$REQ_A2" | json_field id)
STATUS=$(api_status POST "/api/requests/$REQ_A2_ID/approve" "$ADMIN_ONLY_TOKEN" -d '{"comment":"fail"}')
[ "$STATUS" = "403" ] && pass "Admin(no selector match) cannot approve" || fail "Admin approve" "got $STATUS"

echo ""
echo "--- §5 Break-glass ---"
STATUS=$(api_status POST /api/requests "$OPERATOR_TOKEN" \
  -d '{"operation":"execute_select","environment":"production","database":"app","detail":"SELECT bg","emergency":true,"reason":"incident"}')
[ "$STATUS" = "201" ] && pass "Operator can break-glass" || fail "Op break-glass" "got $STATUS"

STATUS=$(api_status POST /api/requests "$REQUESTER_TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"app","detail":"SELECT bg2","emergency":true,"reason":"test"}')
[ "$STATUS" = "403" ] && pass "Requester cannot break-glass" || fail "Req break-glass" "got $STATUS"

STATUS=$(api_status POST /api/requests "$ADMIN_ONLY_TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"app","detail":"SELECT bg3","emergency":true,"reason":"test"}')
[ "$STATUS" = "403" ] && pass "Admin cannot break-glass" || fail "Admin break-glass" "got $STATUS"

echo ""
echo "--- §6 Reason validation ---"
REQ_R=$(api POST /api/requests "$REQUESTER_TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"app","detail":"SELECT reason"}')
REQ_R_ID=$(echo "$REQ_R" | json_field id)
STATUS=$(api_status POST "/api/requests/$REQ_R_ID/cancel" "$OPERATOR_TOKEN" -d '{}')
[ "$STATUS" = "400" ] || [ "$STATUS" = "422" ] && pass "Non-owner cancel without reason → error" || fail "Reason cancel" "got $STATUS"

STATUS=$(api_status POST "/api/requests/$REQ_R_ID/cancel" "$OPERATOR_TOKEN" \
  -d '{"reason":"valid reason"}')
[ "$STATUS" = "200" ] && pass "Non-owner cancel with reason → success" || fail "Reason cancel ok" "got $STATUS"

echo ""
echo "--- §6.2 Resume reason validation ---"
# Create and approve a request (production 2-step: backend-team then dba-team)
DBA_APPROVER_TOKEN=$(create_token "vc-dba" approver --groups dba-team)
REQ_RS=$(api POST /api/requests "$REQUESTER_TOKEN" \
  -d '{"operation":"execute_query","environment":"production","database":"app","detail":"SELECT resume1","reason":"resume reason test"}')
REQ_RS_ID=$(echo "$REQ_RS" | json_field id)
# Step 1: backend-team (APPROVER_TOKEN has backend-team)
api_status POST "/api/requests/$REQ_RS_ID/approve" "$APPROVER_TOKEN" -d '{"comment":"step1"}' >/dev/null
# Step 2: dba-team
api_status POST "/api/requests/$REQ_RS_ID/approve" "$DBA_APPROVER_TOKEN" -d '{"comment":"step2"}' >/dev/null

# Operator resume without reason → error
STATUS=$(api_status POST "/api/requests/$REQ_RS_ID/resume" "$OPERATOR_TOKEN" -d '{}')
[ "$STATUS" = "400" ] || [ "$STATUS" = "422" ] && pass "Non-owner resume without reason → error" || fail "Resume reason" "got $STATUS"

# Create another fully-approved request
REQ_RS2=$(api POST /api/requests "$REQUESTER_TOKEN" \
  -d '{"operation":"execute_query","environment":"production","database":"app","detail":"SELECT resume2","reason":"resume test 2"}')
REQ_RS2_ID=$(echo "$REQ_RS2" | json_field id)
api_status POST "/api/requests/$REQ_RS2_ID/approve" "$APPROVER_TOKEN" -d '{"comment":"s1"}' >/dev/null
api_status POST "/api/requests/$REQ_RS2_ID/approve" "$DBA_APPROVER_TOKEN" -d '{"comment":"s2"}' >/dev/null

# Operator resume with reason → success
STATUS=$(api_status POST "/api/requests/$REQ_RS2_ID/resume" "$OPERATOR_TOKEN" \
  -d '{"reason":"operator dispatch"}')
[ "$STATUS" = "200" ] || [ "$STATUS" = "202" ] && pass "Non-owner resume with reason → success" || fail "Resume reason ok" "got $STATUS"

echo ""
echo "--- §6.3 Result.view non-owner ---"
# Requester cannot view other's result (operator's break-glass result)
if [ -n "$REQ_OP_ID" ]; then
  STATUS=$(api_status GET "/api/requests/$REQ_OP_ID/result/content" "$REQUESTER_TOKEN")
  [ "$STATUS" = "403" ] || [ "$STATUS" = "404" ] && pass "Requester(own) cannot view other's result" || fail "Result view other" "got $STATUS"
fi

echo ""
echo "--- §7 Schema ---"
STATUS=$(api_status GET "/api/schemas/app?environment=development" "$REQUESTER_TOKEN")
[ "$STATUS" = "200" ] && pass "Requester(schema.read) can read schema" || fail "Req schema" "got $STATUS"

STATUS=$(api_status GET "/api/schemas/app?environment=development" "$ADMIN_ONLY_TOKEN")
[ "$STATUS" = "403" ] && pass "Admin(no schema.read) cannot read schema" || fail "Admin schema" "got $STATUS"

echo ""
echo "--- §8 Audit ---"
STATUS=$(api_status GET /api/audit/events "$ADMIN_TOKEN_RAW")
[ "$STATUS" = "200" ] && pass "Admin(audit.read) can read audit" || fail "Admin audit" "got $STATUS"

STATUS=$(api_status GET /api/audit/events "$REQUESTER_TOKEN")
[ "$STATUS" = "403" ] && pass "Requester(no audit.read) cannot read audit" || fail "Req audit" "got $STATUS"

echo ""
echo "--- §9 User management ---"
STATUS=$(api_status GET /api/users "$ADMIN_TOKEN_RAW")
[ "$STATUS" = "200" ] && pass "Admin(user.read) can list users" || fail "Admin users" "got $STATUS"

STATUS=$(api_status GET /api/users "$REQUESTER_TOKEN")
[ "$STATUS" = "403" ] && pass "Requester cannot list users" || fail "Req users" "got $STATUS"

echo ""
echo "--- §11 Agent isolation ---"
AGENT_TOKEN=$(docker compose exec -T dbward-server cat /data/agent-token)
STATUS=$(api_status POST /api/requests "$AGENT_TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"app","detail":"SELECT 1"}')
[ "$STATUS" = "403" ] && pass "Agent cannot create request" || fail "Agent create" "got $STATUS"

echo ""
echo "--- §12 Built-in roles ---"
STATUS=$(api_status POST /api/requests "$ADMIN_ONLY_TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"app","detail":"SELECT 1"}')
[ "$STATUS" = "403" ] && pass "Admin has no Operation Plane access" || fail "Admin op" "got $STATUS"

echo ""
echo "--- §13 Bootstrap ---"
ME=$(api GET /api/me "$ADMIN_TOKEN_RAW")
ROLES=$(echo "$ME" | python3 -c "
import sys,json
try:
  d=json.load(sys.stdin)
  r=d.get('roles',[])
  names=[x['name'] if isinstance(x,dict) else x for x in r]
  print(','.join(sorted(names)))
except:
  print('')
" 2>/dev/null || echo "")
[[ "$ROLES" == *"admin"* ]] && [[ "$ROLES" == *"requester"* ]] && \
  pass "Bootstrap user has admin+requester" || fail "Bootstrap roles" "got: $ROLES"

echo ""
echo "--- §4 Token: admin can list, revoke(any) ---"
STATUS=$(api_status GET /api/tokens "$ADMIN_TOKEN_RAW")
[ "$STATUS" = "200" ] && pass "Admin(token.list) lists all tokens" || fail "Admin tokens" "got $STATUS"

summary
