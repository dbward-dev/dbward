#!/bin/bash
set -euo pipefail

# E2E test script for dbward OIDC group-based authorization
# Usage: ./dev/e2e-test.sh
# Requires: docker compose, curl, python3

cd "$(dirname "$0")/.."

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'
PASS=0
FAIL=0

pass() { echo -e "${GREEN}✅ PASS${NC}: $1"; PASS=$((PASS+1)); }
fail() { echo -e "${RED}❌ FAIL${NC}: $1 — $2"; FAIL=$((FAIL+1)); }

echo "=== Starting services ==="
docker compose --profile oidc up -d --build 2>&1 | tail -3

echo "Waiting for Keycloak..."
for i in $(seq 1 60); do
  curl -sf http://localhost:8080/realms/dbward/.well-known/openid-configuration >/dev/null 2>&1 && break || sleep 3
done
curl -sf http://localhost:8080/realms/dbward/.well-known/openid-configuration >/dev/null 2>&1 || { echo "Keycloak failed to start"; exit 1; }
echo "Keycloak ready"

echo "Waiting for dbward-server..."
for i in $(seq 1 30); do
  curl -sf http://localhost:13000/health >/dev/null 2>&1 && break || sleep 2
done
curl -sf http://localhost:13000/health >/dev/null 2>&1 || { echo "Server failed to start"; exit 1; }
echo "Server ready"

# Fix Keycloak users (firstName required in KC 26)
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8080/realms/master/protocol/openid-connect/token \
  -d "grant_type=password" -d "client_id=admin-cli" -d "username=admin" -d "password=admin" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
for user in alice bob carol; do
  USER_ID=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
    "http://localhost:8080/admin/realms/dbward/users?username=$user" | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['id'])")
  curl -s -X PUT -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
    "http://localhost:8080/admin/realms/dbward/users/$USER_ID" \
    -d "{\"firstName\":\"$user\",\"lastName\":\"Test\",\"emailVerified\":true,\"enabled\":true,\"requiredActions\":[]}" >/dev/null
done

# Helper: get OIDC token
get_token() {
  curl -s -X POST http://localhost:8080/realms/dbward/protocol/openid-connect/token \
    -d "grant_type=password" -d "client_id=dbward-cli" -d "username=$1" -d "password=$1" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])"
}

# Helper: API call
api() {
  local method=$1 path=$2 token=$3
  shift 3
  curl -s -X "$method" "http://localhost:13000$path" \
    -H "Authorization: Bearer $token" -H "Content-Type: application/json" "$@"
}

echo ""
echo "=== E2E Tests ==="
echo ""

ALICE_TOKEN=$(get_token alice)
BOB_TOKEN=$(get_token bob)
CAROL_TOKEN=$(get_token carol)

# --- Test: OIDC groups in token ---
ALICE_GROUPS=$(echo "$ALICE_TOKEN" | python3 -c "
import sys,json,base64
token=sys.stdin.read().strip()
payload=token.split('.')[1]+'=='
claims=json.loads(base64.urlsafe_b64decode(payload))
print(','.join(sorted(claims.get('groups',[]))))")
if [[ "$ALICE_GROUPS" == *"backend-team"* ]]; then
  pass "Alice has backend-team group in OIDC token"
else
  fail "Alice groups" "got: $ALICE_GROUPS"
fi

# --- Test: Developer can create request ---
REQ_ID=$(api POST /api/requests "$BOB_TOKEN" \
  -d '{"operation":"execute_query","environment":"production","database":"app","detail":"SELECT 1","reason":"e2e"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
if [ -n "$REQ_ID" ]; then
  pass "Bob (admin via dbward-admins group) creates request: $REQ_ID"
else
  fail "Create request" "no ID returned"
fi

# --- Test: Wrong group cannot approve ---
RESULT=$(api POST "/api/requests/$REQ_ID/approve" "$CAROL_TOKEN" -d '{}')
if echo "$RESULT" | grep -q "not allowed"; then
  pass "Carol (dba-team) cannot approve step 1 (requires backend-team)"
else
  fail "Wrong group approve" "$RESULT"
fi

# --- Test: Correct group approves step 1 ---
RESULT=$(api POST "/api/requests/$REQ_ID/approve" "$ALICE_TOKEN" -d '{}')
STATUS=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))")
if [ "$STATUS" = "pending" ]; then
  pass "Alice (backend-team) approves step 1"
else
  fail "Step 1 approve" "$RESULT"
fi

# --- Test: Correct group approves step 2 ---
RESULT=$(api POST "/api/requests/$REQ_ID/approve" "$CAROL_TOKEN" -d '{}')
STATUS=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))")
TOKEN=$(echo "$RESULT" | python3 -c "import sys,json; print('yes' if json.load(sys.stdin).get('execution_token') else 'no')")
if [ "$STATUS" = "approved" ] && [ "$TOKEN" = "yes" ]; then
  pass "Carol (dba-team) approves step 2 → approved + execution_token"
else
  fail "Step 2 approve" "status=$STATUS token=$TOKEN"
fi

# --- Test: Dispatch + agent execution ---
api POST "/api/requests/$REQ_ID/dispatch" "$BOB_TOKEN" -d '{}' >/dev/null
sleep 3
FINAL=$(api GET "/api/requests/$REQ_ID" "$BOB_TOKEN")
FINAL_STATUS=$(echo "$FINAL" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))")
if [ "$FINAL_STATUS" = "executed" ]; then
  pass "Agent executed request successfully"
else
  fail "Agent execution" "status=$FINAL_STATUS"
fi

# --- Test: Group-based reject ---
REQ2=$(api POST /api/requests "$BOB_TOKEN" \
  -d '{"operation":"execute_query","environment":"production","database":"app","detail":"DROP TABLE x","reason":"reject test"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
# Alice approves step 1
api POST "/api/requests/$REQ2/approve" "$ALICE_TOKEN" -d '{}' >/dev/null
# Carol rejects (she's step 2 approver)
RESULT=$(api POST "/api/requests/$REQ2/reject" "$CAROL_TOKEN" -d '{}')
STATUS=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))")
if [ "$STATUS" = "rejected" ]; then
  pass "Carol (dba-team) rejects request via group permission"
else
  fail "Group reject" "status=$STATUS"
fi

# --- Test: Auto-approve in development ---
RESULT=$(api POST /api/requests "$ALICE_TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"app","detail":"SELECT version()"}')
STATUS=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))")
if [ "$STATUS" = "auto_approved" ]; then
  pass "Development environment auto-approves"
else
  fail "Auto-approve" "status=$STATUS"
fi

# --- Summary ---
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

docker compose --profile oidc down -v >/dev/null 2>&1

if [ $FAIL -gt 0 ]; then
  exit 1
fi
