#!/bin/bash
# E2E SAFE-1/3/6 Tests — Read-only tx, execution_plan, CancellationGuard
# Requires: docker compose services running (server + agent + postgres + mysql)
# Usage: ./dev/e2e/safe.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."
source "$SCRIPT_DIR/helpers.sh"

echo ""
echo "=== E2E SAFE-1/3/6 Tests ==="
echo ""

TOKEN=$(create_token safe-tester admin,requester)
[ -z "$TOKEN" ] && { echo "Failed to create token"; exit 1; }

# --- SAFE-1: Read-only transaction ---
echo "--- SAFE-1: Read-only transaction ---"

# PG SELECT succeeds
REQ=$(api POST /api/requests "$TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"app","detail":"SELECT 1 as safe1"}')
REQ_ID=$(echo "$REQ" | json_field id)
sleep 3
STATUS=$(api GET "/api/requests/$REQ_ID" "$TOKEN" | json_field status)
[ "$STATUS" = "executed" ] && pass "PG: SELECT in read-only tx" || fail "PG SELECT" "status=$STATUS"

# PG multi-statement
REQ=$(api POST /api/requests "$TOKEN" \
  -d "{\"operation\":\"execute_query\",\"environment\":\"development\",\"database\":\"app\",\"detail\":\"SET LOCAL statement_timeout = '10s'; SELECT 42\"}")
REQ_ID=$(echo "$REQ" | json_field id)
sleep 3
STATUS=$(api GET "/api/requests/$REQ_ID" "$TOKEN" | json_field status)
[ "$STATUS" = "executed" ] && pass "PG: Multi-statement in read-only tx" || fail "PG multi-stmt" "status=$STATUS"

# MySQL SELECT succeeds
REQ=$(api POST /api/requests "$TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"mysql_dev","detail":"SELECT 1 as safe1"}')
REQ_ID=$(echo "$REQ" | json_field id)
sleep 3
STATUS=$(api GET "/api/requests/$REQ_ID" "$TOKEN" | json_field status)
[ "$STATUS" = "executed" ] && pass "MySQL: SELECT in read-only tx" || fail "MySQL SELECT" "status=$STATUS"

# --- SAFE-1: Classifier reclassification ---
echo ""
echo "--- SAFE-1: Classifier reclassification ---"

# FOR UPDATE → DML
REQ=$(api POST /api/requests "$TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"app","detail":"SELECT * FROM users FOR UPDATE"}')
OP=$(echo "$REQ" | json_field operation)
[ "$OP" = "execute_dml" ] && pass "FOR UPDATE → execute_dml" || fail "FOR UPDATE classify" "op=$OP"

# nextval → DML
REQ=$(api POST /api/requests "$TOKEN" \
  -d "{\"operation\":\"execute_query\",\"environment\":\"development\",\"database\":\"app\",\"detail\":\"SELECT nextval('nonexist')\"}")
OP=$(echo "$REQ" | json_field operation)
[ "$OP" = "execute_dml" ] && pass "nextval → execute_dml" || fail "nextval classify" "op=$OP"

# pg_advisory_lock → DML
REQ=$(api POST /api/requests "$TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"app","detail":"SELECT pg_advisory_lock(1)"}')
OP=$(echo "$REQ" | json_field operation)
[ "$OP" = "execute_dml" ] && pass "pg_advisory_lock → execute_dml" || fail "advisory classify" "op=$OP"

# MySQL GET_LOCK → DML
REQ=$(api POST /api/requests "$TOKEN" \
  -d "{\"operation\":\"execute_query\",\"environment\":\"development\",\"database\":\"mysql_dev\",\"detail\":\"SELECT GET_LOCK('x', 1)\"}")
OP=$(echo "$REQ" | json_field operation)
[ "$OP" = "execute_dml" ] && pass "MySQL GET_LOCK → execute_dml" || fail "GET_LOCK classify" "op=$OP"

# INSERT → DML
REQ=$(api POST /api/requests "$TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"app","detail":"INSERT INTO t VALUES(1)"}')
OP=$(echo "$REQ" | json_field operation)
[ "$OP" = "execute_dml" ] && pass "INSERT → execute_dml" || fail "INSERT classify" "op=$OP"

# --- SAFE-3: execution_plan ---
echo ""
echo "--- SAFE-3: Execution plan ---"

# Error case: non-existent table → agent reports failure
REQ=$(api POST /api/requests "$TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"app","detail":"SELECT * FROM nonexist_xyz_safe3"}')
REQ_ID=$(echo "$REQ" | json_field id)
sleep 3
STATUS=$(api GET "/api/requests/$REQ_ID" "$TOKEN" | json_field status)
[ "$STATUS" = "failed" ] && pass "SAFE-3: Error propagation (bad table)" || fail "SAFE-3 error" "status=$STATUS"

# --- SAFE-6: Pool recovery after errors ---
echo ""
echo "--- SAFE-6: Pool recovery ---"

# After error, next query still works
REQ=$(api POST /api/requests "$TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"app","detail":"SELECT 1 as pool_recovered"}')
REQ_ID=$(echo "$REQ" | json_field id)
sleep 3
STATUS=$(api GET "/api/requests/$REQ_ID" "$TOKEN" | json_field status)
[ "$STATUS" = "executed" ] && pass "PG: Pool healthy after error" || fail "PG pool" "status=$STATUS"

REQ=$(api POST /api/requests "$TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"mysql_dev","detail":"SELECT 1 as pool_recovered"}')
REQ_ID=$(echo "$REQ" | json_field id)
sleep 3
STATUS=$(api GET "/api/requests/$REQ_ID" "$TOKEN" | json_field status)
[ "$STATUS" = "executed" ] && pass "MySQL: Pool healthy after error" || fail "MySQL pool" "status=$STATUS"

# --- SAFE-1: Timeout ---
echo ""
echo "--- SAFE-1: Statement timeout ---"

# PG timeout (statement_timeout)
REQ=$(api POST /api/requests "$TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"app","detail":"SELECT pg_sleep(300)"}')
REQ_ID=$(echo "$REQ" | json_field id)
echo -n "  Waiting for PG timeout (~60s)..."
for i in $(seq 1 40); do
  sleep 2
  STATUS=$(api GET "/api/requests/$REQ_ID" "$TOKEN" | json_field status)
  [ "$STATUS" = "failed" ] && break
done
echo ""
[ "$STATUS" = "failed" ] && pass "PG: Statement timeout → failed" || fail "PG timeout" "status=$STATUS"

# Pool still works after timeout
REQ=$(api POST /api/requests "$TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"app","detail":"SELECT 1 as after_timeout"}')
REQ_ID=$(echo "$REQ" | json_field id)
sleep 3
STATUS=$(api GET "/api/requests/$REQ_ID" "$TOKEN" | json_field status)
[ "$STATUS" = "executed" ] && pass "PG: Pool recovered after timeout" || fail "PG pool timeout" "status=$STATUS"

echo ""
summary
