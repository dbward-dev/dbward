#!/bin/bash
# E2E MySQL Tests — Verify full flow works with MySQL backend
# Requires: docker compose --profile mysql services running
# Usage: ./dev/e2e-mysql.sh

set -euo pipefail
cd "$(dirname "$0")/.."
source dev/e2e-helpers.sh

echo ""
echo "=== E2E MySQL Tests ==="
echo ""

# Ensure MySQL profile services are running
docker compose --profile mysql up -d mysql dbward-agent-mysql 2>&1 | tail -2

# Check MySQL is available
echo "Waiting for MySQL..."
for i in $(seq 1 30); do
  docker compose exec -T mysql mysqladmin ping -h localhost -uroot -pdbward 2>/dev/null && break || sleep 2
done
docker compose exec -T mysql mysqladmin ping -h localhost -uroot -pdbward 2>/dev/null || { echo "MySQL not available"; exit 1; }
echo "MySQL ready"

# Create agent token pointing to MySQL
ADMIN_TOKEN=$(docker compose exec -T dbward-server dbward server token create --user admin1 --role admin --data /data/dbward.db 2>/dev/null | grep -o 'dbw_[a-z0-9]*')
DEV_TOKEN=$(docker compose exec -T dbward-server dbward server token create --user dev1 --role developer --data /data/dbward.db 2>/dev/null | grep -o 'dbw_[a-z0-9]*')

[ -z "$ADMIN_TOKEN" ] && { echo "Failed to create admin token"; exit 1; }
[ -z "$DEV_TOKEN" ] && { echo "Failed to create dev token"; exit 1; }

# --- 1. Basic SELECT via MySQL ---
echo "--- MySQL basic query ---"

REQ=$(api POST /api/requests "$DEV_TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"mysql_dev","detail":"SELECT 1 AS num, VERSION() AS ver"}')
REQ_ID=$(echo "$REQ" | json_field id)
STATUS=$(echo "$REQ" | json_field status)

if [ -n "$REQ_ID" ]; then
  show_output "Created request ${REQ_ID:0:8} (status=$STATUS)"
  sleep 4
  FINAL=$(api GET "/api/requests/$REQ_ID" "$DEV_TOKEN" | json_field status)
  if [ "$FINAL" = "executed" ]; then
    pass "MySQL SELECT executed"
  else
    fail "MySQL SELECT" "status=$FINAL"
    show_output "Error: $(json_error)"
  fi
else
  fail "Create MySQL request" "no ID returned"
  show_output "Response: $(echo "$REQ" | head -c 200)"
fi

# --- 2. MySQL DML ---
echo ""
echo "--- MySQL DML ---"

# Cleanup from previous runs
docker compose exec -T mysql mysql -udbward -pdbward dbward_dev -e "DROP TABLE IF EXISTS e2e_test" 2>/dev/null

# Create table first
REQ=$(api POST /api/requests "$DEV_TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"mysql_dev","detail":"CREATE TABLE IF NOT EXISTS e2e_test (id INT AUTO_INCREMENT PRIMARY KEY, val VARCHAR(255))"}')
REQ_ID=$(echo "$REQ" | json_field id)
sleep 4
STATUS=$(api GET "/api/requests/$REQ_ID" "$DEV_TOKEN" | json_field status)
show_output "CREATE TABLE: status=$STATUS"

# Insert
REQ=$(api POST /api/requests "$DEV_TOKEN" \
  -d "{\"operation\":\"execute_query\",\"environment\":\"development\",\"database\":\"mysql_dev\",\"detail\":\"INSERT INTO e2e_test (val) VALUES ('hello'), ('world')\"}")
REQ_ID=$(echo "$REQ" | json_field id)
sleep 4
STATUS=$(api GET "/api/requests/$REQ_ID" "$DEV_TOKEN" | json_field status)
[ "$STATUS" = "executed" ] && pass "MySQL INSERT executed" || fail "MySQL INSERT" "status=$STATUS"

# Select to verify
REQ=$(api POST /api/requests "$DEV_TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"mysql_dev","detail":"SELECT COUNT(*) AS cnt FROM e2e_test"}')
REQ_ID=$(echo "$REQ" | json_field id)
sleep 4
STATUS=$(api GET "/api/requests/$REQ_ID" "$DEV_TOKEN" | json_field status)
[ "$STATUS" = "executed" ] && pass "MySQL SELECT after INSERT executed" || fail "MySQL verify" "status=$STATUS"

# --- 3. MySQL Unicode ---
echo ""
echo "--- MySQL Unicode ---"

REQ=$(api POST /api/requests "$DEV_TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"mysql_dev","detail":"SELECT '\''日本語テスト 🎉'\'' AS msg"}')
REQ_ID=$(echo "$REQ" | json_field id)
sleep 4
STATUS=$(api GET "/api/requests/$REQ_ID" "$DEV_TOKEN" | json_field status)
if [ "$STATUS" = "executed" ]; then
  pass "MySQL Unicode query executed"
else
  fail "MySQL Unicode" "status=$STATUS"
  show_output "Error: $(json_error)"
fi

# --- 4. MySQL error handling ---
echo ""
echo "--- MySQL error handling ---"

REQ=$(api POST /api/requests "$DEV_TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"mysql_dev","detail":"SELECT * FROM nonexistent_table_xyz"}')
REQ_ID=$(echo "$REQ" | json_field id)
sleep 4
STATUS=$(api GET "/api/requests/$REQ_ID" "$DEV_TOKEN" | json_field status)
if [ "$STATUS" = "failed" ]; then
  pass "MySQL error returns failed status"
  show_output "Expected failure for nonexistent table"
else
  fail "MySQL error handling" "expected failed, got $STATUS"
fi

summary
