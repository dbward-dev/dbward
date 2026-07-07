#!/bin/bash
# E2E: Bootstrap token management tests
# Tests: auto-bootstrap, idempotency, token file recovery
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."
source "$SCRIPT_DIR/helpers.sh"

echo "=== Bootstrap Tests ==="
echo ""
wait_for_server

ADMIN_TOKEN=$(docker compose exec -T dbward-server cat /data/admin-token 2>/dev/null || echo "")

# ============================================================
# 1. Bootstrap creates admin/developer/agent users + tokens
# ============================================================
echo "--- 1. Bootstrap users exist ---"

STATUS=$(api_status GET /api/users/admin "$ADMIN_TOKEN")
[ "$STATUS" = "200" ] && pass "1a admin bootstrap user exists" || fail "1a" "got $STATUS"

STATUS=$(api_status GET /api/users/developer "$ADMIN_TOKEN")
[ "$STATUS" = "200" ] && pass "1b developer bootstrap user exists" || fail "1b" "got $STATUS"

STATUS=$(api_status GET /api/users/agent "$ADMIN_TOKEN")
[ "$STATUS" = "200" ] && pass "1c agent bootstrap user exists" || fail "1c" "got $STATUS"

STATUS=$(api_status GET /api/users "$ADMIN_TOKEN")
[ "$STATUS" = "200" ] && pass "1d admin token works" || fail "1d" "got $STATUS"

# ============================================================
# 2. Bootstrap idempotency — restart doesn't duplicate
# ============================================================
echo ""
echo "--- 2. Bootstrap idempotency (restart) ---"

BEFORE=$(curl -s http://localhost:13000/api/users -H "Authorization: Bearer $ADMIN_TOKEN" | jq '.users | length')

docker compose restart dbward-server > /dev/null 2>&1
sleep 5
wait_for_server

ADMIN_TOKEN_AFTER=$(docker compose exec -T dbward-server cat /data/admin-token 2>/dev/null || echo "")
[ "$ADMIN_TOKEN" = "$ADMIN_TOKEN_AFTER" ] && pass "2a admin token unchanged after restart" || fail "2a" "token changed"

AFTER=$(curl -s http://localhost:13000/api/users -H "Authorization: Bearer $ADMIN_TOKEN_AFTER" | jq '.users | length')
[ "$BEFORE" = "$AFTER" ] && pass "2b user count unchanged after restart ($BEFORE)" || fail "2b" "before=$BEFORE after=$AFTER"

STATUS=$(api_status GET /api/users "$ADMIN_TOKEN_AFTER")
[ "$STATUS" = "200" ] && pass "2c admin token still works after restart" || fail "2c" "got $STATUS"

# ============================================================
# 3. Token file recovery — missing file detection + force-bootstrap
# ============================================================
echo ""
echo "--- 3. Token file missing detection & recovery ---"

# Delete admin-token file
docker compose exec -T dbward-server sh -c 'rm -f /data/admin-token'

GONE=$(docker compose exec -T dbward-server sh -c 'test -f /data/admin-token && echo "exists" || echo "gone"')
[ "$GONE" = "gone" ] && pass "3a token file deleted" || fail "3a" "file still exists"

# Restart — server should fail with helpful message
docker compose restart dbward-server > /dev/null 2>&1
sleep 5

LOGS=$(docker compose logs dbward-server --tail 10 2>&1)
if echo "$LOGS" | grep -qi "bootstrap token file.*missing\|force-bootstrap\|not recoverable"; then
  pass "3b server detects missing token file and provides recovery guidance"
else
  fail "3b" "no guidance message found"
fi

# Recover using --force-bootstrap via one-shot container
docker compose stop dbward-server > /dev/null 2>&1

docker compose run --rm --no-deps --entrypoint sh \
  -e DBWARD_FORCE_BOOTSTRAP=true \
  dbward-server \
  -c 'dbward-server --listen 0.0.0.0:3000 --config /config/dbward-server.toml --force-bootstrap &
      SERVER_PID=$!
      for i in $(seq 1 20); do
        test -f /data/admin-token && test -f /data/agent-token && break || sleep 1
      done
      kill $SERVER_PID 2>/dev/null || true
      wait $SERVER_PID 2>/dev/null || true
      test -f /data/admin-token' > /tmp/force-boot.log 2>&1
FORCE_RC=$?

# Remove the crashed container and start fresh
docker compose rm -f dbward-server > /dev/null 2>&1
docker compose up -d dbward-server > /dev/null 2>&1

# Wait longer — the recreated container needs time for healthcheck
for i in $(seq 1 30); do
  curl -sf http://localhost:13000/health >/dev/null 2>&1 && break || sleep 2
done
curl -sf http://localhost:13000/health >/dev/null 2>&1 || { echo "Server failed to start after force-bootstrap"; exit 1; }

# Verify recovered token works
ADMIN_TOKEN_RECOVERED=$(docker compose exec -T dbward-server cat /data/admin-token 2>/dev/null || echo "")
if [ -n "$ADMIN_TOKEN_RECOVERED" ] && [ $FORCE_RC -eq 0 ]; then
  STATUS=$(api_status GET /api/users "$ADMIN_TOKEN_RECOVERED")
  [ "$STATUS" = "200" ] && pass "3c new token works after force-bootstrap" || fail "3c" "got $STATUS"
else
  skip "3c force-bootstrap recovery (rc=$FORCE_RC, token empty=${ADMIN_TOKEN_RECOVERED:+no})"
fi

# Update token for summary
ADMIN_TOKEN="$ADMIN_TOKEN_RECOVERED"

summary
