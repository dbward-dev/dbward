#!/bin/bash
# E2E: V25 Webhook Event Delivery Tests (Section 16)
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."
source "$SCRIPT_DIR/helpers.sh"

echo "=== V25 Webhook Tests ==="
echo ""
wait_for_server

ADMIN_TOKEN=$(docker compose exec -T dbward-server cat /data/admin-token 2>/dev/null || echo "")
TS=$(date +%s)

# Verify webhook-receiver is running
docker compose ps webhook-receiver 2>&1 | grep -q "Up" \
  && pass "webhook-receiver is running" || { fail "pre" "webhook-receiver not running"; summary; exit 1; }

# ============================================================
# 16.1 request.created → webhook delivery (config has this event)
# ============================================================
echo ""
echo "--- 16.1 request.created event delivery ---"

# Create a requester user + token to create a request
RESP=$(api POST /api/users "$ADMIN_TOKEN" -d "{\"id\":\"wh-dev-$TS\",\"roles\":[\"requester\"]}")
DEV_TOKEN=$(echo "$RESP" | jq -r '.token // empty')

# Create a request to trigger webhook
api POST /api/requests "$DEV_TOKEN" \
  -d '{"operation":"execute_query","environment":"development","database":"app","detail":"SELECT 1"}' > /dev/null
sleep 5

# Check webhook-receiver logs for the event
# Development workflow auto-approves, so we get request.auto_approved
LOGS=$(docker compose logs webhook-receiver --since 15s 2>&1)
echo "$LOGS" | grep -q "request.created\|request.auto_approved\|request_created" \
  && pass "16.1 request event webhook delivered" \
  || fail "16.1" "no request event in webhook logs"

# ============================================================
# 16.2 Event filtering — user.* events NOT delivered (not in config)
# ============================================================
echo ""
echo "--- 16.2 Event filtering (user.created NOT in webhook config) ---"

# We created a user above — verify user.created was NOT delivered
echo "$LOGS" | grep -q "user.created\|user_created" \
  && fail "16.2" "user.created delivered but NOT in webhook config" \
  || pass "16.2 user.created correctly NOT delivered (not in events list)"

# ============================================================
# 16.4 Webhook endpoint headers present
# ============================================================
echo ""
echo "--- 16.4 Webhook headers ---"

echo "$LOGS" | grep -q "EVENT:\|X-Dbward-Event" \
  && pass "16.4 webhook includes event type header" \
  || fail "16.4" "no event header found"

summary
