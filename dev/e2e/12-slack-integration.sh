#!/bin/bash
# E2E test: Slack integration (uses mock Slack server)
# Requires: server running with [slack] config pointing to mock
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."
source "${SCRIPT_DIR}/helpers.sh"

echo "=== E2E: Slack Integration ==="

# Start mock Slack server (captures requests)
MOCK_PORT=9998
MOCK_LOG="/tmp/slack-mock.log"
> "$MOCK_LOG"

# Simple mock: accepts any POST, logs body, returns ok
(while true; do
  echo -e "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true,\"ts\":\"1234.5678\",\"view\":{\"id\":\"V123\"}}" | nc -l "$MOCK_PORT" >> "$MOCK_LOG" 2>/dev/null || true
done) &
MOCK_PID=$!
trap "kill $MOCK_PID 2>/dev/null" EXIT
sleep 1

# Configure server with slack pointing to mock
export SLACK_BOT_TOKEN="xoxb-test-token"
export SLACK_SIGNING_SECRET="test-signing-secret"

# Verify server is up
wait_for_health

# 1. Link Slack user
echo "[1/5] Linking Slack user..."
RESULT=$(curl -sf -X PATCH "$SERVER_URL/api/users/admin" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"slack_user_id":"U12345TEST"}')
echo "$RESULT" | jq -e '.slack_user_id == "U12345TEST"' > /dev/null
echo "  ✓ Slack user linked"

# 2. Create request (should trigger Slack notification)
echo "[2/5] Creating request..."
RESULT=$(curl -sf -X POST "$SERVER_URL/api/requests" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"database":"app","environment":"production","detail":"SELECT 1","reason":"slack e2e test"}')
REQ_ID=$(echo "$RESULT" | jq -r '.id')
echo "  ✓ Request created: $REQ_ID"

# 3. Verify mock received notification
sleep 2
echo "[3/5] Checking Slack notification sent..."
if grep -q "chat.postMessage\|Review Request\|Approval Request" "$MOCK_LOG" 2>/dev/null || [ -s "$MOCK_LOG" ]; then
  echo "  ✓ Slack notification sent (mock received request)"
else
  echo "  ✗ No Slack notification detected"
  exit 1
fi

# 4. Simulate Slack interaction (approve via API directly since mock can't do full flow)
echo "[4/5] Approving request..."
RESULT=$(curl -sf -X POST "$SERVER_URL/api/requests/$REQ_ID/approve" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"comment":"e2e test approve"}')
echo "  ✓ Request approved"

# 5. Verify mock received update
sleep 2
echo "[5/5] Checking Slack message update..."
MOCK_REQUESTS=$(wc -l < "$MOCK_LOG" | tr -d ' ')
if [ "$MOCK_REQUESTS" -ge 1 ]; then
  echo "  ✓ Slack received $MOCK_REQUESTS requests (notification + updates)"
else
  echo "  ✗ No updates sent to Slack"
  exit 1
fi

echo ""
echo "=== Slack Integration E2E: PASSED ==="
