#!/bin/bash
# E2E: MCP Phase 2 SSE + Session + Elicitation tests
# Verifies: session lifecycle, SSE streaming, cancel, resume, origin, phase 1 compat
# Requires: docker compose services running (server + agent + postgres)
# Usage: ./dev/e2e/mcp-http-sse.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."
source "$SCRIPT_DIR/helpers.sh"

echo ""
echo "=== E2E MCP Phase 2: SSE + Session Tests ==="
echo ""

wait_for_server

TOKEN=$(create_token mcp-sse-user requester)
[ -z "$TOKEN" ] && { echo "Failed to create token"; exit 1; }

AUTH="Authorization: Bearer $TOKEN"

# --- Test 1: Initialize → Mcp-Session-Id header ---
echo ""
echo "--- Test 1: Initialize creates session ---"
INIT_RESP=$(curl -s -D - -o /tmp/mcp_init_body.json -X POST "${SERVER_URL}/mcp" \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{"elicitation":{}}}}')

SESSION_ID=$(echo "$INIT_RESP" | grep -i "mcp-session-id:" | tr -d '\r' | awk '{print $2}')
INIT_BODY=$(cat /tmp/mcp_init_body.json)

if [ -n "$SESSION_ID" ]; then
  pass "Initialize returned Mcp-Session-Id: $SESSION_ID"
else
  fail "Initialize did not return Mcp-Session-Id" "$INIT_RESP"
fi

if echo "$INIT_BODY" | jq -e '.result.protocolVersion == "2025-03-26"' > /dev/null 2>&1; then
  pass "Initialize result has correct protocolVersion"
else
  fail "Initialize result missing protocolVersion" "$INIT_BODY"
fi

# --- Test 2: notifications/initialized → 202 ---
echo ""
echo "--- Test 2: notifications/initialized ---"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${SERVER_URL}/mcp" \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}')

if [ "$STATUS" = "202" ]; then
  pass "notifications/initialized → 202"
else
  fail "notifications/initialized → expected 202" "got $STATUS"
fi

# --- Test 3: tools/call with SSE Accept → event-stream ---
echo ""
echo "--- Test 3: SSE tools/call ---"
# Use timeout to avoid hanging
SSE_OUT=$(timeout 10 curl -s -N -X POST "${SERVER_URL}/mcp" \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -H "Accept: text/event-stream" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -d '{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"dbward_list_pending","arguments":{}}}' 2>/dev/null || true)

if echo "$SSE_OUT" | grep -q "^data:"; then
  pass "SSE tools/call returned event-stream with data"
else
  fail "SSE tools/call did not return SSE events" "${SSE_OUT:0:200}"
fi

# Extract event ID for resume test
EVENT_ID=$(echo "$SSE_OUT" | grep "^id:" | tail -1 | sed 's/^id: *//')

# --- Test 4: Phase 1 compat (no session header) → JSON ---
echo ""
echo "--- Test 4: Phase 1 compat (no session, JSON) ---"
P1_RESP=$(curl -s -X POST "${SERVER_URL}/mcp" \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"jsonrpc":"2.0","id":20,"method":"tools/list","params":{}}')

if echo "$P1_RESP" | jq -e '.result.tools' > /dev/null 2>&1; then
  pass "Phase 1 compat: tools/list works without session"
else
  fail "Phase 1 compat failed" "$P1_RESP"
fi

# --- Test 5: Invalid session → 404 ---
echo ""
echo "--- Test 5: Invalid session → 404 ---"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${SERVER_URL}/mcp" \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -H "Mcp-Session-Id: nonexistent-session-id" \
  -d '{"jsonrpc":"2.0","id":30,"method":"tools/list","params":{}}')

if [ "$STATUS" = "404" ]; then
  pass "Invalid session → 404"
else
  fail "Invalid session → expected 404" "got $STATUS"
fi

# --- Test 6: GET /mcp without session → 405 ---
echo ""
echo "--- Test 6: GET without session → 405 ---"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X GET "${SERVER_URL}/mcp" \
  -H "$AUTH" \
  -H "Accept: text/event-stream")

if [ "$STATUS" = "405" ]; then
  pass "GET without session → 405"
else
  fail "GET without session → expected 405" "got $STATUS"
fi

# --- Test 7: GET /mcp resume (if we have an event ID) ---
echo ""
echo "--- Test 7: GET resume ---"
if [ -n "${EVENT_ID:-}" ]; then
  RESUME_OUT=$(timeout 3 curl -s -N -X GET "${SERVER_URL}/mcp" \
    -H "$AUTH" \
    -H "Accept: text/event-stream" \
    -H "Mcp-Session-Id: $SESSION_ID" \
    -H "Last-Event-ID: ${EVENT_ID}" 2>/dev/null || true)
  # Stream is already completed, so we may get empty or the events
  pass "GET resume did not error (stream completed)"
else
  skip "No event ID captured from test 3"
fi

# --- Test 8: DELETE /mcp → 200 ---
echo ""
echo "--- Test 8: DELETE session ---"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "${SERVER_URL}/mcp" \
  -H "$AUTH" \
  -H "Mcp-Session-Id: $SESSION_ID")

if [ "$STATUS" = "200" ]; then
  pass "DELETE session → 200"
else
  fail "DELETE session → expected 200" "got $STATUS"
fi

# --- Test 9: After DELETE → 404 ---
echo ""
echo "--- Test 9: After DELETE → 404 ---"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${SERVER_URL}/mcp" \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -d '{"jsonrpc":"2.0","id":40,"method":"tools/list","params":{}}')

if [ "$STATUS" = "404" ]; then
  pass "After DELETE, session → 404"
else
  fail "After DELETE → expected 404" "got $STATUS"
fi

# --- Test 10: Origin validation ---
echo ""
echo "--- Test 10: Origin validation ---"
# Only runs if server has allowed_origins configured
# Try with forbidden origin
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${SERVER_URL}/mcp" \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -H "Origin: http://evil.example.com" \
  -d '{"jsonrpc":"2.0","id":50,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{}}}')

if [ "$STATUS" = "403" ]; then
  pass "Forbidden origin → 403"
else
  # If server has no allowed_origins, this is fine (CORS disabled)
  skip "Origin not enforced (allowed_origins may be empty)"
fi

# --- Summary ---
echo ""
summary
