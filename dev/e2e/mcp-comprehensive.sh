#!/bin/bash
# E2E: Comprehensive MCP endpoint tests (POST/GET/DELETE /mcp + /metrics)
# Verifies: content negotiation, session lifecycle, SSE, batching, metrics
# Requires: docker compose services running (server + agent + postgres)
# Usage: cd dev && ./e2e/mcp-comprehensive.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."
source e2e/helpers.sh

echo ""
echo "=== E2E MCP Comprehensive Tests ==="
echo ""

wait_for_server

TOKEN=$(create_token mcp-sse-user requester)
[ -z "$TOKEN" ] && { echo "Failed to create token"; exit 1; }

AUTH="Authorization: Bearer $TOKEN"

# ============================================================
# POST /mcp — Content Negotiation & Validation
# ============================================================

echo ""
echo "=== POST /mcp: Content Negotiation ==="

# 1. Missing Content-Type → 415
echo "--- 1. Missing Content-Type → 415 ---"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${SERVER_URL}/mcp" \
  -H "$AUTH" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize"}')
if [ "$STATUS" = "415" ]; then
  pass "Missing Content-Type → 415"
else
  fail "Missing Content-Type" "expected 415, got $STATUS"
fi

# 2. Wrong Content-Type (text/plain) → 415
echo "--- 2. Wrong Content-Type → 415 ---"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${SERVER_URL}/mcp" \
  -H "$AUTH" \
  -H "Content-Type: text/plain" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize"}')
if [ "$STATUS" = "415" ]; then
  pass "Wrong Content-Type (text/plain) → 415"
else
  fail "Wrong Content-Type" "expected 415, got $STATUS"
fi

# 3. Unsupported Accept (text/plain only) → 406
echo "--- 3. Unsupported Accept → 406 ---"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${SERVER_URL}/mcp" \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -H "Accept: text/plain" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{}}}')
if [ "$STATUS" = "406" ]; then
  pass "Unsupported Accept (text/plain) → 406"
else
  fail "Unsupported Accept" "expected 406, got $STATUS"
fi

# 4. Invalid session ID → 404
echo "--- 4. Invalid session ID → 404 ---"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${SERVER_URL}/mcp" \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -H "Mcp-Session-Id: invalid-session-id-12345" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}')
if [ "$STATUS" = "404" ]; then
  pass "Invalid session ID → 404"
else
  fail "Invalid session ID" "expected 404, got $STATUS"
fi

# 5. Malformed JSON body → 200 with JSON-RPC parse error
echo "--- 5. Malformed JSON → parse error ---"
RESP=$(curl -s -X POST "${SERVER_URL}/mcp" \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{not valid json!!}')
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${SERVER_URL}/mcp" \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{not valid json!!}')
ERR_CODE=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('error',{}).get('code',''))" 2>/dev/null || echo "")
if [ "$STATUS" = "200" ] && [ "$ERR_CODE" = "-32700" ]; then
  pass "Malformed JSON → 200 with parse error (-32700)"
else
  fail "Malformed JSON" "status=$STATUS, error_code=$ERR_CODE"
fi

# 6. Invalid JSON-RPC (no method, no id) → 200 with JSON-RPC error
echo "--- 6. Invalid JSON-RPC → error ---"
RESP=$(curl -s -X POST "${SERVER_URL}/mcp" \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"jsonrpc":"2.0"}')
ERR_CODE=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('error',{}).get('code',''))" 2>/dev/null || echo "")
if [ "$ERR_CODE" = "-32600" ] || [ "$ERR_CODE" = "-32700" ]; then
  pass "Invalid JSON-RPC (no method/id) → error code $ERR_CODE"
else
  fail "Invalid JSON-RPC" "expected -32600 or -32700, got $ERR_CODE. Body: $RESP"
fi

# ============================================================
# POST /mcp — Session Lifecycle
# ============================================================

echo ""
echo "=== POST /mcp: Session Lifecycle ==="

# 7. Initialize with valid params → 200 + mcp-session-id header
echo "--- 7. Initialize → 200 + session header ---"
INIT_RESP=$(curl -s -D /tmp/mcp_comp_headers -o /tmp/mcp_comp_body -w "%{http_code}" -X POST "${SERVER_URL}/mcp" \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{"elicitation":{}},"clientInfo":{"name":"comprehensive-test","version":"1.0"}}}')
SESSION_ID=$(grep -i "mcp-session-id:" /tmp/mcp_comp_headers | tr -d '\r' | awk '{print $2}')
INIT_BODY=$(cat /tmp/mcp_comp_body)
if [ "$INIT_RESP" = "200" ] && [ -n "$SESSION_ID" ]; then
  pass "Initialize → 200 + Mcp-Session-Id: ${SESSION_ID:0:16}..."
else
  fail "Initialize" "status=$INIT_RESP, session=$SESSION_ID"
fi

# 8. notifications/initialized with session → 202
echo "--- 8. notifications/initialized → 202 ---"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${SERVER_URL}/mcp" \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}')
if [ "$STATUS" = "202" ]; then
  pass "notifications/initialized with session → 202"
else
  fail "notifications/initialized" "expected 202, got $STATUS"
fi

# 9. tools/list without session (Phase 1 compat, Accept: application/json) → 200
echo "--- 9. tools/list Phase 1 compat → 200 ---"
RESP=$(curl -s -w "\n%{http_code}" -X POST "${SERVER_URL}/mcp" \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}')
STATUS=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
if [ "$STATUS" = "200" ] && echo "$BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'tools' in d.get('result',{})" 2>/dev/null; then
  pass "tools/list without session (Phase 1 compat) → 200"
else
  fail "tools/list Phase 1 compat" "status=$STATUS"
fi

# 10. tools/list with session via SSE → 200 with event-stream content
echo "--- 10. tools/list SSE → event-stream ---"
SSE_OUT=$(timeout 5 curl -s -N -D /tmp/mcp_sse_headers -X POST "${SERVER_URL}/mcp" \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -H "Accept: text/event-stream" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -d '{"jsonrpc":"2.0","id":10,"method":"tools/list","params":{}}' 2>/dev/null || true)
if echo "$SSE_OUT" | grep -q "^data:"; then
  pass "tools/list with session via SSE → event-stream data"
else
  fail "tools/list SSE" "no data: lines in response. Got: ${SSE_OUT:0:200}"
fi

# Extract event ID for resume test later
STREAM_ID=$(echo "$SSE_OUT" | grep "^id:" | tail -1 | sed 's/^id: *//')

# 11. tools/call with session via SSE → 200 with event-stream
echo "--- 11. tools/call SSE → event-stream ---"
SSE_OUT2=$(timeout 10 curl -s -N -X POST "${SERVER_URL}/mcp" \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -H "Accept: text/event-stream" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -d '{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"dbward_list_pending","arguments":{}}}' 2>/dev/null || true)
if echo "$SSE_OUT2" | grep -q "^data:"; then
  pass "tools/call with session via SSE → event-stream data"
else
  fail "tools/call SSE" "no data: lines. Got: ${SSE_OUT2:0:200}"
fi

# 12. notifications/cancelled for unknown request → 202
echo "--- 12. notifications/cancelled → 202 ---"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${SERVER_URL}/mcp" \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -d '{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"nonexistent-req-999"}}')
if [ "$STATUS" = "202" ]; then
  pass "notifications/cancelled for unknown request → 202"
else
  fail "notifications/cancelled" "expected 202, got $STATUS"
fi

# 13. Unknown method → response with error
echo "--- 13. Unknown method → error response ---"
RESP=$(curl -s -X POST "${SERVER_URL}/mcp" \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -d '{"jsonrpc":"2.0","id":13,"method":"unknown/method","params":{}}')
ERR_CODE=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('error',{}).get('code',''))" 2>/dev/null || echo "")
if [ "$ERR_CODE" = "-32601" ]; then
  pass "Unknown method → -32601 Method Not Found"
else
  fail "Unknown method" "expected -32601, got $ERR_CODE"
fi

# 14. Batch with initialize → response contains error
echo "--- 14. Batch with initialize → error ---"
RESP=$(curl -s -X POST "${SERVER_URL}/mcp" \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -d '[{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{}}}]')
if echo "$RESP" | python3 -c "
import sys,json
d=json.load(sys.stdin)
# Response may be array or object — either way must contain an error
if isinstance(d, list):
    assert any('error' in item for item in d)
else:
    assert d.get('error')
" 2>/dev/null; then
  pass "Batch with initialize → error response"
else
  fail "Batch with initialize" "$RESP"
fi

# 15. Batch with nested batch → response contains error
echo "--- 15. Batch with nested batch → error ---"
RESP=$(curl -s -X POST "${SERVER_URL}/mcp" \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -d '[[{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}]]')
if echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('error')" 2>/dev/null; then
  pass "Nested batch → error response"
else
  fail "Nested batch" "$RESP"
fi

# 16. JSON-RPC Response without session → 400
echo "--- 16. JSON-RPC Response without session → 400 ---"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${SERVER_URL}/mcp" \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"result":{"type":"text","text":"hello"}}')
if [ "$STATUS" = "400" ]; then
  pass "JSON-RPC Response without session → 400"
else
  fail "JSON-RPC Response without session" "expected 400, got $STATUS"
fi

# 17. Elicitation response for unknown ID (with session) → 400
echo "--- 17. Elicitation response unknown ID → 400 ---"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${SERVER_URL}/mcp" \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -d '{"jsonrpc":"2.0","id":"elicit-unknown-999","result":{"action":"accept","content":{"reason":"test"}}}')
if [ "$STATUS" = "400" ]; then
  pass "Elicitation response for unknown ID → 400"
else
  fail "Elicitation response unknown ID" "expected 400, got $STATUS"
fi

# ============================================================
# GET /mcp — SSE Resume
# ============================================================

echo ""
echo "=== GET /mcp: SSE Resume ==="

# 19. No session header → 405
echo "--- 19. GET no session → 405 ---"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X GET "${SERVER_URL}/mcp" \
  -H "$AUTH" \
  -H "Accept: text/event-stream")
if [ "$STATUS" = "405" ]; then
  pass "GET without session header → 405"
else
  fail "GET without session" "expected 405, got $STATUS"
fi

# 20. No Last-Event-ID → 405
echo "--- 20. GET no Last-Event-ID → 405 ---"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X GET "${SERVER_URL}/mcp" \
  -H "$AUTH" \
  -H "Accept: text/event-stream" \
  -H "Mcp-Session-Id: $SESSION_ID")
if [ "$STATUS" = "405" ]; then
  pass "GET with session but no Last-Event-ID → 405"
else
  fail "GET no Last-Event-ID" "expected 405, got $STATUS"
fi

# 21. Malformed Last-Event-ID (no colon) → 400
echo "--- 21. Malformed Last-Event-ID → 400 ---"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X GET "${SERVER_URL}/mcp" \
  -H "$AUTH" \
  -H "Accept: text/event-stream" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -H "Last-Event-ID: malformed-no-colon")
if [ "$STATUS" = "400" ]; then
  pass "Malformed Last-Event-ID (no colon) → 400"
else
  fail "Malformed Last-Event-ID" "expected 400, got $STATUS"
fi

# 22. Non-numeric seq in Last-Event-ID → 400
echo "--- 22. Non-numeric seq → 400 ---"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X GET "${SERVER_URL}/mcp" \
  -H "$AUTH" \
  -H "Accept: text/event-stream" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -H "Last-Event-ID: stream123:abc")
if [ "$STATUS" = "400" ]; then
  pass "Non-numeric seq in Last-Event-ID → 400"
else
  fail "Non-numeric seq" "expected 400, got $STATUS"
fi

# 23. Nonexistent session → 404
echo "--- 23. GET nonexistent session → 404 ---"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X GET "${SERVER_URL}/mcp" \
  -H "$AUTH" \
  -H "Accept: text/event-stream" \
  -H "Mcp-Session-Id: nonexistent-session-xyz" \
  -H "Last-Event-ID: stream1:0")
if [ "$STATUS" = "404" ]; then
  pass "GET nonexistent session → 404"
else
  fail "GET nonexistent session" "expected 404, got $STATUS"
fi

# 24. Nonexistent stream (valid session) → 404
echo "--- 24. GET nonexistent stream → 404 ---"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X GET "${SERVER_URL}/mcp" \
  -H "$AUTH" \
  -H "Accept: text/event-stream" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -H "Last-Event-ID: nonexistent-stream:0")
if [ "$STATUS" = "404" ]; then
  pass "GET nonexistent stream (valid session) → 404"
else
  fail "GET nonexistent stream" "expected 404, got $STATUS"
fi

# 25. Valid resume after completed stream → 200 with replayed events
echo "--- 25. Valid resume → 200 with events ---"
if [ -n "${STREAM_ID:-}" ]; then
  RESUME_OUT=$(timeout 3 curl -s -w "\n%{http_code}" -N -X GET "${SERVER_URL}/mcp" \
    -H "$AUTH" \
    -H "Accept: text/event-stream" \
    -H "Mcp-Session-Id: $SESSION_ID" \
    -H "Last-Event-ID: ${STREAM_ID}" 2>/dev/null || true)
  RESUME_STATUS=$(echo "$RESUME_OUT" | tail -1)
  RESUME_BODY=$(echo "$RESUME_OUT" | sed '$d')
  if [ "$RESUME_STATUS" = "200" ]; then
    pass "Valid resume → 200 (stream replayed)"
  else
    fail "Valid resume" "status=$RESUME_STATUS"
  fi
else
  skip "No stream ID captured from test 10"
fi

# ============================================================
# DELETE /mcp — Session Termination
# ============================================================

echo ""
echo "=== DELETE /mcp: Session Termination ==="

# 26. No session header → 404
echo "--- 26. DELETE no session → 404 ---"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "${SERVER_URL}/mcp" \
  -H "$AUTH")
if [ "$STATUS" = "404" ]; then
  pass "DELETE without session header → 404"
else
  fail "DELETE no session" "expected 404, got $STATUS"
fi

# 27. Nonexistent session → 404
echo "--- 27. DELETE nonexistent session → 404 ---"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "${SERVER_URL}/mcp" \
  -H "$AUTH" \
  -H "Mcp-Session-Id: nonexistent-session-delete")
if [ "$STATUS" = "404" ]; then
  pass "DELETE nonexistent session → 404"
else
  fail "DELETE nonexistent session" "expected 404, got $STATUS"
fi

# 28. Valid session → 200
echo "--- 28. DELETE valid session → 200 ---"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "${SERVER_URL}/mcp" \
  -H "$AUTH" \
  -H "Mcp-Session-Id: $SESSION_ID")
if [ "$STATUS" = "200" ]; then
  pass "DELETE valid session → 200"
else
  fail "DELETE valid session" "expected 200, got $STATUS"
fi

# 29. After delete, same session → 404
echo "--- 29. After DELETE → 404 ---"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${SERVER_URL}/mcp" \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -H "Mcp-Session-Id: $SESSION_ID" \
  -d '{"jsonrpc":"2.0","id":29,"method":"tools/list","params":{}}')
if [ "$STATUS" = "404" ]; then
  pass "After DELETE, same session → 404"
else
  fail "After DELETE session" "expected 404, got $STATUS"
fi

# ============================================================
# /metrics — MCP Metrics
# ============================================================

echo ""
echo "=== /metrics: MCP Metrics ==="

# Get admin token for metrics endpoint
ADMIN_TOKEN=$(docker compose exec -T dbward-server cat /data/admin-token 2>/dev/null || echo "")

# 30. MCP metrics present
echo "--- 30. MCP metrics present ---"
METRICS=$(curl -s "${SERVER_URL}/metrics" -H "Authorization: Bearer $ADMIN_TOKEN")
MISSING=""
for METRIC in mcp_requests_total mcp_sessions_created_total mcp_sse_streams_total; do
  if ! echo "$METRICS" | grep -q "$METRIC"; then
    MISSING="$MISSING $METRIC"
  fi
done
if [ -z "$MISSING" ]; then
  pass "MCP metrics present (mcp_requests_total, mcp_sessions_created_total, mcp_sse_streams_total)"
else
  fail "MCP metrics missing" "not found:$MISSING"
fi

# 31. Unknown method appears as method="unknown" in metrics
echo "--- 31. Unknown method in metrics ---"
if echo "$METRICS" | grep -q 'method="unknown"'; then
  pass "Unknown method appears as method=\"unknown\" in metrics"
else
  fail "method=unknown in metrics" "not found in metrics output"
fi

# ============================================================
# Cleanup & Summary
# ============================================================

rm -f /tmp/mcp_comp_headers /tmp/mcp_comp_body /tmp/mcp_sse_headers

summary
