#!/bin/bash
# E2E: MCP HTTP transport tests (POST /mcp)
# Verifies: initialize → tools/list → tools/call → resources/read → error cases
# Requires: docker compose services running (server + agent + postgres)
# Usage: ./dev/e2e/mcp-http.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."
source "$SCRIPT_DIR/helpers.sh"

echo ""
echo "=== E2E MCP HTTP Transport Tests ==="
echo ""

wait_for_server

TOKEN=$(create_token mcp-http-user requester)
[ -z "$TOKEN" ] && { echo "Failed to create token"; exit 1; }

# Helper: POST /mcp with JSON-RPC body
mcp_post() {
  local body="$1"
  curl -s -X POST "${SERVER_URL}/mcp" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -d "$body"
}

mcp_post_status() {
  local body="$1"
  local tmpfile=$(mktemp)
  local status=$(curl -s -o "$tmpfile" -w "%{http_code}" -X POST "${SERVER_URL}/mcp" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -d "$body")
  LAST_RESPONSE_BODY=$(cat "$tmpfile")
  rm -f "$tmpfile"
  echo "$status"
}

# --- 1. Initialize ---
echo "--- 1. Initialize handshake ---"

RESP=$(mcp_post '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"e2e-test","version":"1.0"}}}')
if echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d['result']['protocolVersion']=='2025-03-26'" 2>/dev/null; then
  pass "initialize returns protocolVersion 2025-03-26"
else
  fail "initialize" "$RESP"
fi

# --- 2. tools/list ---
echo "--- 2. tools/list ---"

RESP=$(mcp_post '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}')
TOOL_COUNT=$(echo "$RESP" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['result']['tools']))" 2>/dev/null || echo "0")
if [ "$TOOL_COUNT" = "8" ]; then
  pass "tools/list returns 8 tools"
else
  fail "tools/list tool count" "expected 8, got $TOOL_COUNT"
fi

# --- 3. tools/call — inspect_schema ---
echo "--- 3. tools/call (inspect_schema) ---"

RESP=$(mcp_post '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"dbward_inspect_schema","arguments":{"database":"app"}}}')
if echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'content' in d['result']" 2>/dev/null; then
  pass "tools/call inspect_schema returns content"
else
  fail "tools/call inspect_schema" "$RESP"
fi

# --- 4. resources/list ---
echo "--- 4. resources/list ---"

RESP=$(mcp_post '{"jsonrpc":"2.0","id":4,"method":"resources/list","params":{}}')
RES_COUNT=$(echo "$RESP" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['result']['resources']))" 2>/dev/null || echo "0")
if [ "$RES_COUNT" = "3" ]; then
  pass "resources/list returns 3 resources"
else
  fail "resources/list" "expected 3, got $RES_COUNT"
fi

# --- 5. resources/templates/list ---
echo "--- 5. resources/templates/list ---"

RESP=$(mcp_post '{"jsonrpc":"2.0","id":5,"method":"resources/templates/list","params":{}}')
TMPL_COUNT=$(echo "$RESP" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['result']['resourceTemplates']))" 2>/dev/null || echo "0")
if [ "$TMPL_COUNT" = "3" ]; then
  pass "resources/templates/list returns 3 templates"
else
  fail "resources/templates/list" "expected 3, got $TMPL_COUNT"
fi

# --- 6. prompts/list ---
echo "--- 6. prompts/list ---"

RESP=$(mcp_post '{"jsonrpc":"2.0","id":6,"method":"prompts/list","params":{}}')
PROMPT_COUNT=$(echo "$RESP" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['result']['prompts']))" 2>/dev/null || echo "0")
if [ "$PROMPT_COUNT" = "4" ]; then
  pass "prompts/list returns 4 prompts"
else
  fail "prompts/list" "expected 4, got $PROMPT_COUNT"
fi

# --- 7. Notification → 202 Accepted ---
echo "--- 7. Notification (no id) ---"

STATUS=$(mcp_post_status '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}')
if [ "$STATUS" = "202" ]; then
  pass "notification returns 202 Accepted"
else
  fail "notification status" "expected 202, got $STATUS"
fi

# --- 8. Error cases ---
echo "--- 8. Error cases ---"

# 8a: No auth → 401
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${SERVER_URL}/mcp" \
  -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}')
if [ "$STATUS" = "401" ]; then
  pass "no auth returns 401"
else
  fail "no auth" "expected 401, got $STATUS"
fi

# 8b: GET → 405
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X GET "${SERVER_URL}/mcp" \
  -H "Authorization: Bearer $TOKEN")
if [ "$STATUS" = "405" ]; then
  pass "GET /mcp returns 405"
else
  fail "GET /mcp" "expected 405, got $STATUS"
fi

# 8c: No Content-Type → 415
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${SERVER_URL}/mcp" \
  -H "Authorization: Bearer $TOKEN" -d '{}')
if [ "$STATUS" = "415" ]; then
  pass "missing Content-Type returns 415"
else
  fail "missing Content-Type" "expected 415, got $STATUS"
fi

# 8d: Unknown method → -32601
RESP=$(mcp_post '{"jsonrpc":"2.0","id":99,"method":"foo/bar","params":{}}')
ERR_CODE=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('error',{}).get('code',''))" 2>/dev/null)
if [ "$ERR_CODE" = "-32601" ]; then
  pass "unknown method returns -32601"
else
  fail "unknown method error code" "expected -32601, got $ERR_CODE"
fi

# 8e: Unsupported protocol version → server negotiates to latest (no error)
RESP=$(mcp_post '{"jsonrpc":"2.0","id":100,"method":"initialize","params":{"protocolVersion":"2024-01-01","capabilities":{}}}')
if echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d['result']['protocolVersion'] == '2025-06-18'" 2>/dev/null; then
  pass "unsupported protocol version negotiates to latest"
else
  fail "unsupported version" "$RESP"
fi

# 8f: Batch → -32600
RESP=$(curl -s -X POST "${SERVER_URL}/mcp" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]')
ERR_CODE=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('error',{}).get('code',''))" 2>/dev/null)
if [ "$ERR_CODE" = "-32600" ]; then
  pass "batch request returns -32600"
else
  fail "batch error code" "expected -32600, got $ERR_CODE"
fi

# --- Summary ---
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -gt 0 ] && exit 1
exit 0
