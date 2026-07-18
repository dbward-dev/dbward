#!/bin/bash
# E2E: MCP stdio protocol tests — verify dbward mcp responds to JSON-RPC
# Requires: docker compose services running (server + agent + postgres)
# Usage: ./dev/e2e/mcp.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."
source "$SCRIPT_DIR/helpers.sh"

echo ""
echo "=== E2E MCP Tests ==="
echo ""

wait_for_server

MCP_TOKEN=$(create_token mcp-user requester)
[ -z "$MCP_TOKEN" ] && { echo "Failed to create token"; exit 1; }

# Write CLI config for MCP
docker compose exec -T dbward-server sh -c "cat > /tmp/mcp-test.toml << TOML
default_database = \"app\"

[server]
url = \"http://localhost:3000\"
token = \"$MCP_TOKEN\"

[databases.app]
TOML"

# Helper: send JSON-RPC to dbward mcp via stdin and capture response
mcp_call() {
  local request="$1"
  echo "$request" | docker compose exec -T dbward-server dbward --config /tmp/mcp-test.toml mcp 2>/dev/null | head -1
}

# --- 1. Initialize handshake ---
echo "--- MCP initialize ---"

INIT_REQ='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"e2e-test","version":"1.0"}}}'
RESP=$(mcp_call "$INIT_REQ")

if echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('result',{}).get('serverInfo'), 'no serverInfo'; print('ok')" 2>/dev/null; then
  pass "MCP initialize returns serverInfo"
  show_output "$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['serverInfo'])" 2>/dev/null)"
else
  fail "MCP initialize" "$(echo "$RESP" | head -c 200)"
fi

# --- 2. tools/list ---
echo ""
echo "--- MCP tools/list ---"

TOOLS_REQ='{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
# Need to send initialize first, then tools/list in same session
COMBINED=$(printf '%s\n%s\n' "$INIT_REQ" "$TOOLS_REQ" | docker compose exec -T \
  dbward-server dbward --config /tmp/mcp-test.toml mcp 2>/dev/null | tail -1)

if echo "$COMBINED" | python3 -c "
import sys,json
d=json.load(sys.stdin)
tools = d.get('result',{}).get('tools',[])
names = [t['name'] for t in tools]
assert 'dbward_execute_query' in names, f'missing dbward_execute_query in {names}'
print(f'{len(tools)} tools')
" 2>/dev/null; then
  TOOL_COUNT=$(echo "$COMBINED" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['result']['tools']))" 2>/dev/null)
  pass "MCP tools/list returns $TOOL_COUNT tools (includes dbward_execute_query)"
else
  fail "MCP tools/list" "$(echo "$COMBINED" | head -c 200)"
fi

# --- 3. tools/call — dbward_list_pending ---
echo ""
echo "--- MCP tools/call dbward_list_pending ---"

CALL_REQ='{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"dbward_list_pending","arguments":{}}}'
COMBINED=$(printf '%s\n%s\n' "$INIT_REQ" "$CALL_REQ" | docker compose exec -T \
  dbward-server dbward --config /tmp/mcp-test.toml mcp 2>/dev/null | tail -1)

if echo "$COMBINED" | python3 -c "
import sys,json
d=json.load(sys.stdin)
content = d.get('result',{}).get('content',[])
is_error = d.get('result',{}).get('isError', False)
assert not is_error, f'tool returned error: {content}'
print('ok')
" 2>/dev/null; then
  pass "MCP dbward_list_pending returns successfully"
else
  fail "MCP dbward_list_pending" "$(echo "$COMBINED" | head -c 200)"
fi

# --- 4. Invalid method → error ---
echo ""
echo "--- MCP invalid method ---"

BAD_REQ='{"jsonrpc":"2.0","id":4,"method":"nonexistent/method","params":{}}'
COMBINED=$(printf '%s\n%s\n' "$INIT_REQ" "$BAD_REQ" | docker compose exec -T \
  dbward-server dbward --config /tmp/mcp-test.toml mcp 2>/dev/null | tail -1)

if echo "$COMBINED" | python3 -c "
import sys,json
d=json.load(sys.stdin)
assert 'error' in d, 'expected error response'
print('ok')
" 2>/dev/null; then
  pass "MCP invalid method returns JSON-RPC error"
else
  fail "MCP invalid method" "$(echo "$COMBINED" | head -c 200)"
fi

summary
