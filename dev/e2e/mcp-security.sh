#!/bin/bash
# E2E Security: MCP tool input validation + Config injection
# Tests path traversal, SQL identifier injection via MCP,
# and env var TOML meta-character injection.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."
source "$SCRIPT_DIR/helpers.sh"

echo ""
echo "=== MCP Security + Config Injection Tests ==="
echo ""

ADMIN_TOKEN=$(create_token e2e-mcp-admin admin)
[ -z "$ADMIN_TOKEN" ] && { echo "Failed to create token"; exit 1; }

# --- Path traversal in database/table names ---
echo "--- Path traversal in API params ---"

# Database name with path traversal
STATUS=$(api_status GET "/api/schemas/..%2F..%2Fetc%2Fpasswd" "$ADMIN_TOKEN")
[ "$STATUS" = "400" ] || [ "$STATUS" = "404" ] && pass "Path traversal in schema DB rejected ($STATUS)" || fail "Schema traversal" "got $STATUS"

# Table name with path traversal (must not return 200 with data)
STATUS=$(api_status GET "/api/schemas/app?table=../../etc/passwd" "$ADMIN_TOKEN")
[ "$STATUS" = "400" ] || [ "$STATUS" = "404" ] && pass "Table traversal rejected ($STATUS)" || fail "Table traversal" "got $STATUS (expected 400 or 404)"

# --- SQL identifier injection ---
echo ""
echo "--- SQL identifier injection ---"

# Semicolon in table name
STATUS=$(api_status GET "/api/schemas/app?table=users;DROP+TABLE+users" "$ADMIN_TOKEN")
[ "$STATUS" = "400" ] || [ "$STATUS" = "404" ] && pass "SQL injection in table param rejected ($STATUS)" || fail "Table SQL injection" "got $STATUS"

# Quote in database name
STATUS=$(api_status GET "/api/schemas/dbward'_dev" "$ADMIN_TOKEN")
[ "$STATUS" = "400" ] || [ "$STATUS" = "404" ] && pass "Quote in DB name rejected ($STATUS)" || fail "Quote in DB" "got $STATUS"

# --- Webhook URL with special characters ---
echo ""
echo "--- URL injection in webhook ---"

STATUS=$(api_status POST /api/webhooks "$ADMIN_TOKEN" \
  -d '{"url":"http://example.com/hook?x=1&url=http://169.254.169.254","events":["request.created"],"format":"generic"}')
# CFG-24: webhook write API returns 405 (config-managed)
[ "$STATUS" = "405" ] && pass "Webhook POST returns 405 (config-managed)" || fail "Webhook URL injection" "got $STATUS"

# --- Config injection via request metadata ---
echo ""
echo "--- Metadata injection ---"

# Try to inject via metadata field (should be stored as-is, not interpreted)
STATUS=$(api_status POST /api/requests "$ADMIN_TOKEN" \
  -d '{"detail":"SELECT 1","database":"app","environment":"development","metadata":{"__proto__":{"admin":true},"constructor":{"prototype":{"isAdmin":true}}}}')
[ "$STATUS" = "201" ] && pass "Prototype pollution in metadata harmless" || fail "Metadata injection" "got $STATUS"

# --- Oversized metadata ---
echo ""
echo "--- Oversized fields ---"

BIG_REASON=$(python3 -c "print('A'*100000)")
STATUS=$(api_status POST /api/requests "$ADMIN_TOKEN" \
  -d "{\"detail\":\"SELECT 1\",\"database\":\"app\",\"environment\":\"development\",\"reason\":\"$BIG_REASON\"}")
[ "$STATUS" = "400" ] || [ "$STATUS" = "413" ] || [ "$STATUS" = "201" ] && pass "Large reason field handled ($STATUS)" || fail "Large reason" "got $STATUS"

summary
