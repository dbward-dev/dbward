#!/bin/bash
# E2E Security: SSRF prevention
# Tests that webhooks to internal IPs are rejected.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."
source "$SCRIPT_DIR/helpers.sh"

echo ""
echo "=== SSRF Prevention Tests ==="
echo ""

ADMIN_TOKEN=$(create_token e2e-ssrf-admin admin)
[ -z "$ADMIN_TOKEN" ] && { echo "Failed to create token"; exit 1; }

# --- Webhook to localhost ---
echo "--- Internal IP rejection ---"

STATUS=$(api_status POST /api/webhooks "$ADMIN_TOKEN" \
  -d '{"url":"http://127.0.0.1:8080/hook","events":["request.created"],"format":"generic"}')
[ "$STATUS" = "400" ] || [ "$STATUS" = "422" ] && pass "localhost webhook rejected ($STATUS)" || fail "localhost" "got $STATUS"

# Link-local (AWS metadata)
STATUS=$(api_status POST /api/webhooks "$ADMIN_TOKEN" \
  -d '{"url":"http://169.254.169.254/latest/meta-data/","events":["request.created"],"format":"generic"}')
[ "$STATUS" = "400" ] || [ "$STATUS" = "422" ] && pass "AWS metadata IP rejected ($STATUS)" || fail "169.254" "got $STATUS"

# Private network (10.x)
STATUS=$(api_status POST /api/webhooks "$ADMIN_TOKEN" \
  -d '{"url":"http://10.0.0.1:80/internal","events":["request.created"],"format":"generic"}')
[ "$STATUS" = "400" ] || [ "$STATUS" = "422" ] && pass "Private 10.x rejected ($STATUS)" || fail "10.x" "got $STATUS"

# IPv4-mapped IPv6 (SEC-5)
STATUS=$(api_status POST /api/webhooks "$ADMIN_TOKEN" \
  -d '{"url":"http://[::ffff:127.0.0.1]:80/hook","events":["request.created"],"format":"generic"}')
[ "$STATUS" = "400" ] || [ "$STATUS" = "422" ] && pass "IPv4-mapped IPv6 rejected ($STATUS)" || fail "::ffff:127.0.0.1" "got $STATUS"

# IPv6 loopback
STATUS=$(api_status POST /api/webhooks "$ADMIN_TOKEN" \
  -d '{"url":"http://[::1]:80/hook","events":["request.created"],"format":"generic"}')
[ "$STATUS" = "400" ] || [ "$STATUS" = "422" ] && pass "IPv6 loopback rejected ($STATUS)" || fail "::1" "got $STATUS"

# 0.0.0.0
STATUS=$(api_status POST /api/webhooks "$ADMIN_TOKEN" \
  -d '{"url":"http://0.0.0.0:80/hook","events":["request.created"],"format":"generic"}')
[ "$STATUS" = "400" ] || [ "$STATUS" = "422" ] && pass "0.0.0.0 rejected ($STATUS)" || fail "0.0.0.0" "got $STATUS"

# --- Valid external URL format accepted (DNS may fail in Docker, check not 500) ---
echo ""
echo "--- Valid URL format ---"

STATUS=$(api_status POST /api/webhooks "$ADMIN_TOKEN" \
  -d '{"url":"https://hooks.example.com/dbward","events":["request.created"],"format":"generic"}')
[ "$STATUS" = "201" ] || [ "$STATUS" = "400" ] && pass "External URL handled ($STATUS — DNS may be unavailable)" || fail "External URL" "got $STATUS"

summary
