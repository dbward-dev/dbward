#!/bin/bash
# E2E test helpers — source this from other e2e scripts
# Usage: source "$(dirname "$0")/helpers.sh"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
DIM='\033[2m'
NC='\033[0m'
PASS=0
FAIL=0

pass() { echo -e "${GREEN}✅ PASS${NC}: $1"; PASS=$((PASS+1)); }
fail() {
  echo -e "${RED}❌ FAIL${NC}: $1 — $2"
  FAIL=$((FAIL+1))
  # Show last response body on failure
  if [ -n "${LAST_RESPONSE_BODY:-}" ]; then
    echo -e "${DIM}   Response: ${LAST_RESPONSE_BODY:0:200}${NC}"
  fi
}
skip() { echo -e "${YELLOW}⏭ SKIP${NC}: $1"; }

# Show application output for UX review
show_output() {
  echo -e "${CYAN}   → $1${NC}"
}

SERVER_URL="${SERVER_URL:-http://localhost:13000}"
LAST_RESPONSE_BODY=""

# Ensure summary is printed even on set -e failure
trap 'cleanup_tokens; echo ""; echo "=== Results: $PASS passed, $FAIL failed (interrupted) ==="; [ $FAIL -gt 0 ] && show_server_logs 20' EXIT

# API call helper — stores response body for failure reporting
api() {
  local method=$1 path=$2 token=$3
  shift 3
  LAST_RESPONSE_BODY=$(curl -s -X "$method" "${SERVER_URL}${path}" \
    -H "Authorization: Bearer $token" -H "Content-Type: application/json" "$@")
  echo "$LAST_RESPONSE_BODY"
}

# API call returning HTTP status code + stores body
api_status() {
  local method=$1 path=$2 token=$3
  shift 3
  local tmpfile=$(mktemp)
  local status=$(curl -s -o "$tmpfile" -w "%{http_code}" -X "$method" "${SERVER_URL}${path}" \
    -H "Authorization: Bearer $token" -H "Content-Type: application/json" "$@")
  LAST_RESPONSE_BODY=$(cat "$tmpfile")
  rm -f "$tmpfile"
  echo "$status"
}

# API call without auth
api_noauth() {
  local method=$1 path=$2
  shift 2
  local tmpfile=$(mktemp)
  local status=$(curl -s -o "$tmpfile" -w "%{http_code}" -X "$method" "${SERVER_URL}${path}" \
    -H "Content-Type: application/json" "$@")
  LAST_RESPONSE_BODY=$(cat "$tmpfile")
  rm -f "$tmpfile"
  echo "$status"
}

# JSON field extraction
json_field() {
  python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('$1',''))"
}

# JSON error code extraction (for UX review)
json_error() {
  echo "$LAST_RESPONSE_BODY" | python3 -c "
import sys,json
try:
  d=json.load(sys.stdin)
  code=d.get('code','')
  error=d.get('error','')
  print(f'{code}: {error}' if code else error)
except: print('(not JSON)')" 2>/dev/null
}

# Wait for server to be ready
wait_for_server() {
  echo "Waiting for dbward-server..."
  for i in $(seq 1 30); do
    curl -sf "${SERVER_URL}/health" >/dev/null 2>&1 && break || sleep 2
  done
  curl -sf "${SERVER_URL}/health" >/dev/null 2>&1 || { echo "Server failed to start"; exit 1; }
  echo "Server ready"
}

# Wait for Keycloak
wait_for_keycloak() {
  echo "Waiting for Keycloak..."
  for i in $(seq 1 60); do
    curl -sf http://localhost:8080/realms/dbward/.well-known/openid-configuration >/dev/null 2>&1 && break || sleep 3
  done
  curl -sf http://localhost:8080/realms/dbward/.well-known/openid-configuration >/dev/null 2>&1 || { echo "Keycloak failed to start"; exit 1; }
  echo "Keycloak ready"
}

# Get OIDC token
get_oidc_token() {
  curl -s -X POST http://localhost:8080/realms/dbward/protocol/openid-connect/token \
    -d "grant_type=password" -d "client_id=dbward-cli" -d "username=$1" -d "password=$1" | json_field access_token
}

# Show server logs (last N lines)
show_server_logs() {
  local lines=${1:-20}
  echo -e "${DIM}--- Server logs (last $lines lines) ---${NC}"
  docker compose logs dbward-server --tail="$lines" --no-log-prefix 2>/dev/null | sed "s/^/  ${DIM}/"
  echo -e "${NC}"
}

# Create API token via dbward-server CLI (PR#16+ format)
# Tracks created tokens for cleanup via temp file
CREATED_TOKENS_FILE=$(mktemp)
create_token() {
  local user=$1 role=$2
  shift 2
  local extra_args=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --groups) extra_args="$extra_args --groups $2"; shift 2 ;;
      --agent) extra_args="$extra_args --agent"; shift ;;
      *) shift ;;
    esac
  done
  # Read admin token from file (written by auto-bootstrap on first startup)
  local admin_token
  admin_token=$(docker compose exec -T dbward-server cat /data/admin-token 2>/dev/null || echo "")
  # Create token via API
  local is_agent=""
  case "$extra_args" in *--agent*) is_agent="agent" ;; esac
  local subject_type="${is_agent:-user}"
  local result
  result=$(curl -sf -X POST "${SERVER_URL}/api/tokens" \
    -H "Authorization: Bearer $admin_token" \
    -H "Content-Type: application/json" \
    -d "{\"subject_id\":\"$user\",\"roles\":[\"$role\"],\"subject_type\":\"$subject_type\"}" 2>&1) || true
  local token
  token=$(echo "$result" | grep -o '"token":"[^"]*"' | sed 's/"token":"//;s/"//')
  if [ -n "$token" ]; then
    local token_id
    token_id=$(echo "$result" | grep -o '"id":"[^"]*"' | sed 's/"id":"//;s/"//' | head -1)
    [ -n "$token_id" ] && echo "$token_id" >> "$CREATED_TOKENS_FILE"
  fi
  echo "$token"
}

# Revoke all tokens created during this test run
cleanup_tokens() {
  if [ -z "${CREATED_TOKENS_FILE:-}" ] || [ ! -s "$CREATED_TOKENS_FILE" ]; then return; fi
  local admin_token
  admin_token=$(docker compose exec -T dbward-server cat /data/admin-token 2>/dev/null || echo "")
  while IFS= read -r token_id; do
    curl -sf -X DELETE "${SERVER_URL}/api/tokens/$token_id" \
      -H "Authorization: Bearer $admin_token" 2>/dev/null || true
  done < "$CREATED_TOKENS_FILE"
  rm -f "$CREATED_TOKENS_FILE"
}

# Print summary and exit (disables trap to avoid double-print)

# Poll request status until it reaches expected state or timeout.
# Usage: wait_for_status <request_id> <expected_status> <token> [timeout_secs]
# Returns 0 on success, 1 on timeout/failure.
wait_for_status() {
  local req_id=$1 expected=$2 token=$3 timeout=${4:-30}
  for i in $(seq 1 "$timeout"); do
    local status
    status=$(api GET "/api/requests/$req_id" "$token" | json_field status)
    [ "$status" = "$expected" ] && return 0
    # Terminal failure states — stop early
    case "$status" in
      failed|rejected|cancelled) [ "$status" != "$expected" ] && return 1 ;;
    esac
    sleep 1
  done
  return 1
}

summary() {
  trap - EXIT
  cleanup_tokens
  echo ""
  echo "=== Results: $PASS passed, $FAIL failed ==="
  if [ $FAIL -gt 0 ]; then
    echo ""
    echo "Server logs around failures:"
    show_server_logs 30
    exit 1
  fi
  exit 0
}
