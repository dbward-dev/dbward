#!/bin/bash
# E2E test helpers — source this from other e2e scripts
# Usage: source dev/e2e-helpers.sh

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'
PASS=0
FAIL=0

pass() { echo -e "${GREEN}✅ PASS${NC}: $1"; PASS=$((PASS+1)); }
fail() { echo -e "${RED}❌ FAIL${NC}: $1 — $2"; FAIL=$((FAIL+1)); }
skip() { echo -e "${YELLOW}⏭ SKIP${NC}: $1"; }

SERVER_URL="${SERVER_URL:-http://localhost:13000}"

# API call helper
api() {
  local method=$1 path=$2 token=$3
  shift 3
  curl -s -X "$method" "${SERVER_URL}${path}" \
    -H "Authorization: Bearer $token" -H "Content-Type: application/json" "$@"
}

# API call returning HTTP status code only
api_status() {
  local method=$1 path=$2 token=$3
  shift 3
  curl -s -o /dev/null -w "%{http_code}" -X "$method" "${SERVER_URL}${path}" \
    -H "Authorization: Bearer $token" -H "Content-Type: application/json" "$@"
}

# API call without auth
api_noauth() {
  local method=$1 path=$2
  shift 2
  curl -s -o /dev/null -w "%{http_code}" -X "$method" "${SERVER_URL}${path}" \
    -H "Content-Type: application/json" "$@"
}

# JSON field extraction
json_field() {
  python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('$1',''))"
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

# Create API token via server token create (requires running server with dev-init)
# Reads from shared volume created by dev-init container
read_token() {
  local file="/tmp/dbward-tokens/$1"
  [ -f "$file" ] && cat "$file" || echo ""
}

# Print summary and exit
summary() {
  echo ""
  echo "=== Results: $PASS passed, $FAIL failed ==="
  [ $FAIL -gt 0 ] && exit 1 || exit 0
}
