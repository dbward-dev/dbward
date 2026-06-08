#!/bin/sh
set -eu

SERVER_URL="http://dbward-server:3000"

# Wait for server health
echo "[dev-init] waiting for server..."
until curl -sf "$SERVER_URL/health" >/dev/null 2>&1; do
    sleep 1
done

# Read bootstrap admin token
ADMIN_TOKEN="$(cat /data/admin-token)"

create_token() {
    user="$1"
    role="$2"
    path="$3"
    subject_type="${4:-user}"

    result=$(curl -sf -X POST "$SERVER_URL/api/tokens" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"subject_id\":\"$user\",\"roles\":[\"$role\"],\"subject_type\":\"$subject_type\"}")
    token=$(echo "$result" | grep -o '"token":"[^"]*"' | sed 's/"token":"//;s/"//')

    if [ -z "$token" ]; then
        echo "[dev-init] failed to create token for $user" >&2
        echo "$result" >&2
        exit 1
    fi

    printf '%s\n' "$token" > "$path"
    echo "[dev-init] wrote $(basename "$path") for $user ($role)"
}

mkdir -p /tokens

echo "[dev-init] creating API tokens"
create_token "alice" "developer" "/tokens/alice.token"
create_token "bob" "admin" "/tokens/bob.token"
create_token "carol" "developer" "/tokens/carol.token"
create_token "dave" "developer" "/tokens/dave.token"
create_token "agent" "agent-default" "/tokens/agent.token" "agent"
echo "[dev-init] done"
