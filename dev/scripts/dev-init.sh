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

create_user_token() {
    user="$1"
    role="$2"
    path="$3"

    # Try to create user (returns initial token)
    result=$(curl -s -X POST "$SERVER_URL/api/users" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"id\":\"$user\",\"roles\":[\"$role\"]}")

    token=$(echo "$result" | grep -o '"token":"[^"]*"' | sed 's/"token":"//;s/"//')

    if [ -z "$token" ]; then
        # User might already exist — reissue initial token
        result=$(curl -s -X POST "$SERVER_URL/api/users/$user/reissue-initial-token" \
            -H "Authorization: Bearer $ADMIN_TOKEN" \
            -H "Content-Type: application/json")
        token=$(echo "$result" | grep -o '"token":"[^"]*"' | sed 's/"token":"//;s/"//')
    fi

    if [ -z "$token" ]; then
        echo "[dev-init] failed to create/reissue token for $user" >&2
        echo "$result" >&2
        exit 1
    fi

    printf '%s\n' "$token" > "$path"
    echo "[dev-init] wrote $(basename "$path") for $user ($role)"
}

create_agent_token() {
    user="$1"
    path="$2"

    result=$(curl -s -X POST "$SERVER_URL/api/tokens" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"subject_id\":\"$user\",\"subject_type\":\"agent\"}")
    token=$(echo "$result" | grep -o '"token":"[^"]*"' | sed 's/"token":"//;s/"//')

    if [ -z "$token" ]; then
        echo "[dev-init] failed to create agent token for $user" >&2
        echo "$result" >&2
        exit 1
    fi

    printf '%s\n' "$token" > "$path"
    echo "[dev-init] wrote $(basename "$path") for $user (agent)"
}

mkdir -p /tokens

echo "[dev-init] creating users and tokens"
create_user_token "alice" "developer" "/tokens/alice.token"
create_user_token "bob" "admin" "/tokens/bob.token"
create_user_token "carol" "developer" "/tokens/carol.token"
create_user_token "dave" "developer" "/tokens/dave.token"
create_agent_token "agent" "/tokens/agent.token"
echo "[dev-init] done"
