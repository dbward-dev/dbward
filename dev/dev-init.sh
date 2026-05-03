#!/bin/sh
set -eu

create_token() {
    user="$1"
    role="$2"
    path="$3"

    output="$(dbward server token create --user "$user" --role "$role" --data /data/dbward.db)"
    token="$(printf '%s\n' "$output" | awk -F': ' '/^  Token: /{print $2}')"

    if [ -z "$token" ]; then
        printf '%s\n' "$output" >&2
        echo "[dev-init] failed to parse token for $user" >&2
        exit 1
    fi

    printf '%s\n' "$token" > "$path"
    echo "[dev-init] wrote $(basename "$path") for $user ($role)"
}

mkdir -p /tokens

echo "[dev-init] creating API tokens"
create_token "alice" "developer" "/tokens/alice.token"
create_token "bob" "admin" "/tokens/bob.token"
create_token "agent" "admin" "/tokens/agent.token"
echo "[dev-init] done"
