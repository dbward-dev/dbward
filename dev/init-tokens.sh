#!/bin/sh
set -eu

echo "[dev-init] creating API tokens"

create_token() {
    user="$1"
    role="$2"
    path="$3"
    extra="${4:-}"

    output="$(docker compose exec -T dbward-server dbward server token create --user "$user" --role "$role" $extra --data /data/dbward.db)"
    token="$(printf '%s\n' "$output" | awk -F': ' '/Token: /{print $2}')"

    if [ -z "$token" ]; then
        printf '%s\n' "$output" >&2
        echo "[dev-init] failed to parse token for $user" >&2
        exit 1
    fi

    printf '%s\n' "$token" > "$path"
    echo "[dev-init] wrote $(basename "$path") for $user ($role)"
}

mkdir -p dev/tokens

create_token "alice" "developer" "dev/tokens/alice.token"
create_token "bob" "admin" "dev/tokens/bob.token"
create_token "carol" "developer" "dev/tokens/carol.token"
create_token "dave" "developer" "dev/tokens/dave.token"
create_token "agent" "admin" "dev/tokens/agent.token" "--agent"
echo "[dev-init] done"
