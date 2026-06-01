#!/bin/sh
# Quick Start initialization: creates API tokens for alice (developer) and bob (admin).
# Run after `docker compose up -d`.
set -eu

COMPOSE_CMD="docker compose -f dev/compose.yml -f dev/compose.override.yml"
SERVER_URL="http://localhost:13000"

echo "[quickstart] waiting for server..."
i=0
until curl -sf "$SERVER_URL/health" >/dev/null 2>&1; do
    i=$((i + 1))
    [ "$i" -ge 30 ] && echo "[quickstart] server not ready after 30s" >&2 && exit 1
    sleep 1
done

ADMIN_TOKEN=$($COMPOSE_CMD exec -T dbward-server cat /data/admin-token)

create_token() {
    user="$1"
    role="$2"
    path="$3"

    token=$(curl -sf -X POST "$SERVER_URL/api/tokens" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"subject_id\":\"$user\",\"roles\":[\"$role\"],\"subject_type\":\"user\"}" \
        | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

    printf '%s' "$token" > "$path"
    echo "[quickstart] $user ($role) → $path"
}

mkdir -p dev/tokens
create_token "alice" "developer" "dev/tokens/alice.token"
create_token "bob" "admin" "dev/tokens/bob.token"
echo "[quickstart] done — tokens in dev/tokens/"
