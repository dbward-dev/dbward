#!/bin/sh
set -eu

# Wait for bootstrap token file from server
TOKEN_FILE="/data/agent-token"
echo "[agent-entrypoint] waiting for $TOKEN_FILE..."
while [ ! -f "$TOKEN_FILE" ]; do
    sleep 1
done

export DBWARD_AGENT_TOKEN="$(cat "$TOKEN_FILE")"
echo "[agent-entrypoint] token loaded, starting agent"
exec dbward-agent --config /config/dbward-agent.toml
