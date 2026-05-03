#!/bin/sh
set -eu

token_file="/tokens/agent.token"
config_in="/config/dbward-agent.toml"
config_out="/tmp/dbward-agent.toml"

if [ ! -f "$token_file" ]; then
    echo "missing token file: $token_file" >&2
    exit 1
fi

token="$(cat "$token_file")"
escaped_token="$(printf '%s' "$token" | sed 's/[\\/&]/\\&/g')"

sed "s/__DBWARD_AGENT_TOKEN__/${escaped_token}/" "$config_in" > "$config_out"

exec dbward agent --config "$config_out"
