#!/bin/sh
set -eu

user_name="$1"
shift

token_file="/tokens/${user_name}.token"
config_in="/config/dbward-cli.toml"
config_out="/tmp/dbward-cli.toml"

if [ ! -f "$token_file" ]; then
    echo "missing token file: $token_file" >&2
    exit 1
fi

token="$(cat "$token_file")"
escaped_token="$(printf '%s' "$token" | sed 's/[\\/&]/\\&/g')"

sed "s/__DBWARD_API_TOKEN__/${escaped_token}/" "$config_in" > "$config_out"

exec dbward --config "$config_out" "$@"
