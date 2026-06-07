#!/bin/sh
set -eu
while [ ! -f "$TOKEN_FILE" ]; do sleep 1; done
export DBWARD_API_TOKEN="$(cat "$TOKEN_FILE")"
exec dbward --config /config/cli.toml "$@"
