#!/bin/sh
set -eu
# Wait for server to write the bootstrap agent token
TOKEN_FILE="${DBWARD_AGENT_TOKEN_FILE:-/data/agent-token}"
while [ ! -f "$TOKEN_FILE" ]; do sleep 1; done
export DBWARD_AGENT_TOKEN="$(cat "$TOKEN_FILE")"
exec dbward-agent "$@"
