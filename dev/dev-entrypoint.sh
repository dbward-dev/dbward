#!/bin/sh
# Wrapper: reads token from /tokens/<username>.token and runs dbward
# Usage: dev-entrypoint.sh <username> <dbward args...>
USER=$1
shift

if [ -f "/tokens/${USER}.token" ]; then
    export DBWARD_SERVER_TOKEN=$(cat "/tokens/${USER}.token")
fi

exec dbward "$@"
