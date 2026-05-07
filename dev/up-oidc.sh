#!/bin/sh
# Start dbward with OIDC (Pro mode + Keycloak)
# Usage: ./dev/up-oidc.sh [-d]
set -eu
cd "$(dirname "$0")/.."

export DBWARD_LICENSE_KEY=$(cat fixtures/license/pro.license)
export DBWARD_SERVER_CONFIG=dbward-server-oidc.toml
docker compose --profile oidc up "$@"
