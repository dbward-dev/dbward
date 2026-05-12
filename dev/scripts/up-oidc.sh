#!/bin/sh
# Start dbward with OIDC (Pro mode + Keycloak)
# Usage: ./dev/scripts/up-oidc.sh [-d]
# Requires: DBWARD_LICENSE_KEY env var (or set in dev/.env)
set -eu
cd "$(dirname "$0")/.."

export DBWARD_SERVER_CONFIG=server-oidc.toml
docker compose --profile oidc up "$@"
