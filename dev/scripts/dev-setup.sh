#!/bin/bash
# Generate dev secrets required by docker compose.
# Run once before `docker compose up`.
set -eu

SECRETS_DIR="$(cd "$(dirname "$0")/.." && pwd)/secrets"
mkdir -p "$SECRETS_DIR"

# Postgres password (must match agent.toml connection strings)
if [ ! -f "$SECRETS_DIR/db_password.txt" ]; then
  printf "dbward" > "$SECRETS_DIR/db_password.txt"
  echo "[dev-setup] created db_password.txt"
fi

# Empty license key placeholder (server reads this file on startup)
if [ ! -f "$SECRETS_DIR/license.key" ]; then
  touch "$SECRETS_DIR/license.key"
  echo "[dev-setup] created license.key (empty = Free plan)"
fi

echo "[dev-setup] done — secrets in $SECRETS_DIR"
