#!/bin/bash
set -e

# If running as root, fix /data ownership and re-exec as dbward
if [ "$(id -u)" = '0' ]; then
  chown -R dbward:dbward /data
  exec gosu dbward "$0" "$@"
fi

DB_PATH="/data/dbward.db"

# Litestream replication mode (requires litestream binary in the image)
if [ -n "${LITESTREAM_S3_BUCKET:-}" ]; then
  litestream restore -if-db-not-exists -if-replica-exists "$DB_PATH"
  exec litestream replicate -exec "$*"
fi

exec "$@"
