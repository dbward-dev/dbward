#!/bin/bash
set -e

DB_PATH="${DBWARD_DB_PATH:-/data/dbward.db}"
export DBWARD_DB_PATH="$DB_PATH"

# If Litestream S3 bucket is configured, use Litestream for replication
if [ -n "${LITESTREAM_S3_BUCKET:-}" ]; then
  # Restore from S3 if DB doesn't exist (first deploy or disaster recovery)
  litestream restore -if-db-not-exists -if-replica-exists "$DB_PATH"

  # Start Litestream replication with dbward as child process
  exec litestream replicate -exec "dbward $*"
fi

# No Litestream configured — run dbward directly
exec dbward "$@"
