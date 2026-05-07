#!/bin/sh
# Entrypoint for backup sidecar. Installs deps once, then runs cron.
set -eu

if ! command -v sqlite3 >/dev/null 2>&1; then
  apk add --no-cache sqlite
fi

# Only install aws-cli if S3 bucket is configured
if [ -n "${BACKUP_S3_BUCKET:-}" ] && ! command -v aws >/dev/null 2>&1; then
  apk add --no-cache aws-cli
fi

echo "0 */6 * * * /scripts/backup.sh >> /backups/backup.log 2>&1" | crontab -
echo "backup cron started (every 6h)"
crond -f
