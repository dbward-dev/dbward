#!/bin/sh
# Backup dbward SQLite database.
# Writes to /backups volume (separate from server-data which is :ro).
set -eu

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backups"
BACKUP_FILE="${BACKUP_DIR}/dbward_${TIMESTAMP}.db"

# Online backup with 30s timeout (safe while server is running)
sqlite3 /data/dbward.db ".timeout 30000" ".backup '${BACKUP_FILE}'"

# Keep only last 7 local backups
ls -t "${BACKUP_DIR}"/dbward_*.db 2>/dev/null | tail -n +8 | xargs -r rm

# Upload to S3 if configured
if [ -n "${BACKUP_S3_BUCKET:-}" ]; then
  aws s3 cp "$BACKUP_FILE" \
    "s3://${BACKUP_S3_BUCKET}/${BACKUP_S3_PREFIX}dbward_${TIMESTAMP}.db" \
    --region "${AWS_REGION:-ap-northeast-1}"
  echo "$(date): uploaded to s3://${BACKUP_S3_BUCKET}/${BACKUP_S3_PREFIX}dbward_${TIMESTAMP}.db"
fi

echo "$(date): backup complete ($(du -h "$BACKUP_FILE" | cut -f1))"
