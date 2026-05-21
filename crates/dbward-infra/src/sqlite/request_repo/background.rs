use rusqlite::params;

use dbward_app::error::AppError;
use dbward_app::ports::BackgroundTaskRepo;
use dbward_domain::entities::AuditEvent;

use super::{SqliteRequestRepo, map_err};

impl BackgroundTaskRepo for SqliteRequestRepo {
    fn find_expired_approved(&self, now: &str) -> Result<Vec<String>, AppError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id FROM requests WHERE status = 'approved' \
             AND datetime(updated_at, '+' || COALESCE(json_extract(workflow_snapshot_json, '$.approval_ttl_secs'), 86400) || ' seconds') < datetime(?1)"
        ).map_err(map_err)?;
        let rows = stmt
            .query_map(params![now], |row| row.get(0))
            .map_err(map_err)?;
        rows.collect::<Result<Vec<String>, _>>().map_err(map_err)
    }
    fn find_expired_pending(&self, now: &str) -> Result<Vec<String>, AppError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id FROM requests WHERE status = 'pending' \
             AND workflow_snapshot_json IS NOT NULL \
             AND json_extract(workflow_snapshot_json, '$.pending_ttl_secs') IS NOT NULL \
             AND datetime(created_at, '+' || json_extract(workflow_snapshot_json, '$.pending_ttl_secs') || ' seconds') < datetime(?1)"
        ).map_err(map_err)?;
        let rows = stmt
            .query_map(params![now], |row| row.get(0))
            .map_err(map_err)?;
        rows.collect::<Result<Vec<String>, _>>().map_err(map_err)
    }
    fn find_dispatched_older_than(&self, cutoff: &str) -> Result<Vec<String>, AppError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id FROM requests WHERE status = 'dispatched' AND datetime(updated_at) < datetime(?1)"
        ).map_err(map_err)?;
        let rows = stmt
            .query_map(params![cutoff], |row| row.get(0))
            .map_err(map_err)?;
        rows.collect::<Result<Vec<String>, _>>().map_err(map_err)
    }
    fn mark_expired(&self, id: &str, now: &str) -> Result<bool, AppError> {
        let conn = self.conn.lock().unwrap();
        let n = conn.execute(
            "UPDATE requests SET status = 'expired', updated_at = ?2 WHERE id = ?1 AND status IN ('approved', 'pending')",
            params![id, now],
        ).map_err(map_err)?;
        Ok(n > 0)
    }
    fn mark_expired_and_record(
        &self,
        id: &str,
        audit_event: &AuditEvent,
        now: &str,
    ) -> Result<bool, AppError> {
        use sha2::{Digest, Sha256};

        let mut conn = self.conn.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(map_err)?;

        let n = tx.execute(
            "UPDATE requests SET status = 'expired', updated_at = ?2 WHERE id = ?1 AND status IN ('approved', 'pending')",
            params![id, now],
        ).map_err(map_err)?;
        if n == 0 {
            return Ok(false);
        }

        let prev_hash: Option<String> = tx
            .query_row(
                "SELECT event_hash FROM audit_events ORDER BY rowid DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .ok();
        let audit_id = uuid::Uuid::new_v4().to_string();
        let hash_input = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            audit_id,
            audit_event.event_type,
            audit_event.actor_id,
            audit_event.created_at.to_rfc3339(),
            prev_hash.as_deref().unwrap_or(""),
            "success",
            audit_event.request_id.as_deref().unwrap_or(""),
            audit_event.operation.as_deref().unwrap_or(""),
            audit_event.database_name.as_deref().unwrap_or(""),
            audit_event.environment.as_deref().unwrap_or(""),
            audit_event.reason.as_deref().unwrap_or(""),
            audit_event.detail_raw.as_deref().unwrap_or(""),
            audit_event.metadata_json,
        );
        let event_hash = hex::encode(Sha256::digest(hash_input.as_bytes()));
        tx.execute(
            "INSERT INTO audit_events (id, event_type, event_category, event_version, outcome, actor_id, actor_type, resource_type, resource_id, peer_ip, client_ip, client_ip_source, request_id, operation, database_name, environment, detail_fingerprint, detail_raw, reason, metadata_json, prev_hash, event_hash, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23)",
            params![
                audit_id, audit_event.event_type, "approval",
                audit_event.event_version, "success",
                audit_event.actor_id, "system",
                audit_event.resource_type, audit_event.resource_id,
                audit_event.peer_ip, audit_event.client_ip, audit_event.client_ip_source,
                audit_event.request_id, audit_event.operation,
                audit_event.database_name, audit_event.environment,
                audit_event.detail_fingerprint, audit_event.detail_raw, audit_event.reason,
                audit_event.metadata_json, prev_hash, event_hash,
                audit_event.created_at.to_rfc3339(),
            ],
        ).map_err(map_err)?;

        tx.commit().map_err(map_err)?;
        Ok(true)
    }
    fn purge_old_requests(&self, before: &str) -> Result<u32, AppError> {
        let conn = self.conn.lock().unwrap();
        // Delete child tables first (FK integrity)
        conn.execute(
            "DELETE FROM dry_run_jobs WHERE request_id IN (\
             SELECT id FROM requests WHERE status IN ('executed', 'failed', 'rejected', 'expired', 'cancelled') AND updated_at < ?1)",
            params![before],
        ).map_err(map_err)?;
        conn.execute(
            "DELETE FROM request_context WHERE request_id IN (\
             SELECT id FROM requests WHERE status IN ('executed', 'failed', 'rejected', 'expired', 'cancelled') AND updated_at < ?1)",
            params![before],
        ).map_err(map_err)?;
        let n = conn.execute(
            "DELETE FROM requests WHERE status IN ('executed', 'failed', 'rejected', 'expired', 'cancelled') AND updated_at < ?1",
            params![before],
        ).map_err(map_err)?;
        Ok(n as u32)
    }
}
