use chrono::{DateTime, Utc};
use rusqlite::params;

use dbward_app::error::AppError;
use dbward_app::ports::RequestWriter;
use dbward_domain::entities::{Request, RequestStatus};

use super::{SqliteRequestRepo, database_id, map_err, populate_pending_approvers};

impl RequestWriter for SqliteRequestRepo {
    fn insert(&self, req: &Request) -> Result<(), AppError> {
        let conn = self.conn.lock().unwrap();
        let db_id = database_id(&req.database, &req.environment);
        let share_with_json = serde_json::to_string(&req.share_with)
            .map_err(|e| AppError::Internal(e.to_string()))?;

        conn.execute(
            "INSERT INTO requests (id, requester, operation, database_id, detail, status, emergency, reason, idempotency_key, metadata_json, share_with_json, no_store, workflow_snapshot_json, cancelled_by, cancel_reason, created_at, updated_at, resolved_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
            params![
                req.id,
                req.requester,
                req.operation.as_str(),
                db_id,
                req.detail,
                req.status.as_str(),
                req.emergency as i64,
                req.reason,
                req.idempotency_key,
                req.metadata_json,
                share_with_json,
                req.no_store as i64,
                req.workflow_snapshot_json,
                req.cancelled_by,
                req.cancel_reason,
                req.created_at.to_rfc3339(),
                req.updated_at.to_rfc3339(),
                req.resolved_at.map(|t| t.to_rfc3339()),
                req.expires_at.map(|t| t.to_rfc3339()),
            ],
        ).map_err(map_err)?;
        if req.status == RequestStatus::Pending {
            populate_pending_approvers(&conn, &req.id, &req.workflow_snapshot_json, 0)?;
        }
        Ok(())
    }
    fn create_and_dispatch(&self, req: &Request) -> Result<(), AppError> {
        let conn = self.conn.lock().unwrap();
        let tx = conn.unchecked_transaction().map_err(map_err)?;
        let db_id = database_id(&req.database, &req.environment);
        let share_with_json = serde_json::to_string(&req.share_with)
            .map_err(|e| AppError::Internal(e.to_string()))?;

        tx.execute(
            "INSERT INTO requests (id, requester, operation, database_id, detail, status, emergency, reason, idempotency_key, metadata_json, share_with_json, no_store, workflow_snapshot_json, cancelled_by, cancel_reason, created_at, updated_at, resolved_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
            params![
                req.id,
                req.requester,
                req.operation.as_str(),
                db_id,
                req.detail,
                req.status.as_str(),
                req.emergency as i64,
                req.reason,
                req.idempotency_key,
                req.metadata_json,
                share_with_json,
                req.no_store as i64,
                req.workflow_snapshot_json,
                req.cancelled_by,
                req.cancel_reason,
                req.created_at.to_rfc3339(),
                req.updated_at.to_rfc3339(),
                req.resolved_at.map(|t| t.to_rfc3339()),
                req.expires_at.map(|t| t.to_rfc3339()),
            ],
        ).map_err(map_err)?;

        tx.execute(
            "UPDATE requests SET status = 'dispatched', updated_at = ?2 WHERE id = ?1",
            params![req.id, req.updated_at.to_rfc3339()],
        )
        .map_err(map_err)?;

        tx.commit().map_err(map_err)?;
        Ok(())
    }
    fn mark_approved(&self, id: &str, now: DateTime<Utc>) -> Result<bool, AppError> {
        let conn = self.conn.lock().unwrap();
        let affected = conn
            .execute(
                "UPDATE requests SET status = 'approved', updated_at = ?2, resolved_at = ?2 WHERE id = ?1 AND status = 'pending' AND (expires_at IS NULL OR expires_at > ?2)",
                params![id, now.to_rfc3339()],
            )
            .map_err(map_err)?;
        Ok(affected > 0)
    }
    fn mark_rejected(&self, id: &str, now: DateTime<Utc>) -> Result<bool, AppError> {
        let conn = self.conn.lock().unwrap();
        let affected = conn
            .execute(
                "UPDATE requests SET status = 'rejected', updated_at = ?2, resolved_at = ?2 WHERE id = ?1 AND status = 'pending' AND (expires_at IS NULL OR expires_at > ?2)",
                params![id, now.to_rfc3339()],
            )
            .map_err(map_err)?;
        Ok(affected > 0)
    }
    fn mark_cancelled(
        &self,
        id: &str,
        actor: &str,
        reason: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<bool, AppError> {
        let conn = self.conn.lock().unwrap();
        let affected = conn
            .execute(
                "UPDATE requests SET status = 'cancelled', cancelled_by = ?2, cancel_reason = ?3, updated_at = ?4, resolved_at = ?4
                 WHERE id = ?1 AND status IN ('pending', 'approved', 'auto_approved', 'break_glass', 'dispatched', 'running', 'execution_lost')",
                params![id, actor, reason, now.to_rfc3339()],
            )
            .map_err(map_err)?;
        Ok(affected > 0)
    }
    fn mark_dispatched(&self, id: &str, now: DateTime<Utc>) -> Result<bool, AppError> {
        let conn = self.conn.lock().unwrap();
        let affected = conn
            .execute(
                "UPDATE requests SET status = 'dispatched', updated_at = ?2 WHERE id = ?1 AND status IN ('approved', 'auto_approved', 'break_glass', 'executed', 'failed', 'execution_lost')",
                params![id, now.to_rfc3339()],
            )
            .map_err(map_err)?;
        Ok(affected > 0)
    }
    fn mark_running(&self, id: &str, now: DateTime<Utc>) -> Result<bool, AppError> {
        let conn = self.conn.lock().unwrap();
        let affected = conn
            .execute(
                "UPDATE requests SET status = 'running', updated_at = ?2 WHERE id = ?1 AND status = 'dispatched'",
                params![id, now.to_rfc3339()],
            )
            .map_err(map_err)?;
        Ok(affected > 0)
    }
    fn mark_executed(&self, id: &str, now: DateTime<Utc>) -> Result<bool, AppError> {
        let conn = self.conn.lock().unwrap();
        let affected = conn
            .execute(
                "UPDATE requests SET status = 'executed', updated_at = ?2, resolved_at = ?2 WHERE id = ?1 AND status = 'running'",
                params![id, now.to_rfc3339()],
            )
            .map_err(map_err)?;
        Ok(affected > 0)
    }
    fn mark_failed(&self, id: &str, now: DateTime<Utc>) -> Result<bool, AppError> {
        let conn = self.conn.lock().unwrap();
        let affected = conn
            .execute(
                "UPDATE requests SET status = 'failed', updated_at = ?2, resolved_at = ?2 WHERE id = ?1 AND status = 'running'",
                params![id, now.to_rfc3339()],
            )
            .map_err(map_err)?;
        Ok(affected > 0)
    }
    fn cancel_all_for_user(&self, user_id: &str, now: DateTime<Utc>) -> Result<u32, AppError> {
        let conn = self.conn.lock().unwrap();
        let affected = conn
            .execute(
                "UPDATE requests SET status = 'cancelled', updated_at = ?2, resolved_at = ?2
                 WHERE requester = ?1 AND status IN ('pending', 'approved', 'auto_approved', 'break_glass', 'dispatched', 'running', 'execution_lost')",
                params![user_id, now.to_rfc3339()],
            )
            .map_err(map_err)?;
        Ok(affected as u32)
    }
    fn mark_approved_from_dispatched(&self, id: &str, now: &str) -> Result<bool, AppError> {
        let conn = self.conn.lock().unwrap();
        let n = conn.execute(
            "UPDATE requests SET status = 'approved', updated_at = ?2 WHERE id = ?1 AND status = 'dispatched'",
            params![id, now],
        ).map_err(map_err)?;
        Ok(n > 0)
    }
}
