use chrono::{DateTime, Utc};
use rusqlite::params;

use dbward_app::error::AppError;
use dbward_app::ports::RequestWriter;
use dbward_domain::entities::{Request, RequestStatus};

use super::{
    SqliteRequestRepo, database_id, insert_request_row, map_request_insert_error,
    populate_pending_approvers,
};
use crate::sqlite::error::{db_err, json_err};

impl RequestWriter for SqliteRequestRepo {
    fn insert(&self, req: &Request) -> Result<(), AppError> {
        let conn = self.conn.lock();
        let tx = conn
            .unchecked_transaction()
            .map_err(db_err("request: insert"))?;
        let db_id = database_id(&req.database, &req.environment);
        let share_with_json =
            serde_json::to_string(&req.share_with).map_err(json_err("request: insert"))?;

        let result = insert_request_row(&tx, req, &db_id, &share_with_json);
        map_request_insert_error(result, req, "request: insert")?;

        if req.status == RequestStatus::Pending {
            populate_pending_approvers(&tx, &req.id, &req.workflow_snapshot_json, 0)?;
        }
        tx.commit().map_err(db_err("request: insert"))?;
        Ok(())
    }
    fn create_and_dispatch(&self, req: &Request) -> Result<(), AppError> {
        let conn = self.conn.lock();
        let tx = conn
            .unchecked_transaction()
            .map_err(db_err("request: create_and_dispatch"))?;
        let db_id = database_id(&req.database, &req.environment);
        let share_with_json = serde_json::to_string(&req.share_with)
            .map_err(json_err("request: create_and_dispatch"))?;

        let result = insert_request_row(&tx, req, &db_id, &share_with_json);
        map_request_insert_error(result, req, "request: create_and_dispatch")?;

        tx.execute(
            "UPDATE requests SET status = 'dispatched', updated_at = ?2 WHERE id = ?1",
            params![req.id, req.updated_at.to_rfc3339()],
        )
        .map_err(db_err("request: create_and_dispatch"))?;

        tx.commit()
            .map_err(db_err("request: create_and_dispatch"))?;
        Ok(())
    }
    fn mark_approved(&self, id: &str, now: DateTime<Utc>) -> Result<bool, AppError> {
        let conn = self.conn.lock();
        let affected = conn
            .execute(
                "UPDATE requests SET status = 'approved', updated_at = ?2, resolved_at = ?2 WHERE id = ?1 AND status = 'pending' AND (expires_at IS NULL OR expires_at > ?2)",
                params![id, now.to_rfc3339()],
            )
            .map_err(db_err("request: mark_approved"))?;
        Ok(affected > 0)
    }
    fn mark_rejected(&self, id: &str, now: DateTime<Utc>) -> Result<bool, AppError> {
        let conn = self.conn.lock();
        let affected = conn
            .execute(
                "UPDATE requests SET status = 'rejected', updated_at = ?2, resolved_at = ?2 WHERE id = ?1 AND status = 'pending' AND (expires_at IS NULL OR expires_at > ?2)",
                params![id, now.to_rfc3339()],
            )
            .map_err(db_err("request: mark_rejected"))?;
        Ok(affected > 0)
    }
    fn mark_cancelled(
        &self,
        id: &str,
        actor: &str,
        reason: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<bool, AppError> {
        let conn = self.conn.lock();
        let affected = conn
            .execute(
                "UPDATE requests SET status = 'cancelled', cancelled_by = ?2, cancel_reason = ?3, updated_at = ?4, resolved_at = ?4
                 WHERE id = ?1 AND status IN ('pending', 'approved', 'auto_approved', 'break_glass', 'dispatched', 'running', 'execution_lost')",
                params![id, actor, reason, now.to_rfc3339()],
            )
            .map_err(db_err("request: mark_cancelled"))?;
        Ok(affected > 0)
    }
    fn mark_dispatched(&self, id: &str, now: DateTime<Utc>) -> Result<bool, AppError> {
        let conn = self.conn.lock();
        let affected = conn
            .execute(
                "UPDATE requests SET status = 'dispatched', updated_at = ?2 WHERE id = ?1 AND status IN ('approved', 'auto_approved', 'break_glass', 'executed', 'failed', 'execution_lost')",
                params![id, now.to_rfc3339()],
            )
            .map_err(db_err("request: mark_dispatched"))?;
        Ok(affected > 0)
    }
    fn mark_running(&self, id: &str, now: DateTime<Utc>) -> Result<bool, AppError> {
        let conn = self.conn.lock();
        let affected = conn
            .execute(
                "UPDATE requests SET status = 'running', updated_at = ?2 WHERE id = ?1 AND status = 'dispatched'",
                params![id, now.to_rfc3339()],
            )
            .map_err(db_err("request: mark_running"))?;
        Ok(affected > 0)
    }
    fn mark_executed(&self, id: &str, now: DateTime<Utc>) -> Result<bool, AppError> {
        let conn = self.conn.lock();
        let affected = conn
            .execute(
                "UPDATE requests SET status = 'executed', updated_at = ?2, resolved_at = ?2 WHERE id = ?1 AND status = 'running'",
                params![id, now.to_rfc3339()],
            )
            .map_err(db_err("request: mark_executed"))?;
        Ok(affected > 0)
    }
    fn mark_failed(&self, id: &str, now: DateTime<Utc>) -> Result<bool, AppError> {
        let conn = self.conn.lock();
        let affected = conn
            .execute(
                "UPDATE requests SET status = 'failed', updated_at = ?2, resolved_at = ?2 WHERE id = ?1 AND status = 'running'",
                params![id, now.to_rfc3339()],
            )
            .map_err(db_err("request: mark_failed"))?;
        Ok(affected > 0)
    }
    fn cancel_all_for_user(
        &self,
        user_id: &str,
        actor_id: &str,
        reason: &str,
        now: DateTime<Utc>,
        _audit_context: &dbward_domain::entities::AuditContext,
    ) -> Result<Vec<String>, AppError> {
        let mut conn = self.conn.lock();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(db_err("request: cancel_all_for_user"))?;

        let now_str = now.to_rfc3339();
        // 1. Find cancellable request IDs
        let ids: Vec<String> = {
            let mut stmt = tx.prepare(
                "SELECT id FROM requests WHERE requester = ?1 AND status IN ('pending','approved','auto_approved','break_glass','dispatched','running','execution_lost')"
            ).map_err(db_err("request: cancel_all_for_user"))?;
            stmt.query_map(params![user_id], |r| r.get(0))
                .map_err(db_err("request: cancel_all_for_user"))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(db_err("request: cancel_all_for_user"))?
        };

        if ids.is_empty() {
            return Ok(vec![]);
        }

        // 2. Batch UPDATE
        tx.execute(
            "UPDATE requests SET status = 'cancelled', cancel_reason = ?2, cancelled_by = ?3, updated_at = ?4, resolved_at = ?4 WHERE requester = ?1 AND status IN ('pending','approved','auto_approved','break_glass','dispatched','running','execution_lost')",
            params![user_id, reason, actor_id, now_str],
        ).map_err(db_err("request: cancel_all_for_user"))?;

        // 3. Individual audit events in same TX
        for id in &ids {
            let cancel_event = dbward_domain::entities::AuditEvent {
                id: String::new(),
                event_type: "request_cancelled".to_string(),
                event_category: dbward_domain::entities::EventCategory::Approval,
                event_version: 1,
                outcome: dbward_domain::entities::EventOutcome::Success,
                actor_id: actor_id.to_string(),
                actor_type: dbward_domain::entities::ActorType::User,
                resource_type: Some("request".to_string()),
                resource_id: Some(id.clone()),
                peer_ip: None,
                client_ip: None,
                client_ip_source: None,
                request_id: Some(id.clone()),
                operation: None,
                database_name: None,
                environment: None,
                detail_fingerprint: None,
                detail_raw: None,
                reason: Some(reason.to_string()),
                metadata_json: "{}".to_string(),
                prev_hash: None,
                event_hash: String::new(),
                created_at: chrono::DateTime::parse_from_rfc3339(&now_str)
                    .map(|dt| dt.with_timezone(&chrono::Utc))
                    .unwrap_or_else(|_| chrono::Utc::now()),
            };
            crate::sqlite::audit_helper::insert_audit_event_in_tx(
                &tx,
                &cancel_event,
                crate::sqlite::audit_helper::IdPolicy::AlwaysGenerate,
            )
            .map_err(db_err("request: cancel_all_for_user"))?;
        }

        tx.commit()
            .map_err(db_err("request: cancel_all_for_user"))?;
        Ok(ids)
    }
    fn mark_approved_from_dispatched(&self, id: &str, now: &str) -> Result<bool, AppError> {
        let conn = self.conn.lock();
        let n = conn.execute(
            "UPDATE requests SET status = 'approved', updated_at = ?2 WHERE id = ?1 AND status = 'dispatched'",
            params![id, now],
        ).map_err(db_err("request: mark_approved_from_dispatched"))?;
        Ok(n > 0)
    }
}
