use chrono::{DateTime, Utc};
use rusqlite::params;

use dbward_app::error::AppError;
use dbward_app::ports::RequestWriter;
use dbward_domain::entities::AuditEvent;
use dbward_domain::entities::{Request, RequestStatus};

use super::{SqliteRequestRepo, database_id, map_err, populate_pending_approvers};

impl RequestWriter for SqliteRequestRepo {
    fn insert(&self, req: &Request) -> Result<(), AppError> {
        let conn = self.conn.lock().unwrap();
        let db_id = database_id(&req.database, &req.environment);
        let share_with_json = serde_json::to_string(&req.share_with)
            .map_err(|e| AppError::Internal(e.to_string()))?;

        conn.execute(
            "INSERT INTO requests (id, requester, operation, database_id, detail, status, emergency, reason, idempotency_key, metadata_json, share_with_json, no_store, workflow_snapshot_json, decision_trace_json, cancelled_by, cancel_reason, created_at, updated_at, resolved_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
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
                req.decision_trace_json,
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
            "INSERT INTO requests (id, requester, operation, database_id, detail, status, emergency, reason, idempotency_key, metadata_json, share_with_json, no_store, workflow_snapshot_json, decision_trace_json, cancelled_by, cancel_reason, created_at, updated_at, resolved_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
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
                req.decision_trace_json,
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
    fn cancel_all_for_user(
        &self,
        user_id: &str,
        actor_id: &str,
        reason: &str,
        now: DateTime<Utc>,
        _audit_context: &dbward_domain::entities::AuditContext,
    ) -> Result<Vec<String>, AppError> {
        use sha2::{Digest, Sha256};

        let mut conn = self.conn.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(map_err)?;

        let now_str = now.to_rfc3339();
        // 1. Find cancellable request IDs
        let ids: Vec<String> = {
            let mut stmt = tx.prepare(
                "SELECT id FROM requests WHERE requester = ?1 AND status IN ('pending','approved','auto_approved','break_glass','dispatched','running','execution_lost')"
            ).map_err(map_err)?;
            stmt.query_map(params![user_id], |r| r.get(0))
                .map_err(map_err)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(map_err)?
        };

        if ids.is_empty() {
            return Ok(vec![]);
        }

        // 2. Batch UPDATE
        tx.execute(
            "UPDATE requests SET status = 'cancelled', cancel_reason = ?2, cancelled_by = ?3, updated_at = ?4, resolved_at = ?4 WHERE requester = ?1 AND status IN ('pending','approved','auto_approved','break_glass','dispatched','running','execution_lost')",
            params![user_id, reason, actor_id, now_str],
        ).map_err(map_err)?;

        // 3. Individual audit events in same TX
        for id in &ids {
            let outcome = "success";
            let category = "approval";
            let actor_type = "user";
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
                "request_cancelled",
                actor_id,
                now_str,
                prev_hash.as_deref().unwrap_or(""),
                outcome,
                id,
                "",
                "",
                "",
                reason,
                "",
                "{}",
            );
            let event_hash = hex::encode(Sha256::digest(hash_input.as_bytes()));
            tx.execute(
                "INSERT INTO audit_events (id, event_type, event_category, event_version, outcome, actor_id, actor_type, resource_type, resource_id, peer_ip, client_ip, client_ip_source, request_id, operation, database_name, environment, detail_fingerprint, detail_raw, reason, metadata_json, prev_hash, event_hash, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23)",
                params![
                    audit_id, "request_cancelled", category,
                    1, outcome,
                    actor_id, actor_type,
                    "request", id,
                    "", "", "",
                    id as &str, Option::<&str>::None,
                    Option::<&str>::None, Option::<&str>::None,
                    Option::<&str>::None, Option::<&str>::None, reason,
                    "{}", prev_hash, event_hash,
                    now_str,
                ],
            ).map_err(map_err)?;
        }

        tx.commit().map_err(map_err)?;
        Ok(ids)
    }
    fn mark_approved_from_dispatched(&self, id: &str, now: &str) -> Result<bool, AppError> {
        let conn = self.conn.lock().unwrap();
        let n = conn.execute(
            "UPDATE requests SET status = 'approved', updated_at = ?2 WHERE id = ?1 AND status = 'dispatched'",
            params![id, now],
        ).map_err(map_err)?;
        Ok(n > 0)
    }
    fn mark_approved_from_dispatched_and_record(
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
            "UPDATE requests SET status = 'approved', updated_at = ?2 WHERE id = ?1 AND status = 'dispatched'",
            params![id, now],
        ).map_err(map_err)?;
        if n == 0 {
            return Ok(false);
        }

        let outcome = crate::sqlite::audit_repo::outcome_str(audit_event.outcome);
        let category = crate::sqlite::audit_repo::category_str(audit_event.event_category);
        let actor_type = crate::sqlite::audit_repo::actor_type_str(audit_event.actor_type);
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
            outcome,
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
                audit_id, audit_event.event_type, category,
                audit_event.event_version, outcome,
                audit_event.actor_id, actor_type,
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
}
