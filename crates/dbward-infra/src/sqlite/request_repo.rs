use chrono::{DateTime, Utc};
use rusqlite::params;

use dbward_app::error::AppError;
use dbward_app::ports::RequestRepo;
use dbward_domain::entities::{Approval, ApprovalAction, AuditEvent, Request, RequestStatus};
use dbward_domain::values::{DatabaseName, Environment, Operation};

use crate::sqlite::DbConn;


pub struct SqliteRequestRepo {
    conn: DbConn,
}

impl SqliteRequestRepo {
    pub fn new(conn: DbConn) -> Self {
        Self { conn }
    }
}

fn map_err(e: rusqlite::Error) -> AppError {
    AppError::Internal(e.to_string())
}

fn database_id(db: &DatabaseName, env: &Environment) -> String {
    format!("{}:{}", db.as_str(), env.as_str())
}

fn parse_database_id(id: &str) -> Result<(DatabaseName, Environment), AppError> {
    let (name, env) = id
        .split_once(':')
        .ok_or_else(|| AppError::Internal(format!("invalid database_id: {id}")))?;
    let db = DatabaseName::new(name)
        .map_err(|e| AppError::Internal(format!("invalid database name: {e}")))?;
    let env = Environment::new(env)
        .map_err(|e| AppError::Internal(format!("invalid environment: {e}")))?;
    Ok((db, env))
}

fn parse_status(s: &str) -> Result<RequestStatus, AppError> {
    match s {
        "pending" => Ok(RequestStatus::Pending),
        "approved" => Ok(RequestStatus::Approved),
        "auto_approved" => Ok(RequestStatus::AutoApproved),
        "break_glass" => Ok(RequestStatus::BreakGlass),
        "dispatched" => Ok(RequestStatus::Dispatched),
        "running" => Ok(RequestStatus::Running),
        "executed" => Ok(RequestStatus::Executed),
        "failed" => Ok(RequestStatus::Failed),
        "rejected" => Ok(RequestStatus::Rejected),
        "cancelled" => Ok(RequestStatus::Cancelled),
        "expired" => Ok(RequestStatus::Expired),
        "execution_lost" => Ok(RequestStatus::ExecutionLost),
        _ => Err(AppError::Internal(format!("unknown status: {s}"))),
    }
}

fn parse_approval_action(s: &str) -> Result<ApprovalAction, AppError> {
    match s {
        "approve" => Ok(ApprovalAction::Approve),
        "reject" => Ok(ApprovalAction::Reject),
        _ => Err(AppError::Internal(format!("unknown approval action: {s}"))),
    }
}

fn approval_action_str(a: &ApprovalAction) -> &'static str {
    match a {
        ApprovalAction::Approve => "approve",
        ApprovalAction::Reject => "reject",
    }
}

fn parse_ts(s: &str) -> Result<DateTime<Utc>, AppError> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| AppError::Internal(format!("invalid timestamp '{s}': {e}")))
}

fn parse_optional_ts(s: Option<String>) -> Result<Option<DateTime<Utc>>, AppError> {
    s.map(|v| parse_ts(&v)).transpose()
}

fn row_to_request(row: &rusqlite::Row<'_>) -> Result<Request, rusqlite::Error> {
    let db_id: String = row.get("database_id")?;
    let (database, environment) = parse_database_id(&db_id)
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e)))?;

    let op_str: String = row.get("operation")?;
    let operation: Operation = op_str
        .parse()
        .map_err(|e: &str| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(AppError::Internal(e.to_string()))))?;

    let status_str: String = row.get("status")?;
    let status = parse_status(&status_str)
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e)))?;

    let share_with_json: String = row.get("share_with_json")?;
    let share_with: Vec<String> = serde_json::from_str(&share_with_json).unwrap_or_default();

    let created_at_str: String = row.get("created_at")?;
    let updated_at_str: String = row.get("updated_at")?;
    let resolved_at_str: Option<String> = row.get("resolved_at")?;
    let expires_at_str: Option<String> = row.get("expires_at")?;

    let created_at = parse_ts(&created_at_str)
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e)))?;
    let updated_at = parse_ts(&updated_at_str)
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e)))?;
    let resolved_at = parse_optional_ts(resolved_at_str)
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e)))?;
    let expires_at = parse_optional_ts(expires_at_str)
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e)))?;

    Ok(Request {
        id: row.get("id")?,
        requester: row.get("requester")?,
        database,
        environment,
        operation,
        detail: row.get("detail")?,
        status,
        emergency: row.get::<_, i64>("emergency")? != 0,
        reason: row.get("reason")?,
        idempotency_key: row.get("idempotency_key")?,
        metadata_json: row.get("metadata_json")?,
        share_with,
        no_store: row.get::<_, i64>("no_store")? != 0,
        workflow_snapshot_json: row.get("workflow_snapshot_json")?,
        cancel_reason: row.get("cancel_reason")?,
        cancelled_by: row.get("cancelled_by")?,
        created_at,
        updated_at,
        resolved_at,
        expires_at,
    })
}

impl RequestRepo for SqliteRequestRepo {
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
        Ok(())
    }

    fn get(&self, id: &str) -> Result<Option<Request>, AppError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT * FROM requests WHERE id = ?1")
            .map_err(map_err)?;
        let mut rows = stmt.query_and_then(params![id], row_to_request).map_err(map_err)?;
        match rows.next() {
            Some(r) => Ok(Some(r.map_err(map_err)?)),
            None => Ok(None),
        }
    }

    fn list(&self, limit: u32, offset: u32, status: Option<&str>) -> Result<(Vec<Request>, u32), AppError> {
        let conn = self.conn.lock().unwrap();
        let (count_sql, query_sql) = if let Some(s) = status {
            let total: u32 = conn
                .query_row("SELECT COUNT(*) FROM requests WHERE status = ?1", params![s], |r| r.get(0))
                .map_err(map_err)?;
            let mut stmt = conn
                .prepare("SELECT * FROM requests WHERE status = ?1 ORDER BY created_at DESC LIMIT ?2 OFFSET ?3")
                .map_err(map_err)?;
            let rows = stmt.query_and_then(params![s, limit, offset], row_to_request).map_err(map_err)?;
            let items = rows.collect::<Result<Vec<_>, _>>().map_err(map_err)?;
            return Ok((items, total));
        } else {
            ("SELECT COUNT(*) FROM requests", "SELECT * FROM requests ORDER BY created_at DESC LIMIT ?1 OFFSET ?2")
        };
        let total: u32 = conn
            .query_row(count_sql, [], |r| r.get(0))
            .map_err(map_err)?;
        let mut stmt = conn
            .prepare(query_sql)
            .map_err(map_err)?;
        let rows = stmt.query_and_then(params![limit, offset], row_to_request).map_err(map_err)?;
        let items = rows.collect::<Result<Vec<_>, _>>().map_err(map_err)?;
        Ok((items, total))
    }

    fn find_by_idempotency_key(&self, key: &str) -> Result<Option<Request>, AppError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT * FROM requests WHERE idempotency_key = ?1")
            .map_err(map_err)?;
        let mut rows = stmt.query_and_then(params![key], row_to_request).map_err(map_err)?;
        match rows.next() {
            Some(r) => Ok(Some(r.map_err(map_err)?)),
            None => Ok(None),
        }
    }

    fn insert_approval(&self, approval: &Approval) -> Result<(), AppError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO approvals (id, request_id, action, actor_id, matched_selector, step_index, comment, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                approval.id,
                approval.request_id,
                approval_action_str(&approval.action),
                approval.actor_id,
                approval.matched_selector,
                approval.step_index,
                approval.comment,
                approval.created_at.to_rfc3339(),
            ],
        ).map_err(map_err)?;
        Ok(())
    }

    fn get_approvals(&self, request_id: &str) -> Result<Vec<Approval>, AppError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT * FROM approvals WHERE request_id = ?1 ORDER BY created_at ASC")
            .map_err(map_err)?;
        let rows = stmt
            .query_map(params![request_id], |row| {
                let action_str: String = row.get("action")?;
                let action = parse_approval_action(&action_str).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
                })?;
                let created_at_str: String = row.get("created_at")?;
                let created_at = parse_ts(&created_at_str).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
                })?;
                Ok(Approval {
                    id: row.get("id")?,
                    request_id: row.get("request_id")?,
                    action,
                    actor_id: row.get("actor_id")?,
                    matched_selector: row.get("matched_selector")?,
                    step_index: row.get("step_index")?,
                    comment: row.get("comment")?,
                    created_at,
                })
            })
            .map_err(map_err)?;

        rows.collect::<Result<Vec<_>, _>>().map_err(map_err)
    }

    fn count_executions(&self, request_id: &str) -> Result<u32, AppError> {
        let conn = self.conn.lock().unwrap();
        let count: u32 = conn
            .query_row(
                "SELECT COUNT(*) FROM executions WHERE request_id = ?1",
                params![request_id],
                |row| row.get(0),
            )
            .map_err(map_err)?;
        Ok(count)
    }

    fn mark_approved(&self, id: &str, now: DateTime<Utc>) -> Result<bool, AppError> {
        let conn = self.conn.lock().unwrap();
        let affected = conn
            .execute(
                "UPDATE requests SET status = 'approved', updated_at = ?2, resolved_at = ?2 WHERE id = ?1 AND status = 'pending'",
                params![id, now.to_rfc3339()],
            )
            .map_err(map_err)?;
        Ok(affected > 0)
    }

    fn approve_and_mark_approved(&self, approval: &Approval, request_id: &str, now: DateTime<Utc>) -> Result<bool, AppError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate).map_err(map_err)?;

        tx.execute(
            "INSERT INTO approvals (id, request_id, action, actor_id, matched_selector, step_index, comment, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                approval.id,
                approval.request_id,
                approval_action_str(&approval.action),
                approval.actor_id,
                approval.matched_selector,
                approval.step_index,
                approval.comment,
                approval.created_at.to_rfc3339(),
            ],
        ).map_err(map_err)?;

        let now_str = now.to_rfc3339();
        let affected = tx.execute(
            "UPDATE requests SET status = 'approved', updated_at = ?2, resolved_at = ?2 WHERE id = ?1 AND status = 'pending'",
            params![request_id, now_str],
        ).map_err(map_err)?;

        if affected == 0 {
            drop(tx);
            return Ok(false);
        }

        tx.commit().map_err(map_err)?;
        Ok(true)
    }

    fn mark_rejected(&self, id: &str, now: DateTime<Utc>) -> Result<bool, AppError> {
        let conn = self.conn.lock().unwrap();
        let affected = conn
            .execute(
                "UPDATE requests SET status = 'rejected', updated_at = ?2, resolved_at = ?2 WHERE id = ?1 AND status = 'pending'",
                params![id, now.to_rfc3339()],
            )
            .map_err(map_err)?;
        Ok(affected > 0)
    }

    fn reject_and_record(&self, request_id: &str, approval: &Approval, now: DateTime<Utc>) -> Result<bool, AppError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate).map_err(map_err)?;

        let now_str = now.to_rfc3339();
        let affected = tx.execute(
            "UPDATE requests SET status = 'rejected', updated_at = ?2, resolved_at = ?2 WHERE id = ?1 AND status = 'pending'",
            params![request_id, now_str],
        ).map_err(map_err)?;

        if affected == 0 {
            drop(tx);
            return Ok(false);
        }

        tx.execute(
            "INSERT INTO approvals (id, request_id, action, actor_id, matched_selector, step_index, comment, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                approval.id,
                approval.request_id,
                approval_action_str(&approval.action),
                approval.actor_id,
                approval.matched_selector,
                approval.step_index,
                approval.comment,
                approval.created_at.to_rfc3339(),
            ],
        ).map_err(map_err)?;

        tx.commit().map_err(map_err)?;
        Ok(true)
    }

    fn mark_cancelled(&self, id: &str, actor: &str, reason: Option<&str>, now: DateTime<Utc>) -> Result<bool, AppError> {
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
        ).map_err(map_err)?;

        tx.commit().map_err(map_err)?;
        Ok(())
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

    fn find_expired_approved(&self, now: &str) -> Result<Vec<String>, AppError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id FROM requests WHERE status = 'approved' \
             AND datetime(updated_at, '+' || COALESCE(json_extract(workflow_snapshot_json, '$.approval_ttl_secs'), 86400) || ' seconds') < datetime(?1)"
        ).map_err(map_err)?;
        let rows = stmt.query_map(params![now], |row| row.get(0)).map_err(map_err)?;
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
        let rows = stmt.query_map(params![now], |row| row.get(0)).map_err(map_err)?;
        rows.collect::<Result<Vec<String>, _>>().map_err(map_err)
    }

    fn find_dispatched_older_than(&self, cutoff: &str) -> Result<Vec<String>, AppError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id FROM requests WHERE status = 'dispatched' AND datetime(updated_at) < datetime(?1)"
        ).map_err(map_err)?;
        let rows = stmt.query_map(params![cutoff], |row| row.get(0)).map_err(map_err)?;
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

    fn mark_expired_and_record(&self, id: &str, audit_event: &AuditEvent, now: &str) -> Result<bool, AppError> {
        use sha2::{Digest, Sha256};

        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate).map_err(map_err)?;

        let n = tx.execute(
            "UPDATE requests SET status = 'expired', updated_at = ?2 WHERE id = ?1 AND status IN ('approved', 'pending')",
            params![id, now],
        ).map_err(map_err)?;
        if n == 0 {
            return Ok(false);
        }

        // Inline audit INSERT with hash chain
        let prev_hash: Option<String> = tx.query_row(
            "SELECT event_hash FROM audit_events ORDER BY rowid DESC LIMIT 1",
            [],
            |row| row.get(0),
        ).ok();
        let audit_id = uuid::Uuid::new_v4().to_string();
        let hash_input = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            audit_id, audit_event.event_type, audit_event.actor_id,
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

    fn mark_approved_from_dispatched(&self, id: &str, now: &str) -> Result<bool, AppError> {
        let conn = self.conn.lock().unwrap();
        let n = conn.execute(
            "UPDATE requests SET status = 'approved', updated_at = ?2 WHERE id = ?1 AND status = 'dispatched'",
            params![id, now],
        ).map_err(map_err)?;
        Ok(n > 0)
    }

    fn purge_old_requests(&self, before: &str) -> Result<u32, AppError> {
        let conn = self.conn.lock().unwrap();
        let n = conn.execute(
            "DELETE FROM requests WHERE status IN ('executed', 'failed', 'expired', 'cancelled') AND updated_at < ?1",
            params![before],
        ).map_err(map_err)?;
        Ok(n as u32)
    }

    fn count_by_status(&self, status: &str) -> Result<u32, AppError> {
        let conn = self.conn.lock().unwrap();
        let count: u32 = conn.query_row(
            "SELECT COUNT(*) FROM requests WHERE status = ?1",
            params![status],
            |row| row.get(0),
        ).map_err(map_err)?;
        Ok(count)
    }

    fn wal_checkpoint(&self) -> Result<(), AppError> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)").map_err(map_err)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite::open_memory;

    fn make_request() -> Request {
        Request {
            id: "req-1".to_string(),
            requester: "user-1".to_string(),
            database: DatabaseName::new("app").unwrap(),
            environment: Environment::new("production").unwrap(),
            operation: Operation::ExecuteDml,
            detail: "UPDATE users SET active = true".to_string(),
            status: RequestStatus::Pending,
            emergency: false,
            reason: Some("deploy fix".to_string()),
            idempotency_key: Some("idem-1".to_string()),
            metadata_json: "{}".to_string(),
            share_with: vec!["user-2".to_string()],
            no_store: false,
            workflow_snapshot_json: None,
            cancel_reason: None,
            cancelled_by: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            resolved_at: None,
            expires_at: None,
        }
    }

    fn setup() -> SqliteRequestRepo {
        let conn = open_memory().unwrap();
        // Insert the database record (FK constraint)
        {
            let c = conn.lock().unwrap();
            c.execute(
                "INSERT INTO databases (id, name, environment, created_at) VALUES ('app:production', 'app', 'production', '2024-01-01T00:00:00Z')",
                [],
            ).unwrap();
        }
        SqliteRequestRepo::new(conn)
    }

    #[test]
    fn insert_and_get() {
        let repo = setup();
        let req = make_request();
        repo.insert(&req).unwrap();

        let fetched = repo.get("req-1").unwrap().unwrap();
        assert_eq!(fetched.id, "req-1");
        assert_eq!(fetched.database.as_str(), "app");
        assert_eq!(fetched.environment.as_str(), "production");
        assert_eq!(fetched.operation, Operation::ExecuteDml);
        assert_eq!(fetched.share_with, vec!["user-2"]);
    }

    #[test]
    fn find_by_idempotency_key() {
        let repo = setup();
        let req = make_request();
        repo.insert(&req).unwrap();

        let found = repo.find_by_idempotency_key("idem-1").unwrap().unwrap();
        assert_eq!(found.id, "req-1");
        assert!(repo.find_by_idempotency_key("nonexistent").unwrap().is_none());
    }

    #[test]
    fn approvals() {
        let repo = setup();
        repo.insert(&make_request()).unwrap();

        let approval = Approval {
            id: "apr-1".to_string(),
            request_id: "req-1".to_string(),
            action: ApprovalAction::Approve,
            actor_id: "admin-1".to_string(),
            matched_selector: "role:admin".to_string(),
            step_index: 0,
            comment: Some("lgtm".to_string()),
            created_at: Utc::now(),
        };
        repo.insert_approval(&approval).unwrap();

        let approvals = repo.get_approvals("req-1").unwrap();
        assert_eq!(approvals.len(), 1);
        assert_eq!(approvals[0].actor_id, "admin-1");
    }

    #[test]
    fn mark_approved_and_dispatched() {
        let repo = setup();
        repo.insert(&make_request()).unwrap();

        let now = Utc::now();
        assert!(repo.mark_approved("req-1", now).unwrap());
        // Cannot approve again
        assert!(!repo.mark_approved("req-1", now).unwrap());

        assert!(repo.mark_dispatched("req-1", now).unwrap());
        assert!(repo.mark_running("req-1", now).unwrap());
        assert!(repo.mark_executed("req-1", now).unwrap());
    }

    #[test]
    fn mark_cancelled() {
        let repo = setup();
        repo.insert(&make_request()).unwrap();

        let now = Utc::now();
        assert!(repo.mark_cancelled("req-1", "admin", Some("oops"), now).unwrap());

        let req = repo.get("req-1").unwrap().unwrap();
        assert_eq!(req.status, RequestStatus::Cancelled);
        assert_eq!(req.cancelled_by.as_deref(), Some("admin"));
        assert_eq!(req.cancel_reason.as_deref(), Some("oops"));
    }

    #[test]
    fn cancel_all_for_user() {
        let repo = setup();
        let mut req = make_request();
        repo.insert(&req).unwrap();

        req.id = "req-2".to_string();
        req.idempotency_key = Some("idem-2".to_string());
        repo.insert(&req).unwrap();

        let count = repo.cancel_all_for_user("user-1", Utc::now()).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn list_filters_by_status() {
        let repo = setup();
        let mut req = make_request();
        req.id = "req-pending".into();
        req.status = RequestStatus::Pending;
        req.idempotency_key = Some("idem-1".into());
        repo.insert(&req).unwrap();

        let mut req2 = make_request();
        req2.id = "req-dispatched".into();
        req2.status = RequestStatus::Dispatched;
        req2.idempotency_key = Some("idem-2".into());
        repo.insert(&req2).unwrap();

        let (all, _) = repo.list(10, 0, None).unwrap();
        assert_eq!(all.len(), 2);

        let (pending, _) = repo.list(10, 0, Some("pending")).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, "req-pending");

        let (dispatched, _) = repo.list(10, 0, Some("dispatched")).unwrap();
        assert_eq!(dispatched.len(), 1);
        assert_eq!(dispatched[0].id, "req-dispatched");
    }
}
