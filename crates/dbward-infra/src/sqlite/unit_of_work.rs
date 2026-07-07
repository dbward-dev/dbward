use std::any::Any;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, params};

use dbward_app::error::AppError;
use dbward_app::ports::transaction::{
    ApprovalReaderOps, ApprovalWriterOps, AuditWriterOps, ExecutionWriterOps, RequestWriterOps,
    TokenWriterOps, TxScope, UnitOfWork, UserWriterOps,
};
use dbward_domain::entities::{Approval, AuditEvent, Execution, Request, RequestStatus, Token};

use super::DbConn;
use super::audit_helper::insert_audit_event_raw;
use super::error::db_err;
use super::request_repo::{
    approval_action_str, database_id, parse_approval_action, parse_status, parse_ts,
};

/// SQLite Unit of Work. Holds `DbConn` and acquires exclusive lock for entire closure.
pub struct SqliteUnitOfWork {
    conn: DbConn,
    signer: Option<Arc<dyn dbward_app::ports::crypto::AuditSigner>>,
    checkpoint_interval: u64,
}

impl SqliteUnitOfWork {
    pub fn new(conn: DbConn) -> Self {
        Self {
            conn,
            signer: None,
            checkpoint_interval: 100,
        }
    }

    pub fn with_signer(
        conn: DbConn,
        signer: Arc<dyn dbward_app::ports::crypto::AuditSigner>,
        checkpoint_interval: u64,
    ) -> Self {
        Self {
            conn,
            signer: Some(signer),
            checkpoint_interval,
        }
    }
}

impl SqliteUnitOfWork {
    fn run_in_tx<T>(
        &self,
        f: impl FnOnce(&SqliteTxScope<'_>) -> Result<T, AppError>,
    ) -> Result<T, AppError> {
        let guard = self.conn.lock();
        guard
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|e| AppError::Internal(format!("begin: {e}")))?;

        let scope = SqliteTxScope {
            conn: &guard,
            signer: self.signer.as_deref(),
            checkpoint_interval: self.checkpoint_interval,
        };
        let result = f(&scope);

        match result {
            Ok(val) => match guard.execute_batch("COMMIT") {
                Ok(()) => Ok(val),
                Err(commit_err) => {
                    if guard.execute_batch("ROLLBACK").is_err() {
                        tracing::error!("FATAL: both COMMIT and ROLLBACK failed on UoW");
                        return Err(AppError::Internal(
                            "commit and rollback both failed; connection may be poisoned".into(),
                        ));
                    }
                    Err(AppError::Internal(format!("commit: {commit_err}")))
                }
            },
            Err(e) => {
                if let Err(rb_err) = guard.execute_batch("ROLLBACK") {
                    tracing::error!(error = %rb_err, "rollback failed after closure error");
                }
                Err(e)
            }
        }
    }
}

impl UnitOfWork for SqliteUnitOfWork {
    fn execute(
        &self,
        f: Box<dyn FnOnce(&dyn TxScope) -> Result<(), AppError> + '_>,
    ) -> Result<(), AppError> {
        self.run_in_tx(|scope| f(scope))
    }

    fn execute_with_result(
        &self,
        f: Box<dyn FnOnce(&dyn TxScope) -> Result<Box<dyn Any>, AppError> + '_>,
    ) -> Result<Box<dyn Any>, AppError> {
        self.run_in_tx(|scope| f(scope))
    }

    fn execute_sync(
        &self,
        f: Box<
            dyn FnOnce(
                    &dyn dbward_app::ports::sync_scope::SyncScope,
                ) -> Result<Box<dyn Any>, AppError>
                + '_,
        >,
    ) -> Result<Box<dyn Any>, AppError> {
        self.run_in_tx(|scope| f(scope))
    }
}

/// Transaction scope: provides writer operations on a borrowed connection.
pub(crate) struct SqliteTxScope<'a> {
    pub(crate) conn: &'a Connection,
    pub(crate) signer: Option<&'a dyn dbward_app::ports::crypto::AuditSigner>,
    pub(crate) checkpoint_interval: u64,
}

impl RequestWriterOps for SqliteTxScope<'_> {
    fn insert_request(&self, req: &Request) -> Result<(), AppError> {
        let db_id = database_id(&req.database, &req.environment);
        let share_with_json = serde_json::to_string(&req.share_with)
            .map_err(|e| AppError::Internal(format!("json: {e}")))?;

        self.conn
            .execute(
                "INSERT INTO requests (id, requester, operation, database_id, detail, status, emergency, reason, idempotency_key, metadata_json, share_with_json, no_store, workflow_snapshot_json, decision_trace_json, execution_plan_json, cancelled_by, cancel_reason, created_at, updated_at, resolved_at, expires_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21)",
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
                    req.no_result_store as i64,
                    req.workflow_snapshot_json,
                    req.decision_trace_json,
                    req.execution_plan_json,
                    req.cancelled_by,
                    req.cancel_reason,
                    req.created_at.to_rfc3339(),
                    req.updated_at.to_rfc3339(),
                    req.resolved_at.map(|t| t.to_rfc3339()),
                    req.expires_at.map(|t| t.to_rfc3339()),
                ],
            )
            .map_err(db_err("tx: insert_request"))?;

        // Populate pending_approvers for view-permission resolution
        if req.status == RequestStatus::Pending {
            super::request_repo::populate_pending_approvers(
                self.conn,
                &req.id,
                &req.workflow_snapshot_json,
                0,
            )?;
        }
        Ok(())
    }

    fn mark_dispatched(&self, id: &str, now: DateTime<Utc>) -> Result<bool, AppError> {
        self.update_status_guarded(
            id,
            RequestStatus::Dispatched,
            &[
                "approved",
                "auto_approved",
                "break_glass",
                "executed",
                "failed",
                "execution_lost",
            ],
            now,
        )
    }

    fn mark_approved(&self, id: &str, now: DateTime<Utc>) -> Result<bool, AppError> {
        // Phase 2c: Atomic expiry check — reject if request has expired even if background
        // job hasn't updated status yet. Uses dedicated SQL instead of update_status_guarded
        // because other status transitions don't need the expires_at predicate.
        let now_str = now.to_rfc3339();
        let n = self
            .conn
            .execute(
                "UPDATE requests SET status = 'approved', updated_at = ?2, resolved_at = ?2 \
                 WHERE id = ?1 AND status = 'pending' \
                 AND (expires_at IS NULL OR expires_at > ?2)",
                rusqlite::params![id, now_str],
            )
            .map_err(db_err("tx: mark_approved"))?;
        Ok(n > 0)
    }

    fn mark_rejected(&self, id: &str, now: DateTime<Utc>) -> Result<bool, AppError> {
        let now_str = now.to_rfc3339();
        let n = self
            .conn
            .execute(
                "UPDATE requests SET status = 'rejected', updated_at = ?2, resolved_at = ?2 \
                 WHERE id = ?1 AND status = 'pending' \
                 AND (expires_at IS NULL OR expires_at > ?2)",
                params![id, now_str],
            )
            .map_err(db_err("tx: mark_rejected"))?;
        Ok(n > 0)
    }

    fn mark_running(&self, id: &str, now: DateTime<Utc>) -> Result<bool, AppError> {
        self.update_status_guarded(id, RequestStatus::Running, &["dispatched"], now)
    }

    fn mark_cancelled(
        &self,
        id: &str,
        cancelled_by: &str,
        reason: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<bool, AppError> {
        let n = self
            .conn
            .execute(
                "UPDATE requests SET status = ?1, cancelled_by = ?2, cancel_reason = ?3, updated_at = ?4, resolved_at = ?5 WHERE id = ?6 AND status IN ('pending', 'approved', 'dispatched', 'running', 'auto_approved', 'break_glass', 'execution_lost')",
                params![
                    RequestStatus::Cancelled.as_str(),
                    cancelled_by,
                    reason,
                    now.to_rfc3339(),
                    now.to_rfc3339(),
                    id,
                ],
            )
            .map_err(db_err("tx: mark_cancelled"))?;
        Ok(n > 0)
    }

    fn mark_executed(&self, id: &str, success: bool, now: DateTime<Utc>) -> Result<bool, AppError> {
        let status = if success {
            RequestStatus::Executed
        } else {
            RequestStatus::Failed
        };
        let n = self
            .conn
            .execute(
                "UPDATE requests SET status = ?1, updated_at = ?2, resolved_at = ?3 WHERE id = ?4 AND status IN ('running', 'execution_lost')",
                params![status.as_str(), now.to_rfc3339(), now.to_rfc3339(), id],
            )
            .map_err(db_err("tx: mark_executed"))?;
        Ok(n > 0)
    }

    fn mark_expired(&self, id: &str, now: DateTime<Utc>) -> Result<bool, AppError> {
        let n = self
            .conn
            .execute(
                "UPDATE requests SET status = ?1, updated_at = ?2, resolved_at = ?3 WHERE id = ?4 AND status IN ('pending', 'approved')",
                params![
                    RequestStatus::Expired.as_str(),
                    now.to_rfc3339(),
                    now.to_rfc3339(),
                    id
                ],
            )
            .map_err(db_err("tx: mark_expired"))?;
        Ok(n > 0)
    }

    fn mark_execution_lost(&self, id: &str, now: DateTime<Utc>) -> Result<bool, AppError> {
        let n = self
            .conn
            .execute(
                "UPDATE requests SET status = 'execution_lost', updated_at = ?1 WHERE id = ?2 AND status IN ('running')",
                params![now.to_rfc3339(), id],
            )
            .map_err(db_err("tx: mark_execution_lost"))?;
        Ok(n > 0)
    }

    fn mark_approved_from_dispatched(
        &self,
        id: &str,
        now: DateTime<Utc>,
    ) -> Result<bool, AppError> {
        let n = self
            .conn
            .execute(
                "UPDATE requests SET status = 'approved', updated_at = ?1 WHERE id = ?2 AND status = 'dispatched'",
                params![now.to_rfc3339(), id],
            )
            .map_err(db_err("tx: mark_approved_from_dispatched"))?;
        Ok(n > 0)
    }

    fn cancel_all_for_user(
        &self,
        user_id: &str,
        cancelled_by: &str,
        reason: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<Vec<String>, AppError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id FROM requests WHERE requester = ?1 AND status IN ('pending', 'dispatched', 'approved')",
            )
            .map_err(db_err("tx: cancel_all_for_user select"))?;
        let ids: Vec<String> = stmt
            .query_map(params![user_id], |row| row.get(0))
            .map_err(db_err("tx: cancel_all_for_user query"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err("tx: cancel_all_for_user collect"))?;

        for id in &ids {
            self.conn
                .execute(
                    "UPDATE requests SET status = ?1, cancelled_by = ?2, cancel_reason = ?3, updated_at = ?4, resolved_at = ?5 WHERE id = ?6 AND status IN ('pending', 'approved', 'dispatched')",
                    params![
                        RequestStatus::Cancelled.as_str(),
                        cancelled_by,
                        reason,
                        now.to_rfc3339(),
                        now.to_rfc3339(),
                        id,
                    ],
                )
                .map_err(db_err("tx: cancel_all_for_user update"))?;
        }
        Ok(ids)
    }
}

impl ApprovalWriterOps for SqliteTxScope<'_> {
    fn insert_approval(&self, approval: &Approval) -> Result<(), AppError> {
        self.conn
            .execute(
                "INSERT INTO approvals (id, request_id, actor_id, action, matched_selector, step_index, comment, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    approval.id,
                    approval.request_id,
                    approval.actor_id,
                    approval_action_str(&approval.action),
                    approval.matched_selector,
                    approval.step_index,
                    approval.comment,
                    approval.created_at.to_rfc3339(),
                ],
            )
            .map_err(db_err("tx: insert_approval"))?;

        // Re-populate pending_approvers for the new current step
        let snapshot: Option<String> = self
            .conn
            .query_row(
                "SELECT workflow_snapshot_json FROM requests WHERE id = ?1",
                params![approval.request_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(db_err("tx: get workflow_snapshot"))?
            .flatten();
        let all_approvals = self.get_approvals(&approval.request_id)?;
        let current_step = match snapshot.as_deref() {
            Some(json) => {
                let wf: dbward_domain::policies::Workflow = serde_json::from_str(json)
                    .map_err(|e| AppError::Internal(format!("corrupt workflow_snapshot: {e}")))?;
                dbward_domain::services::workflow_matcher::find_current_step(
                    &wf.steps,
                    &all_approvals,
                )
            }
            None => 0,
        };
        super::request_repo::populate_pending_approvers(
            self.conn,
            &approval.request_id,
            &snapshot,
            current_step,
        )?;
        Ok(())
    }
}

impl ApprovalReaderOps for SqliteTxScope<'_> {
    fn get_approvals(&self, request_id: &str) -> Result<Vec<Approval>, AppError> {
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT id, request_id, actor_id, action, matched_selector, step_index, comment, created_at \
                 FROM approvals WHERE request_id = ?1 ORDER BY created_at",
            )
            .map_err(db_err("tx: get_approvals"))?;
        let rows = stmt
            .query_map(params![request_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, u32>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, String>(7)?,
                ))
            })
            .map_err(db_err("tx: get_approvals"))?;
        let mut approvals = Vec::new();
        for row in rows {
            let (
                id,
                req_id,
                actor_id,
                action_str,
                matched_selector,
                step_index,
                comment,
                created_at_str,
            ) = row.map_err(db_err("tx: get_approvals row"))?;
            approvals.push(Approval {
                id,
                request_id: req_id,
                actor_id,
                action: parse_approval_action(&action_str)?,
                matched_selector,
                step_index,
                comment,
                created_at: parse_ts(&created_at_str)?,
            });
        }
        Ok(approvals)
    }

    fn get_request_state(
        &self,
        request_id: &str,
    ) -> Result<Option<dbward_app::ports::transaction::RequestState>, AppError> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT status, expires_at FROM requests WHERE id = ?1")
            .map_err(db_err("tx: get_request_state"))?;
        let result = stmt
            .query_row(params![request_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
            })
            .optional()
            .map_err(db_err("tx: get_request_state"))?;
        match result {
            None => Ok(None),
            Some((status_str, expires_at_str)) => {
                let status = parse_status(&status_str)?;
                let expires_at = expires_at_str.map(|s| parse_ts(&s)).transpose()?;
                Ok(Some((status, expires_at)))
            }
        }
    }
}

impl AuditWriterOps for SqliteTxScope<'_> {
    fn record(&self, event: &AuditEvent) -> Result<(), AppError> {
        insert_audit_event_raw(self.conn, event)
            .map_err(|e| AppError::Internal(format!("audit: {e}")))?;

        // Periodic signed checkpoint: insert after every N events
        if let Some(signer) = self.signer {
            let count: i64 = self.conn
                .query_row(
                    "SELECT COUNT(*) FROM audit_events WHERE event_type != 'audit.signed_checkpoint'",
                    [],
                    |row| row.get(0),
                )
                .map_err(|e| AppError::Internal(format!("checkpoint count: {e}")))?;

            let checkpoints: i64 = self.conn
                .query_row(
                    "SELECT COUNT(*) FROM audit_events WHERE event_type = 'audit.signed_checkpoint'",
                    [],
                    |row| row.get(0),
                )
                .map_err(|e| AppError::Internal(format!("checkpoint count: {e}")))?;

            let events_since = count - (checkpoints * self.checkpoint_interval as i64);
            let time_triggered = if checkpoints > 0 {
                let last_cp: String = self.conn.query_row(
                    "SELECT created_at FROM audit_events WHERE event_type = 'audit.signed_checkpoint' ORDER BY rowid DESC LIMIT 1",
                    [], |row| row.get(0),
                ).unwrap_or_default();
                chrono::DateTime::parse_from_rfc3339(&last_cp)
                    .map(|t| chrono::Utc::now().signed_duration_since(t).num_minutes() >= 60)
                    .unwrap_or(false)
            } else {
                false
            };
            if events_since >= self.checkpoint_interval as i64 || time_triggered {
                let head_hash: String = self
                    .conn
                    .query_row(
                        "SELECT event_hash FROM audit_events ORDER BY rowid DESC LIMIT 1",
                        [],
                        |row| row.get(0),
                    )
                    .map_err(|e| AppError::Internal(format!("checkpoint head: {e}")))?;

                let now = chrono::Utc::now();
                let key_id = signer.current_key_id();
                let msg = format!(
                    "audit-checkpoint:v1|{}|{}|{}",
                    head_hash,
                    events_since,
                    now.to_rfc3339()
                );
                let sig = signer.sign(msg.as_bytes());
                let sig_hex = hex::encode(&sig);

                let checkpoint_event = AuditEvent {
                    id: String::new(),
                    event_type: "audit.signed_checkpoint".to_string(),
                    event_category: dbward_domain::entities::EventCategory::Policy,
                    event_version: 1,
                    outcome: dbward_domain::entities::EventOutcome::Info,
                    actor_id: "system".to_string(),
                    actor_type: dbward_domain::entities::ActorType::System,
                    resource_type: None,
                    resource_id: None,
                    peer_ip: None,
                    client_ip: None,
                    client_ip_source: None,
                    request_id: None,
                    operation: None,
                    database_name: None,
                    environment: None,
                    detail_fingerprint: None,
                    detail_raw: None,
                    reason: None,
                    metadata_json: serde_json::json!({
                        "chain_head_hash": head_hash,
                        "event_count_since_last_checkpoint": events_since,
                        "key_id": key_id,
                        "signature": sig_hex,
                    })
                    .to_string(),
                    prev_hash: None,
                    event_hash: String::new(),
                    created_at: now,
                };
                insert_audit_event_raw(self.conn, &checkpoint_event)
                    .map_err(|e| AppError::Internal(format!("checkpoint insert: {e}")))?;
            }
        }
        Ok(())
    }
}

impl ExecutionWriterOps for SqliteTxScope<'_> {
    fn insert_execution(&self, exec: &Execution) -> Result<(), AppError> {
        self.conn
            .execute(
                "INSERT INTO executions (id, request_id, agent_id, status, token, lease_expires_at, started_at, finished_at, error_message, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                params![
                    exec.id,
                    exec.request_id,
                    exec.agent_id,
                    "claimed",
                    exec.token,
                    exec.lease_expires_at.to_rfc3339(),
                    exec.started_at.map(|t| t.to_rfc3339()),
                    exec.finished_at.map(|t| t.to_rfc3339()),
                    exec.error_message,
                    exec.created_at.to_rfc3339(),
                ],
            )
            .map_err(db_err("tx: insert_execution"))?;
        Ok(())
    }

    fn mark_completed(
        &self,
        execution_id: &str,
        success: bool,
        now: DateTime<Utc>,
    ) -> Result<bool, AppError> {
        let status = if success { "completed" } else { "failed" };
        let n = self
            .conn
            .execute(
                "UPDATE executions SET status = ?1, finished_at = ?2 WHERE id = ?3 AND status IN ('claimed', 'running')",
                params![status, now.to_rfc3339(), execution_id],
            )
            .map_err(db_err("tx: mark_execution_completed"))?;
        Ok(n > 0)
    }
}

impl TxScope for SqliteTxScope<'_> {}

impl TokenWriterOps for SqliteTxScope<'_> {
    fn create_token(&self, token: &Token) -> Result<(), AppError> {
        use super::token_repo::{subject_type_str, token_status_str};
        let scope_ceiling_json = token
            .scope_ceiling
            .as_ref()
            .map(|sc| serde_json::to_string(sc).unwrap());
        self.conn
            .execute(
                "INSERT INTO tokens (id, subject_type, subject_id, token_hash, token_prefix, scope_ceiling_json, name, status, expires_at, created_at, revoked_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                params![
                    token.id,
                    subject_type_str(token.subject_type),
                    token.subject_id,
                    token.token_hash,
                    token.token_prefix,
                    scope_ceiling_json,
                    token.name,
                    token_status_str(token.status),
                    token.expires_at.map(|t| t.to_rfc3339()),
                    token.created_at.to_rfc3339(),
                    token.revoked_at.map(|t| t.to_rfc3339()),
                ],
            )
            .map_err(db_err("tx: create_token"))?;
        Ok(())
    }

    fn revoke_token(&self, token_id: &str, now: DateTime<Utc>) -> Result<bool, AppError> {
        let n = self
            .conn
            .execute(
                "UPDATE tokens SET status = 'revoked', revoked_at = ?1 WHERE id = ?2 AND status = 'active'",
                params![now.to_rfc3339(), token_id],
            )
            .map_err(db_err("tx: revoke_token"))?;
        Ok(n > 0)
    }

    fn revoke_all_for_user(&self, user_id: &str, now: DateTime<Utc>) -> Result<u32, AppError> {
        let n = self
            .conn
            .execute(
                "UPDATE tokens SET status = 'revoked', revoked_at = ?1 WHERE subject_id = ?2 AND status = 'active'",
                params![now.to_rfc3339(), user_id],
            )
            .map_err(db_err("tx: revoke_all_for_user"))?;
        Ok(n as u32)
    }
}

impl UserWriterOps for SqliteTxScope<'_> {
    fn suspend_user(&self, user_id: &str, now: DateTime<Utc>) -> Result<bool, AppError> {
        let n = self
            .conn
            .execute(
                "UPDATE users SET status = 'suspended', updated_at = ?1 WHERE id = ?2 AND status = 'active' AND lifecycle_state = 'active'",
                params![now.to_rfc3339(), user_id],
            )
            .map_err(db_err("tx: suspend_user"))?;
        Ok(n > 0)
    }

    fn activate_user(&self, user_id: &str, now: DateTime<Utc>) -> Result<bool, AppError> {
        let n = self
            .conn
            .execute(
                "UPDATE users SET status = 'active', updated_at = ?1 WHERE id = ?2 AND status = 'suspended' AND lifecycle_state = 'active'",
                params![now.to_rfc3339(), user_id],
            )
            .map_err(db_err("tx: activate_user"))?;
        Ok(n > 0)
    }

    fn upsert_user_tx(&self, user: &dbward_domain::entities::User) -> Result<(), AppError> {
        let roles_json = serde_json::to_string(&user.roles).unwrap_or_else(|_| "[]".into());
        self.conn
            .execute(
                "INSERT INTO users (id, display_name, email, roles_json, status, source, created_at, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, 'api', ?6, ?7) \
                 ON CONFLICT(id) DO UPDATE SET display_name=?2, email=?3, roles_json=?4, updated_at=?7",
                params![
                    user.id,
                    user.display_name,
                    user.email,
                    roles_json,
                    match user.status {
                        dbward_domain::entities::UserStatus::Active => "active",
                        dbward_domain::entities::UserStatus::Suspended => "suspended",
                    },
                    user.created_at.to_rfc3339(),
                    user.updated_at.to_rfc3339(),
                ],
            )
            .map_err(db_err("tx: upsert_user"))?;
        Ok(())
    }

    fn create_token_tx(&self, token: &dbward_domain::entities::Token) -> Result<(), AppError> {
        let scope_json = token
            .scope_ceiling
            .as_ref()
            .map(|s| serde_json::to_string(s).unwrap_or_else(|_| "null".into()));
        self.conn
            .execute(
                "INSERT INTO tokens (id, subject_type, subject_id, token_hash, token_prefix, scope_ceiling_json, name, status, expires_at, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'active', ?8, ?9)",
                params![
                    token.id,
                    match token.subject_type {
                        dbward_domain::auth::SubjectType::User => "user",
                        dbward_domain::auth::SubjectType::Agent => "agent",
                    },
                    token.subject_id,
                    token.token_hash,
                    token.token_prefix,
                    scope_json,
                    token.name,
                    token.expires_at.map(|d| d.to_rfc3339()),
                    token.created_at.to_rfc3339(),
                ],
            )
            .map_err(db_err("tx: create_token"))?;
        Ok(())
    }

    fn add_group_member_tx(
        &self,
        group_name: &str,
        user_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), AppError> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO group_members (group_name, user_id, added_at) VALUES (?1, ?2, ?3)",
                params![group_name, user_id, now.to_rfc3339()],
            )
            .map_err(db_err("tx: add_group_member"))?;
        Ok(())
    }

    fn set_roles_tx(&self, user_id: &str, roles: &[String]) -> Result<(), AppError> {
        let roles_json = serde_json::to_string(roles).unwrap_or_else(|_| "[]".into());
        self.conn
            .execute(
                "UPDATE users SET roles_json = ?1, updated_at = ?2 WHERE id = ?3",
                params![roles_json, chrono::Utc::now().to_rfc3339(), user_id],
            )
            .map_err(db_err("tx: set_roles"))?;
        Ok(())
    }

    fn remove_member_tx(&self, group_name: &str, user_id: &str) -> Result<(), AppError> {
        self.conn
            .execute(
                "DELETE FROM group_members WHERE group_name = ?1 AND user_id = ?2",
                params![group_name, user_id],
            )
            .map_err(db_err("tx: remove_member"))?;
        Ok(())
    }

    fn soft_delete_tx(
        &self,
        user_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), AppError> {
        self.conn
            .execute(
                "UPDATE users SET lifecycle_state = 'deleted', status = 'suspended', updated_at = ?1 WHERE id = ?2",
                params![now.to_rfc3339(), user_id],
            )
            .map_err(db_err("tx: soft_delete"))?;
        Ok(())
    }

    fn remove_all_memberships_tx(&self, user_id: &str) -> Result<(), AppError> {
        self.conn
            .execute(
                "DELETE FROM group_members WHERE user_id = ?1",
                params![user_id],
            )
            .map_err(db_err("tx: remove_all_memberships"))?;
        Ok(())
    }

    fn count_active_tx(&self) -> Result<u32, AppError> {
        let count: u32 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM users WHERE lifecycle_state = 'active' AND status = 'active'",
                [],
                |r| r.get(0),
            )
            .map_err(|e| AppError::Internal(format!("count_active_tx: {e}")))?;
        Ok(count)
    }

    fn user_exists_tx(&self, user_id: &str) -> Result<bool, AppError> {
        let exists: bool = self
            .conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM users WHERE id = ?1)",
                params![user_id],
                |r| r.get(0),
            )
            .map_err(|e| AppError::Internal(format!("user_exists_tx: {e}")))?;
        Ok(exists)
    }

    fn count_admins_tx(&self, admin_groups: &[String]) -> Result<u32, AppError> {
        if admin_groups.is_empty() {
            // Only direct admin role holders
            let count: u32 = self
                .conn
                .query_row(
                    "SELECT COUNT(*) FROM users WHERE lifecycle_state = 'active' AND status = 'active' AND EXISTS(SELECT 1 FROM json_each(roles_json) WHERE value = 'admin')",
                    [],
                    |r| r.get(0),
                )
                .map_err(|e| AppError::Internal(format!("count_admins_tx: {e}")))?;
            return Ok(count);
        }
        // UNION direct admin holders with users who are admin via group membership
        let placeholders: String = admin_groups
            .iter()
            .enumerate()
            .map(|(i, _)| format!("?{}", i + 1))
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT COUNT(DISTINCT id) FROM (\
                SELECT id FROM users WHERE lifecycle_state = 'active' AND status = 'active' \
                    AND EXISTS(SELECT 1 FROM json_each(roles_json) WHERE value = 'admin') \
                UNION \
                SELECT gm.user_id AS id FROM group_members gm \
                    JOIN users u ON u.id = gm.user_id \
                    WHERE gm.group_name IN ({placeholders}) \
                    AND u.lifecycle_state = 'active' AND u.status = 'active'\
            )"
        );
        let mut stmt = self.conn.prepare(&sql)
            .map_err(|e| AppError::Internal(format!("count_admins_tx: {e}")))?;
        let params: Vec<&dyn rusqlite::types::ToSql> = admin_groups
            .iter()
            .map(|s| s as &dyn rusqlite::types::ToSql)
            .collect();
        let count: u32 = stmt
            .query_row(params.as_slice(), |r| r.get(0))
            .map_err(|e| AppError::Internal(format!("count_admins_tx: {e}")))?;
        Ok(count)
    }

    fn user_has_admin_tx(&self, user_id: &str, admin_groups: &[String]) -> Result<bool, AppError> {
        // Check direct admin role
        let has_direct: bool = self
            .conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM users WHERE id = ?1 AND EXISTS(SELECT 1 FROM json_each(roles_json) WHERE value = 'admin'))",
                params![user_id],
                |r| r.get(0),
            )
            .map_err(|e| AppError::Internal(format!("user_has_admin_tx: {e}")))?;
        if has_direct {
            return Ok(true);
        }
        // Check admin via group membership
        if !admin_groups.is_empty() {
            let placeholders: String = admin_groups
                .iter()
                .enumerate()
                .map(|(i, _)| format!("?{}", i + 2))
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                "SELECT EXISTS(SELECT 1 FROM group_members WHERE user_id = ?1 AND group_name IN ({placeholders}))"
            );
            let mut stmt = self.conn.prepare(&sql)
                .map_err(|e| AppError::Internal(format!("user_has_admin_tx: {e}")))?;
            let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = vec![Box::new(user_id.to_string())];
            for g in admin_groups {
                param_values.push(Box::new(g.clone()));
            }
            let param_refs: Vec<&dyn rusqlite::types::ToSql> = param_values.iter().map(|b| b.as_ref()).collect();
            let has_via_group: bool = stmt
                .query_row(param_refs.as_slice(), |r| r.get(0))
                .map_err(|e| AppError::Internal(format!("user_has_admin_tx: {e}")))?;
            return Ok(has_via_group);
        }
        Ok(false)
    }

    fn user_in_group_tx(&self, user_id: &str, group_name: &str) -> Result<bool, AppError> {
        let exists: bool = self
            .conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM group_members WHERE user_id = ?1 AND group_name = ?2)",
                params![user_id, group_name],
                |r| r.get(0),
            )
            .map_err(|e| AppError::Internal(format!("user_in_group_tx: {e}")))?;
        Ok(exists)
    }

    fn set_slack_user_id_tx(
        &self,
        user_id: &str,
        slack_user_id: &str,
        source: &str,
    ) -> Result<(), AppError> {
        self.conn
            .execute(
                "UPDATE users SET slack_user_id = ?1, source = ?2 WHERE id = ?3",
                params![slack_user_id, source, user_id],
            )
            .map_err(db_err("tx: set_slack_user_id"))?;
        Ok(())
    }

    fn claim_onboarding_approved_tx(
        &self,
        request_id: &str,
        decided_by: &str,
        decided_at: chrono::DateTime<chrono::Utc>,
        approved_roles: &[String],
        approved_groups: &[String],
        decision_comment: Option<&str>,
    ) -> Result<bool, AppError> {
        let roles_json = serde_json::to_string(approved_roles)
            .map_err(|e| AppError::Internal(format!("serialize: {e}")))?;
        let groups_json = serde_json::to_string(approved_groups)
            .map_err(|e| AppError::Internal(format!("serialize: {e}")))?;
        let affected = self
            .conn
            .execute(
                "UPDATE onboarding_requests SET status = 'approved', decided_by = ?1, decided_at = ?2, \
                 approved_roles_json = ?3, approved_groups_json = ?4, decision_comment = ?5 \
                 WHERE id = ?6 AND status = 'pending'",
                params![
                    decided_by,
                    decided_at.to_rfc3339(),
                    roles_json,
                    groups_json,
                    decision_comment,
                    request_id,
                ],
            )
            .map_err(db_err("tx: claim_onboarding_approved"))?;
        Ok(affected > 0)
    }
}

impl dbward_app::ports::ResultWriterOps for SqliteTxScope<'_> {
    fn insert_result(&self, rm: &dbward_domain::entities::ExecutionResult) -> Result<(), AppError> {
        self.conn
            .execute(
                "INSERT INTO results (id, request_id, execution_id, storage_backend, storage_key, content_length, checksum_sha256, retention_days, status, truncated, truncation_reason, stored_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    rm.id, rm.request_id, rm.execution_id, rm.storage_backend, rm.storage_key,
                    rm.content_length as i64, rm.checksum_sha256, rm.retention_days,
                    "stored", rm.truncated as i64, rm.truncation_reason,
                    rm.stored_at.to_rfc3339(), rm.expires_at.to_rfc3339(),
                ],
            )
            .map_err(db_err("tx: insert_result"))?;
        Ok(())
    }

    fn insert_result_access(
        &self,
        access: &[dbward_domain::entities::ResultAccess],
    ) -> Result<(), AppError> {
        for ra in access {
            let st = match ra.selector_type {
                dbward_domain::entities::SelectorType::User => "user",
                dbward_domain::entities::SelectorType::Group => "group",
                dbward_domain::entities::SelectorType::Role => "role",
                dbward_domain::entities::SelectorType::Requester => "requester",
            };
            self.conn
                .execute(
                    "INSERT INTO result_access (id, result_id, selector_type, selector_value) VALUES (?1, ?2, ?3, ?4)",
                    params![ra.id, ra.result_id, st, ra.selector_value],
                )
                .map_err(db_err("tx: insert_result_access"))?;
        }
        Ok(())
    }
}

impl SqliteTxScope<'_> {
    /// Simple status update. Does NOT assert prior state — use cases MUST validate
    /// the expected prior status via RequestReader BEFORE calling UoW.
    fn update_status_guarded(
        &self,
        id: &str,
        status: RequestStatus,
        valid_from: &[&str],
        now: DateTime<Utc>,
    ) -> Result<bool, AppError> {
        let placeholders: String = valid_from
            .iter()
            .enumerate()
            .map(|(i, _)| format!("?{}", i + 4))
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "UPDATE requests SET status = ?1, updated_at = ?2 WHERE id = ?3 AND status IN ({})",
            placeholders
        );
        let mut stmt = self
            .conn
            .prepare_cached(&sql)
            .map_err(db_err("tx: update_status"))?;
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = vec![
            Box::new(status.as_str().to_string()),
            Box::new(now.to_rfc3339()),
            Box::new(id.to_string()),
        ];
        for s in valid_from {
            param_values.push(Box::new(s.to_string()));
        }
        let params: Vec<&dyn rusqlite::types::ToSql> =
            param_values.iter().map(|b| b.as_ref()).collect();
        let n = stmt
            .execute(params.as_slice())
            .map_err(db_err("tx: update_status"))?;
        Ok(n > 0)
    }
}
