use chrono::{DateTime, Utc};
use rusqlite::{OptionalExtension, params};

use dbward_app::error::AppError;
use dbward_app::ports::AgentRepo;
use dbward_domain::entities::*;
use dbward_domain::values::{DatabaseName, Environment, Operation};

use crate::sqlite::DbConn;
use crate::sqlite::error::{db_err, json_err};

pub struct SqliteAgentRepo {
    conn: DbConn,
}

impl SqliteAgentRepo {
    pub fn new(conn: DbConn) -> Self {
        Self { conn }
    }
}

impl AgentRepo for SqliteAgentRepo {
    fn upsert(&self, agent: &Agent) -> Result<(), AppError> {
        let conn = self.conn.lock();
        let databases_json =
            serde_json::to_string(&agent.databases).map_err(json_err("agent: upsert"))?;
        let active_jobs_json =
            serde_json::to_string(&agent.active_jobs).map_err(json_err("agent: upsert"))?;
        let status = agent_status_str(agent.status);
        let last_seen = agent.last_seen.map(|t| t.to_rfc3339());
        let created_at = agent.created_at.to_rfc3339();

        conn.execute(
            "INSERT INTO agents (id, token_id, databases_json, status, max_concurrent, in_flight, uptime_secs, active_jobs_json, last_seen_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(id) DO UPDATE SET
               token_id = excluded.token_id,
               databases_json = excluded.databases_json,
               status = excluded.status,
               max_concurrent = excluded.max_concurrent,
               in_flight = excluded.in_flight,
               uptime_secs = excluded.uptime_secs,
               active_jobs_json = excluded.active_jobs_json,
               last_seen_at = excluded.last_seen_at",
            params![agent.id, agent.token_id, databases_json, status, agent.max_concurrent, agent.in_flight, agent.uptime_secs as i64, active_jobs_json, last_seen, created_at],
        ).map_err(db_err("agent: upsert"))?;
        Ok(())
    }

    fn get(&self, agent_id: &str) -> Result<Option<Agent>, AppError> {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT id, token_id, databases_json, status, max_concurrent, in_flight, uptime_secs, active_jobs_json, last_seen_at, created_at FROM agents WHERE id = ?1",
            params![agent_id],
            |row| {
                Ok(AgentRow {
                    id: row.get(0)?,
                    token_id: row.get(1)?,
                    databases_json: row.get(2)?,
                    status: row.get(3)?,
                    max_concurrent: row.get(4)?,
                    in_flight: row.get(5)?,
                    uptime_secs: row.get(6)?,
                    active_jobs_json: row.get(7)?,
                    last_seen_at: row.get::<_, Option<String>>(8)?,
                    created_at: row.get(9)?,
                })
            },
        )
        .optional()
        .map_err(db_err("agent: get"))?
        .map(row_to_agent)
        .transpose()
    }

    fn list(&self) -> Result<Vec<Agent>, AppError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, token_id, databases_json, status, max_concurrent, in_flight, uptime_secs, active_jobs_json, last_seen_at, created_at FROM agents ORDER BY last_seen_at DESC",
        ).map_err(db_err("agent: list"))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(AgentRow {
                    id: row.get(0)?,
                    token_id: row.get(1)?,
                    databases_json: row.get(2)?,
                    status: row.get(3)?,
                    max_concurrent: row.get(4)?,
                    in_flight: row.get(5)?,
                    uptime_secs: row.get(6)?,
                    active_jobs_json: row.get(7)?,
                    last_seen_at: row.get::<_, Option<String>>(8)?,
                    created_at: row.get(9)?,
                })
            })
            .map_err(db_err("agent: list"))?;
        let mut results = Vec::new();
        for row in rows {
            let r = row.map_err(db_err("agent: list"))?;
            results.push(row_to_agent(r)?);
        }
        Ok(results)
    }

    fn create_execution(&self, execution: &Execution) -> Result<(), AppError> {
        let conn = self.conn.lock();
        let status = execution_status_str(execution.status);
        let lease = execution.lease_expires_at.to_rfc3339();
        let started = execution.started_at.map(|t| t.to_rfc3339());
        let finished = execution.finished_at.map(|t| t.to_rfc3339());
        let created = execution.created_at.to_rfc3339();

        conn.execute(
            "INSERT INTO executions (id, request_id, agent_id, status, token, lease_expires_at, started_at, finished_at, error_message, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![execution.id, execution.request_id, execution.agent_id, status, execution.token, lease, started, finished, execution.error_message, created],
        ).map_err(db_err("agent: create_execution"))?;
        Ok(())
    }

    fn get_execution(&self, execution_id: &str) -> Result<Option<Execution>, AppError> {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT id, request_id, agent_id, status, token, lease_expires_at, started_at, finished_at, error_message, created_at
             FROM executions WHERE id = ?1",
            params![execution_id],
            row_to_execution,
        )
        .optional()
        .map_err(db_err("agent: get_execution"))
    }

    fn update_execution_status(
        &self,
        execution_id: &str,
        status: ExecutionStatus,
    ) -> Result<(), AppError> {
        let conn = self.conn.lock();
        // Set finished_at when execution reaches a terminal state
        let finished = matches!(status, ExecutionStatus::Completed | ExecutionStatus::Failed);
        if finished {
            conn.execute(
                "UPDATE executions SET status = ?1, finished_at = ?3 WHERE id = ?2",
                params![
                    execution_status_str(status),
                    execution_id,
                    chrono::Utc::now().to_rfc3339()
                ],
            )
            .map_err(db_err("agent: update_execution_status"))?;
        } else {
            conn.execute(
                "UPDATE executions SET status = ?1 WHERE id = ?2",
                params![execution_status_str(status), execution_id],
            )
            .map_err(db_err("agent: update_execution_status"))?;
        }
        Ok(())
    }

    fn extend_lease(&self, execution_id: &str, new_expiry: DateTime<Utc>) -> Result<(), AppError> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE executions SET lease_expires_at = ?1 WHERE id = ?2",
            params![new_expiry.to_rfc3339(), execution_id],
        )
        .map_err(db_err("agent: extend_lease"))?;
        Ok(())
    }

    fn find_dispatched_jobs(
        &self,
        databases: &[(DatabaseName, Environment)],
    ) -> Result<Vec<Request>, AppError> {
        if databases.is_empty() {
            return Ok(vec![]);
        }
        let conn = self.conn.lock();
        let placeholders: Vec<String> = databases
            .iter()
            .enumerate()
            .map(|(i, _)| format!("?{}", i + 2))
            .collect();
        let sql = format!(
            "SELECT id, requester, operation, database_id, detail, status, emergency, reason, idempotency_key, metadata_json, share_with_json, no_store, workflow_snapshot_json, decision_trace_json, execution_plan_json, cancelled_by, cancel_reason, created_at, updated_at, resolved_at, expires_at
             FROM requests WHERE status = ?1 AND database_id IN ({})",
            placeholders.join(",")
        );

        let mut stmt = conn
            .prepare(&sql)
            .map_err(db_err("agent: find_dispatched_jobs"))?;
        let db_ids: Vec<String> = databases
            .iter()
            .map(|(db, env)| format!("{}:{}", db, env))
            .collect();

        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        param_values.push(Box::new("dispatched".to_string()));
        for id in &db_ids {
            param_values.push(Box::new(id.clone()));
        }
        let params_ref: Vec<&dyn rusqlite::types::ToSql> =
            param_values.iter().map(|p| p.as_ref()).collect();

        let rows = stmt
            .query_map(params_ref.as_slice(), |row| {
                Ok(RequestRow {
                    id: row.get(0)?,
                    requester: row.get(1)?,
                    operation: row.get(2)?,
                    database_id: row.get(3)?,
                    detail: row.get(4)?,
                    status: row.get(5)?,
                    emergency: row.get(6)?,
                    reason: row.get(7)?,
                    idempotency_key: row.get(8)?,
                    metadata_json: row.get(9)?,
                    share_with_json: row.get(10)?,
                    no_store: row.get(11)?,
                    workflow_snapshot_json: row.get(12)?,
                    decision_trace_json: row.get(13)?,
                    execution_plan_json: row.get(14)?,
                    cancelled_by: row.get(15)?,
                    cancel_reason: row.get(16)?,
                    created_at: row.get(17)?,
                    updated_at: row.get(18)?,
                    resolved_at: row.get(19)?,
                    expires_at: row.get(20)?,
                })
            })
            .map_err(db_err("agent: find_dispatched_jobs"))?;

        let mut results = Vec::new();
        for row in rows {
            let r = row.map_err(db_err("agent: find_dispatched_jobs"))?;
            results.push(row_to_request(r)?);
        }
        Ok(results)
    }

    fn has_running_migration(
        &self,
        db: &DatabaseName,
        env: &Environment,
        exclude_request_id: &str,
    ) -> Result<bool, AppError> {
        let conn = self.conn.lock();
        let database_id = format!("{}:{}", db, env);
        let count: u32 = conn
            .query_row(
                "SELECT COUNT(*) FROM requests
             WHERE status IN ('dispatched','running')
               AND operation IN ('migrate_up','migrate_down','migrate_repair')
               AND database_id = ?1
               AND id != ?2",
                params![database_id, exclude_request_id],
                |row| row.get(0),
            )
            .map_err(db_err("agent: has_running_migration"))?;
        Ok(count > 0)
    }

    fn find_executions_for_request(&self, request_id: &str) -> Result<Vec<Execution>, AppError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, request_id, agent_id, status, token, lease_expires_at, started_at, finished_at, error_message, created_at
             FROM executions WHERE request_id = ?1 ORDER BY created_at ASC",
        ).map_err(db_err("agent: find_executions_for_request"))?;

        let rows = stmt
            .query_map(params![request_id], row_to_execution)
            .map_err(db_err("agent: find_executions_for_request"))?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row.map_err(db_err("agent: find_executions_for_request"))?);
        }
        Ok(results)
    }

    fn claim_and_mark_running(
        &self,
        execution: &Execution,
        request_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, AppError> {
        let conn = self.conn.lock();
        let tx = conn
            .unchecked_transaction()
            .map_err(db_err("agent: claim_and_mark_running"))?;

        // Migration exclusion check within TX (prevents TOCTOU race)
        let (operation, database_id): (String, String) = tx
            .query_row(
                "SELECT operation, database_id FROM requests WHERE id = ?1",
                params![request_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(db_err("agent: claim_and_mark_running"))?;

        if operation == "migrate_up" || operation == "migrate_down" || operation == "migrate_repair"
        {
            let conflict: u32 = tx
                .query_row(
                    "SELECT COUNT(*) FROM requests
                     WHERE status IN ('dispatched','running')
                       AND operation IN ('migrate_up','migrate_down','migrate_repair')
                       AND database_id = ?1
                       AND id != ?2",
                    params![database_id, request_id],
                    |row| row.get(0),
                )
                .map_err(db_err("agent: claim_and_mark_running"))?;
            if conflict > 0 {
                drop(tx);
                return Ok(false);
            }
        }

        let status = execution_status_str(execution.status);
        let lease = execution.lease_expires_at.to_rfc3339();
        let started = execution.started_at.map(|t| t.to_rfc3339());
        let finished = execution.finished_at.map(|t| t.to_rfc3339());
        let created = execution.created_at.to_rfc3339();

        tx.execute(
            "INSERT INTO executions (id, request_id, agent_id, status, token, lease_expires_at, started_at, finished_at, error_message, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![execution.id, execution.request_id, execution.agent_id, status, execution.token, lease, started, finished, execution.error_message, created],
        ).map_err(db_err("agent: claim_and_mark_running"))?;

        let now_str = now.to_rfc3339();
        let updated = tx.execute(
            "UPDATE requests SET status = 'running', updated_at = ?2 WHERE id = ?1 AND status = 'dispatched'",
            params![request_id, now_str],
        ).map_err(db_err("agent: claim_and_mark_running"))?;

        if updated == 0 {
            drop(tx);
            return Ok(false);
        }

        tx.commit()
            .map_err(db_err("agent: claim_and_mark_running"))?;
        Ok(true)
    }

    fn complete_execution(
        &self,
        execution_id: &str,
        request_id: &str,
        success: bool,
        now: chrono::DateTime<chrono::Utc>,
        audit_event: &AuditEvent,
        result_manifest: Option<&ExecutionResult>,
        share_with: &[ResultAccess],
    ) -> Result<dbward_app::ports::CompletionOutcome, AppError> {
        use dbward_app::ports::CompletionOutcome;

        let mut conn = self.conn.lock();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(db_err("agent: complete_execution"))?;

        let exec_status = if success { "completed" } else { "failed" };
        tx.execute(
            "UPDATE executions SET status = ?1, finished_at = ?2 WHERE id = ?3",
            params![exec_status, now.to_rfc3339(), execution_id],
        )
        .map_err(db_err("agent: complete_execution"))?;

        let req_status = if success { "executed" } else { "failed" };
        let updated = tx.execute(
            "UPDATE requests SET status = ?1, updated_at = ?2 WHERE id = ?3 AND status IN ('running', 'execution_lost')",
            params![req_status, now.to_rfc3339(), request_id],
        ).map_err(db_err("agent: complete_execution"))?;

        if updated == 0 {
            // Check if request was cancelled or already completed
            let current_status: String = tx
                .query_row(
                    "SELECT status FROM requests WHERE id = ?1",
                    params![request_id],
                    |r| r.get(0),
                )
                .map_err(db_err("agent: complete_execution"))?;

            match current_status.as_str() {
                // Cancelled: store result/audit but don't update request status
                "cancelled" => {}
                // Already completed (idempotent retry): still store result
                "executed" | "failed" => {}
                _ => {
                    return Err(AppError::Conflict(format!(
                        "request status changed to '{current_status}' during execution"
                    )));
                }
            }
            // Cancelled/already-completed: still save result/audit but don't update request status
        }

        // Insert result manifest
        if let Some(rm) = result_manifest {
            tx.execute(
                "INSERT INTO results (id, request_id, execution_id, storage_backend, storage_key, content_length, checksum_sha256, retention_days, status, truncated, truncation_reason, stored_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    rm.id, rm.request_id, rm.execution_id, rm.storage_backend, rm.storage_key,
                    rm.content_length as i64, rm.checksum_sha256, rm.retention_days,
                    "stored", rm.truncated as i64, rm.truncation_reason,
                    rm.stored_at.to_rfc3339(), rm.expires_at.to_rfc3339(),
                ],
            ).map_err(db_err("agent: complete_execution"))?;

            for ra in share_with {
                tx.execute(
                    "INSERT INTO result_access (id, result_id, selector_type, selector_value) VALUES (?1, ?2, ?3, ?4)",
                    params![ra.id, ra.result_id, selector_type_str(ra.selector_type), ra.selector_value],
                ).map_err(db_err("agent: complete_execution"))?;
            }
        }

        insert_audit_in_agent_tx(&tx, audit_event)?;

        tx.commit().map_err(db_err("agent: complete_execution"))?;
        Ok(if updated > 0 {
            CompletionOutcome::Normal
        } else {
            CompletionOutcome::RequestCancelled
        })
    }

    fn find_expired_leases(&self, now: &str) -> Result<Vec<(String, String)>, AppError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, request_id FROM executions WHERE status IN ('claimed', 'running') AND datetime(lease_expires_at) < datetime(?1)"
        ).map_err(db_err("agent: find_expired_leases"))?;
        let rows = stmt
            .query_map(rusqlite::params![now], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(db_err("agent: find_expired_leases"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(db_err("agent: find_expired_leases"))
    }

    fn mark_execution_lost(
        &self,
        execution_id: &str,
        request_id: &str,
        now: &str,
    ) -> Result<bool, AppError> {
        let conn = self.conn.lock();
        let tx = conn
            .unchecked_transaction()
            .map_err(db_err("agent: mark_execution_lost"))?;
        let n1 = tx.execute(
            "UPDATE executions SET status = 'failed', finished_at = ?2 WHERE id = ?1 AND status IN ('claimed', 'running')",
            rusqlite::params![execution_id, now],
        ).map_err(db_err("agent: mark_execution_lost"))?;
        if n1 == 0 {
            return Ok(false);
        }
        tx.execute(
            "UPDATE requests SET status = 'execution_lost', updated_at = ?2 WHERE id = ?1 AND status IN ('dispatched', 'running')",
            rusqlite::params![request_id, now],
        ).map_err(db_err("agent: mark_execution_lost"))?;
        tx.commit().map_err(db_err("agent: mark_execution_lost"))?;
        Ok(true)
    }

    fn mark_execution_lost_and_record(
        &self,
        execution_id: &str,
        request_id: &str,
        audit_event: &AuditEvent,
        now: &str,
    ) -> Result<bool, AppError> {
        let mut conn = self.conn.lock();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(db_err("agent: mark_execution_lost_and_record"))?;
        let n1 = tx.execute(
            "UPDATE executions SET status = 'failed', finished_at = ?2 WHERE id = ?1 AND status IN ('claimed', 'running')",
            rusqlite::params![execution_id, now],
        ).map_err(db_err("agent: mark_execution_lost_and_record"))?;
        if n1 == 0 {
            return Ok(false);
        }
        tx.execute(
            "UPDATE requests SET status = 'execution_lost', updated_at = ?2 WHERE id = ?1 AND status IN ('dispatched', 'running')",
            rusqlite::params![request_id, now],
        ).map_err(db_err("agent: mark_execution_lost_and_record"))?;

        // Inline audit INSERT with hash chain
        crate::sqlite::audit_helper::insert_audit_event_in_tx(
            &tx,
            audit_event,
            crate::sqlite::audit_helper::IdPolicy::AlwaysGenerate,
        )
        .map_err(db_err("agent: mark_execution_lost_and_record"))?;

        tx.commit()
            .map_err(db_err("agent: mark_execution_lost_and_record"))?;
        Ok(true)
    }

    fn find_expired_results(&self, now: &str) -> Result<Vec<(String, String)>, AppError> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare(
                "SELECT id, storage_key FROM results WHERE datetime(expires_at) < datetime(?1)",
            )
            .map_err(db_err("agent: find_expired_results"))?;
        let rows = stmt
            .query_map(rusqlite::params![now], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(db_err("agent: find_expired_results"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(db_err("agent: find_expired_results"))
    }

    fn delete_result(&self, result_id: &str) -> Result<(), AppError> {
        let conn = self.conn.lock();
        conn.execute(
            "DELETE FROM result_access WHERE result_id = ?1",
            rusqlite::params![result_id],
        )
        .map_err(db_err("agent: delete_result"))?;
        conn.execute(
            "DELETE FROM results WHERE id = ?1",
            rusqlite::params![result_id],
        )
        .map_err(db_err("agent: delete_result"))?;
        Ok(())
    }
}

// --- helpers ---

fn insert_audit_in_agent_tx(
    tx: &rusqlite::Transaction<'_>,
    audit_event: &AuditEvent,
) -> Result<(), AppError> {
    crate::sqlite::audit_helper::insert_audit_event_in_tx(
        tx,
        audit_event,
        crate::sqlite::audit_helper::IdPolicy::AlwaysGenerate,
    )
    .map_err(db_err("agent: insert_audit"))
}

fn selector_type_str(st: SelectorType) -> &'static str {
    match st {
        SelectorType::Requester => "requester",
        SelectorType::Role => "role",
        SelectorType::Group => "group",
        SelectorType::User => "user",
    }
}

fn agent_status_str(s: AgentStatus) -> &'static str {
    match s {
        AgentStatus::Active => "active",
        AgentStatus::Draining => "draining",
    }
}

fn parse_agent_status(s: &str) -> Result<AgentStatus, AppError> {
    match s {
        "active" => Ok(AgentStatus::Active),
        "draining" => Ok(AgentStatus::Draining),
        _ => Err(AppError::Internal(format!("unknown agent status: {s}"))),
    }
}

fn execution_status_str(s: ExecutionStatus) -> &'static str {
    match s {
        ExecutionStatus::Claimed => "claimed",
        ExecutionStatus::Running => "running",
        ExecutionStatus::Completed => "completed",
        ExecutionStatus::Failed => "failed",
    }
}

fn parse_execution_status(s: &str) -> Result<ExecutionStatus, AppError> {
    match s {
        "claimed" => Ok(ExecutionStatus::Claimed),
        "running" => Ok(ExecutionStatus::Running),
        "completed" => Ok(ExecutionStatus::Completed),
        "failed" => Ok(ExecutionStatus::Failed),
        _ => Err(AppError::Internal(format!("unknown execution status: {s}"))),
    }
}

fn parse_request_status(s: &str) -> Result<RequestStatus, AppError> {
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
        _ => Err(AppError::Internal(format!("unknown request status: {s}"))),
    }
}

fn parse_dt(s: &str) -> Result<DateTime<Utc>, AppError> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| AppError::Internal(format!("invalid datetime: {e}")))
}

fn parse_dt_opt(s: Option<String>) -> Result<Option<DateTime<Utc>>, AppError> {
    s.map(|v| parse_dt(&v)).transpose()
}

struct AgentRow {
    id: String,
    token_id: String,
    databases_json: String,
    status: String,
    max_concurrent: u32,
    in_flight: u32,
    uptime_secs: i64,
    active_jobs_json: String,
    last_seen_at: Option<String>,
    created_at: String,
}

fn row_to_agent(r: AgentRow) -> Result<Agent, AppError> {
    let databases: Vec<DatabaseCapability> =
        serde_json::from_str(&r.databases_json).map_err(json_err("agent: row_to_agent"))?;
    let active_jobs: Vec<ActiveJobEntry> =
        serde_json::from_str(&r.active_jobs_json).map_err(json_err("agent: active_jobs"))?;
    Ok(Agent {
        id: r.id,
        token_id: r.token_id,
        databases,
        status: parse_agent_status(&r.status)?,
        max_concurrent: r.max_concurrent,
        in_flight: r.in_flight,
        uptime_secs: r.uptime_secs as u64,
        active_jobs,
        last_seen: parse_dt_opt(r.last_seen_at)?,
        created_at: parse_dt(&r.created_at)?,
        lease_duration_secs: None,
    })
}

fn row_to_execution(row: &rusqlite::Row) -> rusqlite::Result<Execution> {
    let status_str: String = row.get(3)?;
    let lease_str: String = row.get(5)?;
    let started_str: Option<String> = row.get(6)?;
    let finished_str: Option<String> = row.get(7)?;
    let created_str: String = row.get(9)?;

    // Parse inside rusqlite::Result by mapping errors
    let status = parse_execution_status(&status_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let lease_expires_at = parse_dt(&lease_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let started_at = parse_dt_opt(started_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(6, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let finished_at = parse_dt_opt(finished_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(7, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let created_at = parse_dt(&created_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(9, rusqlite::types::Type::Text, Box::new(e))
    })?;

    Ok(Execution {
        id: row.get(0)?,
        request_id: row.get(1)?,
        agent_id: row.get(2)?,
        status,
        token: row.get(4)?,
        lease_expires_at,
        started_at,
        finished_at,
        error_message: row.get(8)?,
        created_at,
    })
}

struct RequestRow {
    id: String,
    requester: String,
    operation: String,
    database_id: String,
    detail: String,
    status: String,
    emergency: bool,
    reason: Option<String>,
    idempotency_key: Option<String>,
    metadata_json: String,
    share_with_json: String,
    no_store: bool,
    workflow_snapshot_json: Option<String>,
    decision_trace_json: Option<String>,
    execution_plan_json: Option<String>,
    cancelled_by: Option<String>,
    cancel_reason: Option<String>,
    created_at: String,
    updated_at: String,
    resolved_at: Option<String>,
    expires_at: Option<String>,
}

fn row_to_request(r: RequestRow) -> Result<Request, AppError> {
    let (db_str, env_str) = r
        .database_id
        .split_once(':')
        .ok_or_else(|| AppError::Internal(format!("invalid database_id: {}", r.database_id)))?;
    let database = DatabaseName::new(db_str).map_err(|e| AppError::Internal(e.to_string()))?;
    let environment = Environment::new(env_str).map_err(|e| AppError::Internal(e.to_string()))?;
    let operation: Operation = r
        .operation
        .parse()
        .map_err(|e: String| AppError::Internal(e))?;
    let status = parse_request_status(&r.status)?;
    let share_with: Vec<String> =
        serde_json::from_str(&r.share_with_json).map_err(json_err("agent: row_to_request"))?;

    Ok(Request {
        id: r.id,
        requester: r.requester,
        database,
        environment,
        operation,
        detail: r.detail,
        status,
        emergency: r.emergency,
        reason: r.reason,
        idempotency_key: r.idempotency_key,
        metadata_json: r.metadata_json,
        share_with,
        no_store: r.no_store,
        workflow_snapshot_json: r.workflow_snapshot_json,
        decision_trace_json: r.decision_trace_json,
        execution_plan_json: r.execution_plan_json,
        cancelled_by: r.cancelled_by,
        cancel_reason: r.cancel_reason,
        created_at: parse_dt(&r.created_at)?,
        updated_at: parse_dt(&r.updated_at)?,
        resolved_at: parse_dt_opt(r.resolved_at)?,
        expires_at: parse_dt_opt(r.expires_at)?,
    })
}
