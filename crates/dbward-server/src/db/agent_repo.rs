use rusqlite::Connection;
use std::ops::Deref;

/// Upsert agent capabilities on poll.
pub fn upsert_agent<C>(
    conn: &C,
    agent_id: &str,
    token_id: &str,
    capabilities_json: &str,
) -> Result<(), rusqlite::Error>
where
    C: Deref<Target = Connection> + ?Sized,
{
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO agents (id, token_id, capabilities_json, last_seen_at, created_at)
         VALUES (?1, ?2, ?3, ?4, ?4)
         ON CONFLICT(id) DO UPDATE SET capabilities_json = ?3, last_seen_at = ?4",
        rusqlite::params![agent_id, token_id, capabilities_json, now],
    )?;
    Ok(())
}

/// Get agent capabilities JSON.
pub fn get_agent_capabilities(conn: &Connection, agent_id: &str) -> Option<String> {
    conn.query_row(
        "SELECT capabilities_json FROM agents WHERE id = ?1",
        rusqlite::params![agent_id],
        |row| row.get::<_, String>(0),
    )
    .ok()
}

/// Create agent execution and mark request as running. Returns execution_id.
pub fn create_execution_and_mark_running(
    conn: &mut Connection,
    request_id: &str,
    agent_id: &str,
    execution_token_json: &str,
) -> Result<String, rusqlite::Error> {
    let now = chrono::Utc::now();
    let now_rfc3339 = now.to_rfc3339();
    let lease_expires = (now + chrono::Duration::minutes(5)).to_rfc3339();
    let exec_id = uuid::Uuid::new_v4().to_string();

    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO agent_executions (id, request_id, agent_id, status, execution_token_json, lease_expires_at, started_at, created_at)
         VALUES (?1, ?2, ?3, 'claimed', ?4, ?5, ?6, ?6)",
        rusqlite::params![exec_id, request_id, agent_id, execution_token_json, lease_expires, now_rfc3339],
    )?;
    tx.execute(
        "UPDATE requests SET status = 'running', updated_at = ?1 WHERE id = ?2",
        rusqlite::params![now_rfc3339, request_id],
    )?;
    tx.commit()?;
    Ok(exec_id)
}

/// Execution context for result submission.
pub struct ExecutionContext {
    pub request_id: String,
    pub status: String,
    pub agent_id: String,
}

/// Load execution context for result submission.
pub fn get_execution_context(
    conn: &Connection,
    execution_id: &str,
) -> Result<ExecutionContext, rusqlite::Error> {
    conn.query_row(
        "SELECT request_id, status, agent_id FROM agent_executions WHERE id = ?1",
        rusqlite::params![execution_id],
        |row| {
            Ok(ExecutionContext {
                request_id: row.get(0)?,
                status: row.get(1)?,
                agent_id: row.get(2)?,
            })
        },
    )
}

/// Finalize execution: update execution status, request status, insert audit log.
pub fn finish_execution(
    conn: &mut Connection,
    execution_id: &str,
    request_id: &str,
    success: bool,
    error_msg: Option<&str>,
    operation: &str,
    environment: &str,
    database_name: &str,
    detail: &str,
    actor: &str,
) -> Result<String, rusqlite::Error> {
    let now = chrono::Utc::now().to_rfc3339();
    let exec_status = if success { "completed" } else { "failed" };
    let req_status = if success { "executed" } else { "failed" };
    let audit_id = uuid::Uuid::new_v4().to_string();

    let tx = conn.transaction()?;
    tx.execute(
        "UPDATE agent_executions SET status = ?1, finished_at = ?2, error_message = ?3 WHERE id = ?4",
        rusqlite::params![exec_status, now, error_msg, execution_id],
    )?;
    tx.execute(
        "UPDATE requests SET status = ?1, updated_at = ?2, resolved_at = ?2 WHERE id = ?3",
        rusqlite::params![req_status, now, request_id],
    )?;
    tx.execute(
        "INSERT INTO audit_log (id, request_id, execution_id, actor_id, operation, environment, database_name, detail, status, result_summary, error_message, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, ?10, ?11)",
        rusqlite::params![audit_id, request_id, execution_id, actor, operation, environment, database_name, detail, req_status, error_msg, now],
    )?;
    tx.commit()?;
    Ok(req_status.to_string())
}
