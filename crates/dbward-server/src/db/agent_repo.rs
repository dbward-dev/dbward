use rusqlite::Connection;
use std::ops::Deref;

/// Upsert agent capabilities on poll.
pub fn upsert_agent<C>(
    conn: &C,
    agent_id: &str,
    token_id: &str,
    capabilities_json: &str,
    status: Option<&AgentStatusReport>,
) -> Result<(), rusqlite::Error>
where
    C: Deref<Target = Connection> + ?Sized,
{
    let now = chrono::Utc::now().to_rfc3339();
    let (in_flight, max_concurrent, draining, uptime_secs, active_jobs_json) = match status {
        Some(s) => (
            s.in_flight as i64,
            s.max_concurrent as i64,
            s.draining as i64,
            s.uptime_secs as i64,
            s.active_jobs_json.as_str(),
        ),
        None => (0, 1, 0, 0, "[]"),
    };
    conn.execute(
        "INSERT INTO agents (id, token_id, capabilities_json, last_seen_at, created_at, in_flight, max_concurrent, draining, uptime_secs, active_jobs_json)
         VALUES (?1, ?2, ?3, ?4, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(id) DO UPDATE SET capabilities_json = ?3, last_seen_at = ?4, in_flight = ?5, max_concurrent = ?6, draining = ?7, uptime_secs = ?8, active_jobs_json = ?9",
        rusqlite::params![agent_id, token_id, capabilities_json, now, in_flight, max_concurrent, draining, uptime_secs, active_jobs_json],
    )?;
    Ok(())
}

/// Agent status as reported in poll request.
pub struct AgentStatusReport {
    pub in_flight: u32,
    pub max_concurrent: u32,
    pub draining: bool,
    pub uptime_secs: u64,
    pub active_jobs_json: String,
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

/// List all known agents with their last_seen_at and capabilities.
/// Agent info returned by list_agents.
pub struct AgentInfo {
    pub id: String,
    pub capabilities_json: String,
    pub last_seen_at: String,
    pub created_at: String,
    pub in_flight: i64,
    pub max_concurrent: i64,
    pub draining: bool,
    pub uptime_secs: i64,
    pub active_jobs_json: String,
}

pub fn list_agents(conn: &Connection) -> Result<Vec<AgentInfo>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT id, capabilities_json, last_seen_at, created_at, in_flight, max_concurrent, draining, uptime_secs, active_jobs_json FROM agents ORDER BY last_seen_at DESC",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok(AgentInfo {
                id: row.get(0)?,
                capabilities_json: row.get(1)?,
                last_seen_at: row.get(2)?,
                created_at: row.get(3)?,
                in_flight: row.get(4)?,
                max_concurrent: row.get(5)?,
                draining: row.get::<_, i64>(6)? != 0,
                uptime_secs: row.get(7)?,
                active_jobs_json: row.get(8)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Claim a dispatched request, create agent execution, and mark request as running.
pub fn create_execution_and_mark_running(
    conn: &mut Connection,
    request_id: &str,
    agent_id: &str,
    execution_token_json: &str,
) -> Result<Option<String>, rusqlite::Error> {
    let now = chrono::Utc::now();
    let now_rfc3339 = now.to_rfc3339();
    let lease_expires = (now + chrono::Duration::minutes(5)).to_rfc3339();
    let exec_id = uuid::Uuid::new_v4().to_string();

    let tx = conn.transaction()?;
    let claimed = tx.execute(
        "UPDATE requests
         SET status = 'running', updated_at = ?1
         WHERE id = ?2 AND status = 'dispatched'",
        rusqlite::params![now_rfc3339, request_id],
    )?;
    if claimed == 0 {
        tx.rollback()?;
        return Ok(None);
    }
    tx.execute(
        "INSERT INTO agent_executions (id, request_id, agent_id, status, execution_token_json, lease_expires_at, started_at, created_at)
         VALUES (?1, ?2, ?3, 'claimed', ?4, ?5, ?6, ?6)",
        rusqlite::params![exec_id, request_id, agent_id, execution_token_json, lease_expires, now_rfc3339],
    )?;
    tx.commit()?;
    Ok(Some(exec_id))
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
#[allow(clippy::too_many_arguments)]
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

    let tx = conn.transaction()?;
    let current_request_status: String = tx.query_row(
        "SELECT status FROM requests WHERE id = ?1",
        rusqlite::params![request_id],
        |row| row.get(0),
    )?;
    let req_status = if current_request_status == "cancelled" {
        "cancelled"
    } else if success {
        "executed"
    } else {
        "failed"
    };
    tx.execute(
        "UPDATE agent_executions SET status = ?1, finished_at = ?2, error_message = ?3 WHERE id = ?4",
        rusqlite::params![exec_status, now, error_msg, execution_id],
    )?;
    if current_request_status != "cancelled" {
        tx.execute(
            "UPDATE requests SET status = ?1, updated_at = ?2, resolved_at = ?2 WHERE id = ?3",
            rusqlite::params![req_status, now, request_id],
        )?;
    }
    tx.commit()?;
    Ok(req_status.to_string())
}
