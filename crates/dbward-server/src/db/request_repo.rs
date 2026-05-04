use rusqlite::Connection;
use std::ops::Deref;

// --- Row types ---

/// Minimal request info for approve/reject/dispatch context loading.
pub struct RequestContext {
    pub created_by: String,
    pub status: String,
    pub operation: String,
    pub environment: String,
    pub database_name: String,
    pub detail: String,
    pub workflow_snapshot_json: Option<String>,
    pub resolved_at: Option<String>,
}

/// New request to insert.
pub struct NewRequest<'a> {
    pub id: &'a str,
    pub created_by: &'a str,
    pub operation: &'a str,
    pub environment: &'a str,
    pub database_name: &'a str,
    pub detail: &'a str,
    pub status: &'a str,
    pub emergency: bool,
    pub reason: Option<&'a str>,
    pub workflow_id: Option<&'a str>,
    pub workflow_snapshot_json: Option<&'a str>,
}

// --- Reads ---

/// Load request context for approve/reject/dispatch/claim.
pub fn get_request_context(conn: &Connection, id: &str) -> Result<RequestContext, rusqlite::Error> {
    conn.query_row(
        "SELECT created_by, status, operation, environment, database_name, detail, workflow_snapshot_json, resolved_at FROM requests WHERE id = ?1",
        rusqlite::params![id],
        |row| Ok(RequestContext {
            created_by: row.get(0)?,
            status: row.get(1)?,
            operation: row.get(2)?,
            environment: row.get(3)?,
            database_name: row.get(4)?,
            detail: row.get(5)?,
            workflow_snapshot_json: row.get(6)?,
            resolved_at: row.get(7)?,
        }),
    )
}

/// Get approvals for a request (step_index, actor_id, actor_role).
pub fn get_approvals(
    conn: &Connection,
    request_id: &str,
) -> Result<Vec<(i64, String, String)>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT step_index, actor_id, actor_role FROM approvals WHERE request_id = ?1 AND action = 'approve'",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![request_id], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Count agent executions for a request.
pub fn count_executions(conn: &Connection, request_id: &str) -> u32 {
    conn.query_row(
        "SELECT COUNT(*) FROM agent_executions WHERE request_id = ?1",
        rusqlite::params![request_id],
        |row| row.get(0),
    )
    .unwrap_or(0)
}

// --- Writes ---

/// Insert a new request.
pub fn insert_request(conn: &Connection, req: &NewRequest, now: &str) -> Result<(), rusqlite::Error> {
    conn.execute(
        "INSERT INTO requests (id, created_by, operation, environment, database_name, detail, status, created_at, updated_at, emergency, reason, workflow_id, workflow_snapshot_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        rusqlite::params![req.id, req.created_by, req.operation, req.environment, req.database_name, req.detail, req.status, now, now, req.emergency, req.reason, req.workflow_id, req.workflow_snapshot_json],
    )?;
    Ok(())
}

/// Insert an approval record.
pub fn insert_approval<C>(
    conn: &C,
    request_id: &str,
    action: &str,
    actor_id: &str,
    step_index: i64,
    actor_role: &str,
    now: &str,
) -> Result<(), rusqlite::Error>
where
    C: Deref<Target = Connection> + ?Sized,
{
    let id = uuid::Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO approvals (id, request_id, action, actor_id, step_index, actor_role, comment, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7)",
        rusqlite::params![id, request_id, action, actor_id, step_index, actor_role, now],
    )?;
    Ok(())
}

/// Mark request as approved with resolved_at.
pub fn mark_approved<C>(conn: &C, id: &str, now: &str) -> Result<(), rusqlite::Error>
where
    C: Deref<Target = Connection> + ?Sized,
{
    conn.execute(
        "UPDATE requests SET status = 'approved', updated_at = ?1, resolved_at = ?2 WHERE id = ?3",
        rusqlite::params![now, now, id],
    )?;
    Ok(())
}

/// Mark request as rejected with resolved_at.
pub fn mark_rejected<C>(conn: &C, id: &str, now: &str) -> Result<(), rusqlite::Error>
where
    C: Deref<Target = Connection> + ?Sized,
{
    conn.execute(
        "UPDATE requests SET status = 'rejected', updated_at = ?1, resolved_at = ?2 WHERE id = ?3",
        rusqlite::params![now, now, id],
    )?;
    Ok(())
}

/// Touch updated_at only.
pub fn touch_updated_at<C>(conn: &C, id: &str, now: &str) -> Result<(), rusqlite::Error>
where
    C: Deref<Target = Connection> + ?Sized,
{
    conn.execute(
        "UPDATE requests SET updated_at = ?1 WHERE id = ?2",
        rusqlite::params![now, id],
    )?;
    Ok(())
}

/// Atomically set status to dispatched. Returns true if updated.
pub fn mark_dispatched(conn: &Connection, id: &str) -> Result<bool, rusqlite::Error> {
    let now = chrono::Utc::now().to_rfc3339();
    let rows = conn.execute(
        "UPDATE requests SET status = 'dispatched', updated_at = ?1 WHERE id = ?2 AND status IN ('approved', 'auto_approved', 'break_glass', 'executed', 'failed')",
        rusqlite::params![now, id],
    )?;
    Ok(rows > 0)
}
