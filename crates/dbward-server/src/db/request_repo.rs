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
    pub share_with_json: Option<&'a str>,
}

// --- ID resolution ---

/// Resolve a request ID: accepts exactly 8-char short ID or full UUID (36 chars).
/// Short ID uses prefix match. Returns error if 0 or 2+ matches.
pub fn resolve_request_id(conn: &Connection, input: &str) -> Result<String, ResolveError> {
    if let Ok(uuid) = uuid::Uuid::parse_str(input) {
        return Ok(uuid.hyphenated().to_string());
    }
    if input.len() != 8 || !input.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ResolveError::InvalidFormat);
    }
    let prefix = input.to_ascii_lowercase();
    let mut stmt = conn
        .prepare("SELECT id FROM requests WHERE substr(id, 1, 8) = ?1 LIMIT 2")
        .map_err(|e| ResolveError::Db(e.to_string()))?;
    let ids: Vec<String> = stmt
        .query_map(rusqlite::params![prefix], |row| row.get(0))
        .map_err(|e| ResolveError::Db(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ResolveError::Db(e.to_string()))?;
    match ids.len() {
        0 => Err(ResolveError::NotFound),
        1 => Ok(ids.into_iter().next().unwrap()),
        _ => Err(ResolveError::Ambiguous(ids)),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    NotFound,
    Ambiguous(Vec<String>),
    InvalidFormat,
    Db(String),
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
pub fn insert_request(
    conn: &Connection,
    req: &NewRequest,
    now: &str,
) -> Result<(), rusqlite::Error> {
    conn.execute(
        "INSERT INTO requests (id, created_by, operation, environment, database_name, detail, status, created_at, updated_at, emergency, reason, workflow_id, workflow_snapshot_json, share_with_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        rusqlite::params![req.id, req.created_by, req.operation, req.environment, req.database_name, req.detail, req.status, now, now, req.emergency, req.reason, req.workflow_id, req.workflow_snapshot_json, req.share_with_json],
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_conn() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        crate::db::init(&conn).unwrap();
        conn
    }

    fn insert_request(conn: &Connection, id: &str) {
        conn.execute(
            "INSERT INTO requests (id, created_by, operation, environment, database_name, status, detail, created_at, updated_at)
             VALUES (?1, 'alice', 'execute_query', 'development', 'app', 'pending', 'SELECT 1', 't1', 't1')",
            rusqlite::params![id],
        )
        .unwrap();
    }

    #[test]
    fn resolves_full_uuid_and_normalizes_case() {
        let conn = test_conn();
        let id = "550e8400-e29b-41d4-a716-446655440000";
        insert_request(&conn, id);

        let resolved = resolve_request_id(&conn, "550E8400-E29B-41D4-A716-446655440000").unwrap();

        assert_eq!(resolved, id);
    }

    #[test]
    fn resolves_short_id_case_insensitively() {
        let conn = test_conn();
        let id = "deadbeef-e29b-41d4-a716-446655440000";
        insert_request(&conn, id);

        let resolved = resolve_request_id(&conn, "DEADBEEF").unwrap();

        assert_eq!(resolved, id);
    }

    #[test]
    fn rejects_invalid_formats_before_querying() {
        let conn = test_conn();

        assert_eq!(
            resolve_request_id(&conn, "deadbeez").unwrap_err(),
            ResolveError::InvalidFormat
        );
        assert_eq!(
            resolve_request_id(&conn, "deadbee%").unwrap_err(),
            ResolveError::InvalidFormat
        );
        assert_eq!(
            resolve_request_id(&conn, "550e8400-e29b-41d4-a716-44665544000z").unwrap_err(),
            ResolveError::InvalidFormat
        );
    }

    #[test]
    fn reports_ambiguous_short_ids() {
        let conn = test_conn();
        let first = "cafebabe-e29b-41d4-a716-446655440000";
        let second = "cafebabe-e29b-41d4-a716-446655440001";
        insert_request(&conn, first);
        insert_request(&conn, second);

        let err = resolve_request_id(&conn, "cafebabe").unwrap_err();

        assert_eq!(
            err,
            ResolveError::Ambiguous(vec![first.to_string(), second.to_string()])
        );
    }
}
