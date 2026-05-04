use rusqlite::Connection;

/// Reset dispatched/running requests back to approved on server restart.
pub(super) fn recover_in_flight_requests(conn: &Connection) -> Result<(), rusqlite::Error> {
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute_batch("BEGIN")?;
    conn.execute(
        "UPDATE requests
         SET status = 'approved', updated_at = ?1
         WHERE status IN ('dispatched', 'running')",
        rusqlite::params![now],
    )?;
    conn.execute(
        "UPDATE agent_executions
         SET status = 'failed', finished_at = ?1, error_message = COALESCE(error_message, 'server restarted before result relay completed')
         WHERE status = 'claimed'",
        rusqlite::params![now],
    )?;
    conn.execute_batch("COMMIT")?;
    Ok(())
}

/// Purge old completed requests and audit logs based on TTL.
pub fn purge_old_records(
    conn: &Connection,
    request_ttl_days: u32,
    audit_ttl_days: u32,
) -> Result<(usize, usize), rusqlite::Error> {
    let req_cutoff =
        (chrono::Utc::now() - chrono::Duration::days(request_ttl_days as i64)).to_rfc3339();
    let audit_cutoff =
        (chrono::Utc::now() - chrono::Duration::days(audit_ttl_days as i64)).to_rfc3339();

    conn.execute(
        "DELETE FROM approvals WHERE request_id IN (SELECT id FROM requests WHERE created_at < ?1 AND status IN ('executed', 'failed', 'rejected'))",
        rusqlite::params![req_cutoff],
    )?;
    conn.execute(
        "DELETE FROM agent_executions WHERE request_id IN (SELECT id FROM requests WHERE created_at < ?1 AND status IN ('executed', 'failed', 'rejected'))",
        rusqlite::params![req_cutoff],
    )?;
    let req_deleted = conn.execute(
        "DELETE FROM requests WHERE created_at < ?1 AND status IN ('executed', 'failed', 'rejected')",
        rusqlite::params![req_cutoff],
    )?;
    let audit_deleted = conn.execute(
        "DELETE FROM audit_log WHERE created_at < ?1",
        rusqlite::params![audit_cutoff],
    )?;
    Ok((req_deleted, audit_deleted))
}

/// Reclaim expired leases: reset running→approved so client can re-dispatch.
pub fn reclaim_expired_leases(conn: &Connection) -> Result<usize, rusqlite::Error> {
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute_batch("BEGIN")?;
    let count = conn.execute(
        "UPDATE requests SET status = 'approved', updated_at = ?1
         WHERE status = 'running' AND id IN (
           SELECT request_id FROM agent_executions
           WHERE status = 'claimed' AND lease_expires_at < ?1
         )",
        rusqlite::params![now],
    )?;
    conn.execute(
        "UPDATE agent_executions SET status = 'failed', finished_at = ?1,
         error_message = 'lease expired'
         WHERE status = 'claimed' AND lease_expires_at < ?1",
        rusqlite::params![now],
    )?;
    conn.execute_batch("COMMIT")?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    #[test]
    fn purge_old_records_deletes_expired() {
        let conn = Connection::open_in_memory().unwrap();
        db::init(&conn).unwrap();

        let old = "2020-01-01T00:00:00+00:00";
        let recent = chrono::Utc::now().to_rfc3339();

        conn.execute(
            "INSERT INTO requests (id, created_by, operation, environment, database_name, status, detail, created_at, updated_at)
             VALUES ('old-1', 'alice', 'execute_query', 'dev', 'app', 'executed', 'SELECT 1', ?1, ?1)",
            rusqlite::params![old],
        ).unwrap();
        conn.execute(
            "INSERT INTO approvals (id, request_id, action, actor_id, created_at)
             VALUES ('apr-1', 'old-1', 'approve', 'bob', ?1)",
            rusqlite::params![old],
        ).unwrap();
        conn.execute(
            "INSERT INTO requests (id, created_by, operation, environment, database_name, status, detail, created_at, updated_at)
             VALUES ('new-1', 'alice', 'execute_query', 'dev', 'app', 'executed', 'SELECT 1', ?1, ?1)",
            rusqlite::params![recent],
        ).unwrap();
        conn.execute(
            "INSERT INTO requests (id, created_by, operation, environment, database_name, status, detail, created_at, updated_at)
             VALUES ('old-2', 'alice', 'execute_query', 'dev', 'app', 'pending', 'SELECT 1', ?1, ?1)",
            rusqlite::params![old],
        ).unwrap();
        conn.execute(
            "INSERT INTO audit_log (id, actor_id, operation, environment, database_name, detail, status, created_at)
             VALUES ('aud-1', 'alice', 'execute_query', 'dev', 'app', 'SELECT 1', 'ok', ?1)",
            rusqlite::params![old],
        ).unwrap();
        conn.execute(
            "INSERT INTO audit_log (id, actor_id, operation, environment, database_name, detail, status, created_at)
             VALUES ('aud-2', 'alice', 'execute_query', 'dev', 'app', 'SELECT 1', 'ok', ?1)",
            rusqlite::params![recent],
        ).unwrap();

        let (req_del, audit_del) = purge_old_records(&conn, 90, 365).unwrap();
        assert_eq!(req_del, 1);
        assert_eq!(audit_del, 1);

        let req_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM requests", [], |r| r.get(0))
            .unwrap();
        assert_eq!(req_count, 2);
        let apr_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM approvals", [], |r| r.get(0))
            .unwrap();
        assert_eq!(apr_count, 0);
        let aud_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM audit_log", [], |r| r.get(0))
            .unwrap();
        assert_eq!(aud_count, 1);
    }
}
