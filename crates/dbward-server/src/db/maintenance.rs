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
        "DELETE FROM approvals WHERE request_id IN (SELECT id FROM requests WHERE created_at < ?1 AND status IN ('executed', 'failed', 'rejected', 'cancelled', 'execution_lost'))",
        rusqlite::params![req_cutoff],
    )?;
    conn.execute(
        "DELETE FROM agent_executions WHERE request_id IN (SELECT id FROM requests WHERE created_at < ?1 AND status IN ('executed', 'failed', 'rejected', 'cancelled', 'execution_lost'))",
        rusqlite::params![req_cutoff],
    )?;
    let req_deleted = conn.execute(
        "DELETE FROM requests WHERE created_at < ?1 AND status IN ('executed', 'failed', 'rejected', 'cancelled', 'execution_lost')",
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
    // Mark as execution_lost instead of re-dispatching (prevents duplicate execution)
    let count = conn.execute(
        "UPDATE requests SET status = 'execution_lost', updated_at = ?1
         WHERE status = 'running' AND id IN (
           SELECT request_id FROM agent_executions
           WHERE status = 'claimed' AND lease_expires_at < ?1
         )",
        rusqlite::params![now],
    )?;
    conn.execute(
        "UPDATE agent_executions SET status = 'lost', finished_at = ?1,
         error_message = 'lease expired, execution outcome unknown'
         WHERE status = 'claimed' AND lease_expires_at < ?1",
        rusqlite::params![now],
    )?;
    conn.execute_batch("COMMIT")?;
    Ok(count)
}

/// Purge expired results: delete from storage and DB.
/// Returns list of request_ids whose storage objects should be deleted.
#[allow(dead_code)]
pub fn collect_expired_results(
    conn: &Connection,
) -> Result<Vec<(String, String)>, rusqlite::Error> {
    let now = chrono::Utc::now().to_rfc3339();
    let mut stmt = conn.prepare(
        "SELECT request_id, storage_key FROM request_results WHERE expires_at < ?1 AND status = 'stored'",
    )?;
    let rows: Vec<(String, String)> = stmt
        .query_map(rusqlite::params![now], |row| Ok((row.get(0)?, row.get(1)?)))?
        .filter_map(|r| r.ok())
        .collect();
    Ok(rows)
}

/// Remove DB records for expired results (call after storage deletion).
#[allow(dead_code)]
pub fn delete_expired_result_records(
    conn: &Connection,
    request_id: &str,
) -> Result<(), rusqlite::Error> {
    conn.execute(
        "DELETE FROM result_access WHERE request_id = ?1",
        rusqlite::params![request_id],
    )?;
    conn.execute(
        "DELETE FROM request_results WHERE request_id = ?1",
        rusqlite::params![request_id],
    )?;
    Ok(())
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
             VALUES ('old-1', 'alice', 'execute_query', 'dev', 'app', 'cancelled', 'SELECT 1', ?1, ?1)",
            rusqlite::params![old],
        ).unwrap();
        conn.execute(
            "INSERT INTO approvals (id, request_id, action, actor_id, created_at)
             VALUES ('apr-1', 'old-1', 'approve', 'bob', ?1)",
            rusqlite::params![old],
        )
        .unwrap();
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

    #[test]
    fn reclaim_expired_leases_marks_execution_lost() {
        let conn = Connection::open_in_memory().unwrap();
        db::init(&conn).unwrap();

        let now = chrono::Utc::now().to_rfc3339();
        let expired = (chrono::Utc::now() - chrono::Duration::minutes(10)).to_rfc3339();

        conn.execute(
            "INSERT INTO requests (id, created_by, operation, environment, database_name, status, detail, created_at, updated_at)
             VALUES ('req-1', 'alice', 'execute_query', 'development', 'app', 'running', 'SELECT 1', ?1, ?1)",
            rusqlite::params![now],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO agent_executions (id, request_id, agent_id, status, execution_token_json, lease_expires_at, started_at, created_at)
             VALUES ('exec-1', 'req-1', 'agent-1', 'claimed', '{}', ?1, ?2, ?2)",
            rusqlite::params![expired, now],
        )
        .unwrap();

        let reclaimed = reclaim_expired_leases(&conn).unwrap();
        assert_eq!(reclaimed, 1);

        let request_status: String = conn
            .query_row("SELECT status FROM requests WHERE id = 'req-1'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(request_status, "execution_lost");

        let (exec_status, error_message): (String, String) = conn
            .query_row(
                "SELECT status, error_message FROM agent_executions WHERE id = 'exec-1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(exec_status, "lost");
        assert_eq!(error_message, "lease expired, execution outcome unknown");
    }

    #[test]
    fn purge_old_records_deletes_execution_lost_requests() {
        let conn = Connection::open_in_memory().unwrap();
        db::init(&conn).unwrap();

        let old = "2020-01-01T00:00:00+00:00";

        conn.execute(
            "INSERT INTO requests (id, created_by, operation, environment, database_name, status, detail, created_at, updated_at)
             VALUES ('old-lost', 'alice', 'execute_query', 'development', 'app', 'execution_lost', 'SELECT 1', ?1, ?1)",
            rusqlite::params![old],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO approvals (id, request_id, action, actor_id, created_at)
             VALUES ('apr-lost', 'old-lost', 'approve', 'bob', ?1)",
            rusqlite::params![old],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO agent_executions (id, request_id, agent_id, status, execution_token_json, lease_expires_at, started_at, created_at)
             VALUES ('exec-lost', 'old-lost', 'agent-1', 'lost', '{}', ?1, ?1, ?1)",
            rusqlite::params![old],
        )
        .unwrap();

        let (req_deleted, _) = purge_old_records(&conn, 90, 365).unwrap();
        assert_eq!(req_deleted, 1);

        let request_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM requests WHERE id = 'old-lost'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let approval_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM approvals WHERE request_id = 'old-lost'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let execution_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM agent_executions WHERE request_id = 'old-lost'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(request_count, 0);
        assert_eq!(approval_count, 0);
        assert_eq!(execution_count, 0);
    }
}
