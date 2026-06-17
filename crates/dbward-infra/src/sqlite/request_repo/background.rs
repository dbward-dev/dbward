use rusqlite::params;

use dbward_app::error::AppError;
use dbward_app::ports::BackgroundTaskRepo;

use super::SqliteRequestRepo;
use crate::sqlite::error::db_err;

impl BackgroundTaskRepo for SqliteRequestRepo {
    fn find_expired_approved(&self, now: &str) -> Result<Vec<String>, AppError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id FROM requests WHERE status = 'approved' \
             AND resolved_at IS NOT NULL \
             AND datetime(resolved_at, '+' || COALESCE(json_extract(workflow_snapshot_json, '$.approval_ttl_secs'), 86400) || ' seconds') < datetime(?1)"
        ).map_err(db_err("request: find_expired_approved"))?;
        let rows = stmt
            .query_map(params![now], |row| row.get(0))
            .map_err(db_err("request: find_expired_approved"))?;
        rows.collect::<Result<Vec<String>, _>>()
            .map_err(db_err("request: find_expired_approved"))
    }
    fn find_expired_pending(&self, now: &str) -> Result<Vec<String>, AppError> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare(
                "SELECT id FROM requests WHERE status = 'pending' \
             AND expires_at IS NOT NULL \
             AND datetime(expires_at) < datetime(?1)",
            )
            .map_err(db_err("request: find_expired_pending"))?;
        let rows = stmt
            .query_map(params![now], |row| row.get(0))
            .map_err(db_err("request: find_expired_pending"))?;
        rows.collect::<Result<Vec<String>, _>>()
            .map_err(db_err("request: find_expired_pending"))
    }
    fn find_dispatched_older_than(&self, cutoff: &str) -> Result<Vec<String>, AppError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id FROM requests WHERE status = 'dispatched' AND datetime(updated_at) < datetime(?1)"
        ).map_err(db_err("request: find_dispatched_older_than"))?;
        let rows = stmt
            .query_map(params![cutoff], |row| row.get(0))
            .map_err(db_err("request: find_dispatched_older_than"))?;
        rows.collect::<Result<Vec<String>, _>>()
            .map_err(db_err("request: find_dispatched_older_than"))
    }
    fn mark_expired(&self, id: &str, now: &str) -> Result<bool, AppError> {
        let conn = self.conn.lock();
        let n = conn.execute(
            "UPDATE requests SET status = 'expired', updated_at = ?2 WHERE id = ?1 AND status IN ('approved', 'pending')",
            params![id, now],
        ).map_err(db_err("request: mark_expired"))?;
        Ok(n > 0)
    }
    fn purge_old_requests(&self, before: &str) -> Result<u32, AppError> {
        let mut conn = self.conn.lock();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(db_err("request: purge_old_requests"))?;
        let subquery = "SELECT id FROM requests WHERE status IN ('executed', 'failed', 'rejected', 'expired', 'cancelled') AND updated_at < ?1";
        // Delete FK children in safe order
        tx.execute(
            &format!("DELETE FROM result_access WHERE result_id IN (SELECT id FROM results WHERE request_id IN ({subquery}))"),
            params![before],
        ).map_err(db_err("request: purge_old_requests"))?;
        tx.execute(
            &format!("DELETE FROM results WHERE request_id IN ({subquery})"),
            params![before],
        )
        .map_err(db_err("request: purge_old_requests"))?;
        tx.execute(
            &format!("DELETE FROM executions WHERE request_id IN ({subquery})"),
            params![before],
        )
        .map_err(db_err("request: purge_old_requests"))?;
        tx.execute(
            &format!("DELETE FROM approvals WHERE request_id IN ({subquery})"),
            params![before],
        )
        .map_err(db_err("request: purge_old_requests"))?;
        tx.execute(
            &format!("DELETE FROM request_pending_approvers WHERE request_id IN ({subquery})"),
            params![before],
        )
        .map_err(db_err("request: purge_old_requests"))?;
        tx.execute(
            &format!("DELETE FROM dry_run_jobs WHERE request_id IN ({subquery})"),
            params![before],
        )
        .map_err(db_err("request: purge_old_requests"))?;
        tx.execute(
            &format!("DELETE FROM request_context WHERE request_id IN ({subquery})"),
            params![before],
        )
        .map_err(db_err("request: purge_old_requests"))?;
        tx.execute(
            &format!("DELETE FROM slack_messages WHERE request_id IN ({subquery})"),
            params![before],
        )
        .map_err(db_err("request: purge_old_requests"))?;
        let n = tx
            .execute(
                &format!("DELETE FROM requests WHERE id IN ({subquery})"),
                params![before],
            )
            .map_err(db_err("request: purge_old_requests"))?;
        tx.commit().map_err(db_err("request: purge_old_requests"))?;
        Ok(n as u32)
    }
}
