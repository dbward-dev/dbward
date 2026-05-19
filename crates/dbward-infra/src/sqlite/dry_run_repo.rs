use rusqlite::params;

use dbward_app::error::AppError;
use dbward_app::ports::repos::{DryRunJobRecord, DryRunRepo};

use crate::sqlite::DbConn;

pub struct SqliteDryRunRepo {
    conn: DbConn,
}

impl SqliteDryRunRepo {
    pub fn new(conn: DbConn) -> Self {
        Self { conn }
    }
}

impl DryRunRepo for SqliteDryRunRepo {
    fn create_jobs(&self, jobs: &[DryRunJobRecord]) -> Result<(), AppError> {
        let conn = self.conn.lock().unwrap();
        for job in jobs {
            conn.execute(
                "INSERT INTO dry_run_jobs (id, request_id, database_name, environment, sql_text, status, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, 'pending', ?6)",
                params![job.id, job.request_id, job.database_name, job.environment, job.sql_text, job.created_at],
            )
            .map_err(|e| AppError::Internal(e.to_string()))?;
        }
        Ok(())
    }

    fn find_pending_for_agent(
        &self,
        databases: &[(String, String)],
    ) -> Result<Vec<DryRunJobRecord>, AppError> {
        if databases.is_empty() {
            return Ok(vec![]);
        }
        let conn = self.conn.lock().unwrap();
        // Build WHERE clause for (database_name, environment) pairs
        let conditions: Vec<String> = databases
            .iter()
            .map(|(db, env)| {
                format!(
                    "(database_name = '{}' AND environment = '{}')",
                    db.replace('\'', "''"),
                    env.replace('\'', "''")
                )
            })
            .collect();
        let sql = format!(
            "SELECT id, request_id, database_name, environment, sql_text, status, \
             claimed_by, claimed_at, claim_token, result_json, error_message, created_at, completed_at \
             FROM dry_run_jobs WHERE status = 'pending' AND ({}) LIMIT 10",
            conditions.join(" OR ")
        );
        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(DryRunJobRecord {
                    id: row.get(0)?,
                    request_id: row.get(1)?,
                    database_name: row.get(2)?,
                    environment: row.get(3)?,
                    sql_text: row.get(4)?,
                    status: row.get(5)?,
                    claimed_by: row.get(6)?,
                    claimed_at: row.get(7)?,
                    claim_token: row.get(8)?,
                    result_json: row.get(9)?,
                    error_message: row.get(10)?,
                    created_at: row.get(11)?,
                    completed_at: row.get(12)?,
                })
            })
            .map_err(|e| AppError::Internal(e.to_string()))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| AppError::Internal(e.to_string()))
    }

    fn claim(
        &self,
        job_id: &str,
        agent_id: &str,
        claim_token: &str,
        now: &str,
    ) -> Result<bool, AppError> {
        let conn = self.conn.lock().unwrap();
        let affected = conn.execute(
            "UPDATE dry_run_jobs SET status = 'claimed', claimed_by = ?1, claimed_at = ?2, claim_token = ?3 \
             WHERE id = ?4 AND status = 'pending'",
            params![agent_id, now, claim_token, job_id],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(affected > 0)
    }

    fn complete(
        &self,
        job_id: &str,
        agent_id: &str,
        claim_token: &str,
        result_json: &str,
        now: &str,
    ) -> Result<bool, AppError> {
        let conn = self.conn.lock().unwrap();
        let affected = conn
            .execute(
                "UPDATE dry_run_jobs SET status = 'completed', result_json = ?1, completed_at = ?2 \
             WHERE id = ?3 AND claimed_by = ?4 AND claim_token = ?5 AND status = 'claimed'",
                params![result_json, now, job_id, agent_id, claim_token],
            )
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(affected > 0)
    }

    fn fail(
        &self,
        job_id: &str,
        agent_id: &str,
        claim_token: &str,
        error: &str,
        now: &str,
    ) -> Result<bool, AppError> {
        let conn = self.conn.lock().unwrap();
        let affected = conn
            .execute(
                "UPDATE dry_run_jobs SET status = 'failed', error_message = ?1, completed_at = ?2 \
             WHERE id = ?3 AND claimed_by = ?4 AND claim_token = ?5 AND status = 'claimed'",
                params![error, now, job_id, agent_id, claim_token],
            )
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(affected > 0)
    }

    fn reclaim_stale(&self, cutoff: &str) -> Result<u32, AppError> {
        let conn = self.conn.lock().unwrap();
        let affected = conn.execute(
            "UPDATE dry_run_jobs SET status = 'pending', claimed_by = NULL, claimed_at = NULL, claim_token = NULL \
             WHERE status = 'claimed' AND claimed_at < ?1",
            params![cutoff],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(affected as u32)
    }

    fn find_for_request(&self, request_id: &str) -> Result<Vec<DryRunJobRecord>, AppError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, request_id, database_name, environment, sql_text, status, \
             claimed_by, claimed_at, claim_token, result_json, error_message, created_at, completed_at \
             FROM dry_run_jobs WHERE request_id = ?1",
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;
        let rows = stmt
            .query_map(params![request_id], |row| {
                Ok(DryRunJobRecord {
                    id: row.get(0)?,
                    request_id: row.get(1)?,
                    database_name: row.get(2)?,
                    environment: row.get(3)?,
                    sql_text: row.get(4)?,
                    status: row.get(5)?,
                    claimed_by: row.get(6)?,
                    claimed_at: row.get(7)?,
                    claim_token: row.get(8)?,
                    result_json: row.get(9)?,
                    error_message: row.get(10)?,
                    created_at: row.get(11)?,
                    completed_at: row.get(12)?,
                })
            })
            .map_err(|e| AppError::Internal(e.to_string()))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| AppError::Internal(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite::open_memory;
    use crate::sqlite::schema::initialize;

    fn setup() -> DbConn {
        let conn = open_memory().unwrap();
        {
            let c = conn.lock().unwrap();
            initialize(&c).unwrap();
            // Disable FK for test isolation (initialize enables it)
            c.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
            for id in ["req-1", "req-2", "req-3"] {
                c.execute(
                    "INSERT INTO requests (id, requester, operation, database_id, detail, status, created_at, updated_at) \
                     VALUES (?1, 'test', 'execute_query', 'db-1', 'SELECT 1', 'pending', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
                    rusqlite::params![id],
                ).unwrap();
            }
        }
        conn
    }

    #[test]
    fn create_and_find_pending() {
        let conn = setup();
        let repo = SqliteDryRunRepo::new(conn);
        let job = DryRunJobRecord {
            id: "job-1".into(),
            request_id: "req-1".into(),
            database_name: "app".into(),
            environment: "production".into(),
            sql_text: "SELECT 1".into(),
            status: "pending".into(),
            claimed_by: None,
            claimed_at: None,
            claim_token: None,
            result_json: None,
            error_message: None,
            created_at: "2026-01-01T00:00:00Z".into(),
            completed_at: None,
        };
        repo.create_jobs(&[job]).unwrap();
        let pending = repo
            .find_pending_for_agent(&[("app".into(), "production".into())])
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, "job-1");
    }

    #[test]
    fn claim_and_complete() {
        let conn = setup();
        let repo = SqliteDryRunRepo::new(conn);
        let job = DryRunJobRecord {
            id: "job-2".into(),
            request_id: "req-2".into(),
            database_name: "app".into(),
            environment: "prod".into(),
            sql_text: "SELECT 1".into(),
            status: "pending".into(),
            claimed_by: None,
            claimed_at: None,
            claim_token: None,
            result_json: None,
            error_message: None,
            created_at: "2026-01-01T00:00:00Z".into(),
            completed_at: None,
        };
        repo.create_jobs(&[job]).unwrap();
        assert!(
            repo.claim("job-2", "agent-1", "token-abc", "2026-01-01T00:01:00Z")
                .unwrap()
        );
        // Double claim fails
        assert!(
            !repo
                .claim("job-2", "agent-2", "token-def", "2026-01-01T00:02:00Z")
                .unwrap()
        );
        // Complete with correct token
        assert!(
            repo.complete(
                "job-2",
                "agent-1",
                "token-abc",
                "{}",
                "2026-01-01T00:03:00Z"
            )
            .unwrap()
        );
        // Complete again fails (fencing)
        assert!(
            !repo
                .complete(
                    "job-2",
                    "agent-1",
                    "token-abc",
                    "{}",
                    "2026-01-01T00:04:00Z"
                )
                .unwrap()
        );
    }

    #[test]
    fn reclaim_stale() {
        let conn = setup();
        let repo = SqliteDryRunRepo::new(conn);
        let job = DryRunJobRecord {
            id: "job-3".into(),
            request_id: "req-3".into(),
            database_name: "app".into(),
            environment: "prod".into(),
            sql_text: "SELECT 1".into(),
            status: "pending".into(),
            claimed_by: None,
            claimed_at: None,
            claim_token: None,
            result_json: None,
            error_message: None,
            created_at: "2026-01-01T00:00:00Z".into(),
            completed_at: None,
        };
        repo.create_jobs(&[job]).unwrap();
        repo.claim("job-3", "agent-1", "tok", "2026-01-01T00:00:00Z")
            .unwrap();
        let reclaimed = repo.reclaim_stale("2026-01-01T00:01:01Z").unwrap();
        assert_eq!(reclaimed, 1);
        // Now it's pending again
        let pending = repo
            .find_pending_for_agent(&[("app".into(), "prod".into())])
            .unwrap();
        assert_eq!(pending.len(), 1);
    }
}
