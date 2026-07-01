use rusqlite::OptionalExtension;
use rusqlite::params;

use dbward_app::error::AppError;
use dbward_app::ports::repos::{PreflightJob, PreflightJobRepo};

use crate::sqlite::DbConn;
use crate::sqlite::error::db_err;

pub struct SqlitePreflightJobRepo {
    conn: DbConn,
}

impl SqlitePreflightJobRepo {
    pub fn new(conn: DbConn) -> Self {
        Self { conn }
    }
}

impl PreflightJobRepo for SqlitePreflightJobRepo {
    fn create_with_limit(&self, job: &PreflightJob, max_concurrent: u32) -> Result<(), AppError> {
        let conn = self.conn.lock();
        // Atomic: INSERT only if user has fewer than max_concurrent active jobs
        let rows = conn
            .execute(
                "INSERT INTO preflight_jobs (id, user_id, database_name, environment, sql_text, status, created_at, expires_at)
                 SELECT ?1, ?2, ?3, ?4, ?5, 'pending', ?6, ?7
                 WHERE (SELECT COUNT(*) FROM preflight_jobs WHERE user_id = ?2 AND status IN ('pending', 'claimed')) < ?8",
                params![
                    job.id,
                    job.user_id,
                    job.database_name,
                    job.environment,
                    job.sql_text,
                    job.created_at,
                    job.expires_at,
                    max_concurrent,
                ],
            )
            .map_err(db_err("preflight: create_with_limit"))?;

        if rows == 0 {
            return Err(AppError::RateLimited(
                "concurrent preflight limit exceeded".into(),
            ));
        }
        Ok(())
    }

    fn claim_for_agent(
        &self,
        agent_id: &str,
        scopes: &[(String, String)],
        limit: usize,
    ) -> Result<Vec<PreflightJob>, AppError> {
        if scopes.is_empty() || limit == 0 {
            return Ok(vec![]);
        }
        let conn = self.conn.lock();

        let claim_token = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();

        // Build parameterized scope conditions to prevent SQL injection
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = vec![
            Box::new(agent_id.to_string()),
            Box::new(claim_token.clone()),
            Box::new(now.clone()),
            Box::new(limit as u32),
        ];
        let scope_conditions: Vec<String> = scopes
            .iter()
            .enumerate()
            .map(|(i, (db, env))| {
                let base = 5 + i * 2;
                params.push(Box::new(db.clone()));
                params.push(Box::new(env.clone()));
                format!(
                    "(database_name = ?{} AND environment = ?{})",
                    base,
                    base + 1
                )
            })
            .collect();
        let scope_filter = scope_conditions.join(" OR ");

        // Atomic claim: UPDATE pending jobs that match scopes and aren't expired
        let sql = format!(
            "UPDATE preflight_jobs SET status = 'claimed', claimed_by = ?1, claim_token = ?2
             WHERE id IN (
                 SELECT id FROM preflight_jobs
                 WHERE status = 'pending' AND expires_at > ?3 AND ({scope_filter})
                 LIMIT ?4
             )
             RETURNING id, user_id, database_name, environment, sql_text, status, claimed_by, claim_token, result_json, error_message, created_at, expires_at, completed_at"
        );

        let params_ref: Vec<&dyn rusqlite::types::ToSql> =
            params.iter().map(|p| p.as_ref()).collect();
        let mut stmt = conn
            .prepare(&sql)
            .map_err(db_err("preflight: claim_for_agent prepare"))?;

        let jobs = stmt
            .query_map(params_ref.as_slice(), |row| {
                Ok(PreflightJob {
                    id: row.get(0)?,
                    user_id: row.get(1)?,
                    database_name: row.get(2)?,
                    environment: row.get(3)?,
                    sql_text: row.get(4)?,
                    status: row.get(5)?,
                    claimed_by: row.get(6)?,
                    claim_token: row.get(7)?,
                    result_json: row.get(8)?,
                    error_message: row.get(9)?,
                    created_at: row.get(10)?,
                    expires_at: row.get(11)?,
                    completed_at: row.get(12)?,
                })
            })
            .map_err(db_err("preflight: claim_for_agent query"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err("preflight: claim_for_agent collect"))?;

        Ok(jobs)
    }

    fn complete(
        &self,
        job_id: &str,
        agent_id: &str,
        claim_token: &str,
        result_json: &str,
        now: &str,
    ) -> Result<bool, AppError> {
        let conn = self.conn.lock();
        let rows = conn
            .execute(
                "UPDATE preflight_jobs SET status = 'completed', result_json = ?1, completed_at = ?2
                 WHERE id = ?3 AND claimed_by = ?4 AND claim_token = ?5 AND status = 'claimed'",
                params![result_json, now, job_id, agent_id, claim_token],
            )
            .map_err(db_err("preflight: complete"))?;
        Ok(rows > 0)
    }

    fn fail(
        &self,
        job_id: &str,
        agent_id: &str,
        claim_token: &str,
        error: &str,
        now: &str,
    ) -> Result<bool, AppError> {
        let conn = self.conn.lock();
        let rows = conn
            .execute(
                "UPDATE preflight_jobs SET status = 'error', error_message = ?1, completed_at = ?2
                 WHERE id = ?3 AND claimed_by = ?4 AND claim_token = ?5 AND status = 'claimed'",
                params![error, now, job_id, agent_id, claim_token],
            )
            .map_err(db_err("preflight: fail"))?;
        Ok(rows > 0)
    }

    fn get(&self, job_id: &str) -> Result<Option<PreflightJob>, AppError> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare(
                "SELECT id, user_id, database_name, environment, sql_text, status, claimed_by, claim_token, result_json, error_message, created_at, expires_at, completed_at
                 FROM preflight_jobs WHERE id = ?1",
            )
            .map_err(db_err("preflight: get prepare"))?;

        let job = stmt
            .query_row(params![job_id], |row| {
                Ok(PreflightJob {
                    id: row.get(0)?,
                    user_id: row.get(1)?,
                    database_name: row.get(2)?,
                    environment: row.get(3)?,
                    sql_text: row.get(4)?,
                    status: row.get(5)?,
                    claimed_by: row.get(6)?,
                    claim_token: row.get(7)?,
                    result_json: row.get(8)?,
                    error_message: row.get(9)?,
                    created_at: row.get(10)?,
                    expires_at: row.get(11)?,
                    completed_at: row.get(12)?,
                })
            })
            .optional()
            .map_err(db_err("preflight: get query"))?;

        Ok(job)
    }

    fn mark_expired_by_id(&self, job_id: &str) -> Result<bool, AppError> {
        let conn = self.conn.lock();
        let rows = conn
            .execute(
                "UPDATE preflight_jobs SET status = 'expired'
                 WHERE id = ?1 AND status IN ('pending', 'claimed')",
                params![job_id],
            )
            .map_err(db_err("preflight: mark_expired_by_id"))?;
        Ok(rows > 0)
    }

    fn mark_expired(&self) -> Result<u64, AppError> {
        let conn = self.conn.lock();
        let now = chrono::Utc::now().to_rfc3339();
        let rows = conn
            .execute(
                "UPDATE preflight_jobs SET status = 'expired'
                 WHERE status IN ('pending', 'claimed') AND expires_at <= ?1",
                params![now],
            )
            .map_err(db_err("preflight: mark_expired"))?;
        Ok(rows as u64)
    }

    fn purge_old(&self, retention_secs: u64) -> Result<u64, AppError> {
        let conn = self.conn.lock();
        let cutoff =
            (chrono::Utc::now() - chrono::Duration::seconds(retention_secs as i64)).to_rfc3339();
        let rows = conn
            .execute(
                "DELETE FROM preflight_jobs
                 WHERE (status = 'completed' AND completed_at <= ?1)
                    OR (status IN ('expired', 'error') AND created_at <= ?1)",
                params![cutoff],
            )
            .map_err(db_err("preflight: purge_old"))?;
        Ok(rows as u64)
    }
}
