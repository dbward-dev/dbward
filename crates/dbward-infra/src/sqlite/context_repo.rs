use rusqlite::params;

use dbward_app::error::AppError;
use dbward_app::ports::repos::{ContextRepo, RequestContextRecord};

use crate::sqlite::DbConn;

pub struct SqliteContextRepo {
    conn: DbConn,
}

impl SqliteContextRepo {
    pub fn new(conn: DbConn) -> Self {
        Self { conn }
    }
}

impl ContextRepo for SqliteContextRepo {
    fn create(&self, ctx: &RequestContextRecord) -> Result<(), AppError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO request_context \
             (request_id, status, tables_json, sql_review_json, risk_json, explain_json, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                ctx.request_id,
                ctx.status,
                ctx.tables_json,
                ctx.sql_review_json,
                ctx.risk_json,
                ctx.explain_json,
                ctx.created_at,
                ctx.updated_at,
            ],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(())
    }

    fn get(&self, request_id: &str) -> Result<Option<RequestContextRecord>, AppError> {
        let conn = self.conn.lock().unwrap();
        let result = conn.query_row(
            "SELECT request_id, status, tables_json, sql_review_json, risk_json, explain_json, created_at, updated_at \
             FROM request_context WHERE request_id = ?1",
            params![request_id],
            |row| {
                Ok(RequestContextRecord {
                    request_id: row.get(0)?,
                    status: row.get(1)?,
                    tables_json: row.get(2)?,
                    sql_review_json: row.get(3)?,
                    risk_json: row.get(4)?,
                    explain_json: row.get(5)?,
                    created_at: row.get(6)?,
                    updated_at: row.get(7)?,
                })
            },
        );
        match result {
            Ok(r) => Ok(Some(r)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(AppError::Internal(e.to_string())),
        }
    }

    fn update_explain(
        &self,
        request_id: &str,
        explain_json: &str,
        status: &str,
        now: &str,
    ) -> Result<(), AppError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE request_context SET explain_json = ?1, status = ?2, updated_at = ?3 WHERE request_id = ?4",
            params![explain_json, status, now, request_id],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(())
    }
}
