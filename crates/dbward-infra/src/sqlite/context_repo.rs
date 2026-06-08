use rusqlite::params;

use dbward_app::error::AppError;
use dbward_app::ports::repos::{ContextRepo, RequestContextRecord};

use crate::sqlite::DbConn;
use crate::sqlite::error::db_err;

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
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO request_context \
             (request_id, status, schema_snapshot_collected_at, tables_json, sql_review_json, risk_json, explain_json, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                ctx.request_id,
                ctx.status,
                ctx.schema_snapshot_collected_at,
                ctx.tables_json,
                ctx.sql_review_json,
                ctx.risk_json,
                ctx.explain_json,
                ctx.created_at,
                ctx.updated_at,
            ],
        )
        .map_err(db_err("context: create"))?;
        Ok(())
    }

    fn get(&self, request_id: &str) -> Result<Option<RequestContextRecord>, AppError> {
        let conn = self.conn.lock();
        let result = conn.query_row(
            "SELECT request_id, status, schema_snapshot_collected_at, tables_json, sql_review_json, risk_json, explain_json, created_at, updated_at \
             FROM request_context WHERE request_id = ?1",
            params![request_id],
            |row| {
                Ok(RequestContextRecord {
                    request_id: row.get(0)?,
                    status: row.get(1)?,
                    schema_snapshot_collected_at: row.get(2)?,
                    tables_json: row.get(3)?,
                    sql_review_json: row.get(4)?,
                    risk_json: row.get(5)?,
                    explain_json: row.get(6)?,
                    created_at: row.get(7)?,
                    updated_at: row.get(8)?,
                })
            },
        );
        match result {
            Ok(r) => Ok(Some(r)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(db_err("context: get")(e)),
        }
    }

    fn update_explain(
        &self,
        request_id: &str,
        explain_json: &str,
        status: &str,
        now: &str,
    ) -> Result<(), AppError> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE request_context SET explain_json = ?1, status = ?2, updated_at = ?3 WHERE request_id = ?4",
            params![explain_json, status, now, request_id],
        )
        .map_err(db_err("context: update_explain"))?;
        Ok(())
    }

    fn timeout_collecting(&self, cutoff: &str, now: &str) -> Result<u32, AppError> {
        let conn = self.conn.lock();
        let n = conn
            .execute(
                "UPDATE request_context SET status = 'unavailable', updated_at = ?1 \
             WHERE status = 'collecting' AND created_at < ?2",
                params![now, cutoff],
            )
            .map_err(db_err("context: timeout_collecting"))?;
        Ok(n as u32)
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
            let c = conn.lock();
            initialize(&c).unwrap();
            c.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
        }
        conn
    }

    #[test]
    fn create_and_get() {
        let conn = setup();
        let repo = SqliteContextRepo::new(conn);
        let ctx = RequestContextRecord {
            request_id: "req-1".into(),
            status: "collecting".into(),
            schema_snapshot_collected_at: None,
            tables_json: Some(r#"["users"]"#.into()),
            sql_review_json: Some(r#"{"blocked":false}"#.into()),
            risk_json: Some(r#"{"level":"Low"}"#.into()),
            explain_json: None,
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        };
        repo.create(&ctx).unwrap();
        let got = repo.get("req-1").unwrap().unwrap();
        assert_eq!(got.status, "collecting");
        assert_eq!(got.risk_json.as_deref(), Some(r#"{"level":"Low"}"#));
    }

    #[test]
    fn update_explain_transitions_status() {
        let conn = setup();
        let repo = SqliteContextRepo::new(conn);
        let ctx = RequestContextRecord {
            request_id: "req-2".into(),
            status: "collecting".into(),
            schema_snapshot_collected_at: None,
            tables_json: None,
            sql_review_json: None,
            risk_json: None,
            explain_json: None,
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        };
        repo.create(&ctx).unwrap();
        repo.update_explain("req-2", "[{\"plan\":{}}]", "ready", "2026-01-01T01:00:00Z")
            .unwrap();
        let got = repo.get("req-2").unwrap().unwrap();
        assert_eq!(got.status, "ready");
        assert!(got.explain_json.is_some());
    }

    #[test]
    fn timeout_collecting() {
        let conn = setup();
        let repo = SqliteContextRepo::new(conn);
        let ctx = RequestContextRecord {
            request_id: "req-3".into(),
            status: "collecting".into(),
            schema_snapshot_collected_at: None,
            tables_json: None,
            sql_review_json: None,
            risk_json: None,
            explain_json: None,
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        };
        repo.create(&ctx).unwrap();
        let n = repo
            .timeout_collecting("2026-01-01T00:05:01Z", "2026-01-01T00:06:00Z")
            .unwrap();
        assert_eq!(n, 1);
        let got = repo.get("req-3").unwrap().unwrap();
        assert_eq!(got.status, "unavailable");
    }
}
