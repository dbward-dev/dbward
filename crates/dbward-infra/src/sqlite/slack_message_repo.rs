use std::sync::Arc;

use dbward_app::error::AppError;
use rusqlite::Connection;
use std::sync::Mutex;

use crate::slack::{SlackMessageRef, SlackMessageRepo};

pub struct SqliteSlackMessageRepo {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteSlackMessageRepo {
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }
}

impl SlackMessageRepo for SqliteSlackMessageRepo {
    fn save(&self, request_id: &str, channel: &str, message_ts: &str) -> Result<(), AppError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO slack_messages (request_id, channel, message_ts, created_at) VALUES (?1, ?2, ?3, datetime('now'))",
            rusqlite::params![request_id, channel, message_ts],
        )
        .map_err(|e| AppError::Internal(format!("sqlite: {e}")))?;
        Ok(())
    }

    fn get(&self, request_id: &str) -> Result<Option<SlackMessageRef>, AppError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT channel, message_ts FROM slack_messages WHERE request_id = ?1")
            .map_err(|e| AppError::Internal(format!("sqlite: {e}")))?;

        let result = stmt
            .query_row(rusqlite::params![request_id], |row| {
                Ok(SlackMessageRef {
                    channel: row.get(0)?,
                    message_ts: row.get(1)?,
                })
            })
            .optional()
            .map_err(|e| AppError::Internal(format!("sqlite: {e}")))?;

        Ok(result)
    }
}

use rusqlite::OptionalExtension;

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> SqliteSlackMessageRepo {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE slack_messages (
                request_id TEXT PRIMARY KEY,
                channel TEXT NOT NULL,
                message_ts TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )",
        )
        .unwrap();
        SqliteSlackMessageRepo::new(Arc::new(Mutex::new(conn)))
    }

    #[test]
    fn save_and_get() {
        let repo = setup();
        repo.save("req-1", "#approvals", "1234.5678").unwrap();
        let result = repo.get("req-1").unwrap().unwrap();
        assert_eq!(result.channel, "#approvals");
        assert_eq!(result.message_ts, "1234.5678");
    }

    #[test]
    fn get_missing_returns_none() {
        let repo = setup();
        assert!(repo.get("nonexistent").unwrap().is_none());
    }

    #[test]
    fn save_upserts() {
        let repo = setup();
        repo.save("req-1", "#old", "111.222").unwrap();
        repo.save("req-1", "#new", "333.444").unwrap();
        let result = repo.get("req-1").unwrap().unwrap();
        assert_eq!(result.channel, "#new");
        assert_eq!(result.message_ts, "333.444");
    }
}
