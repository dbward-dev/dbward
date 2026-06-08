use crate::sqlite::DbConn;
use dbward_app::error::AppError;
use dbward_app::ports::WebhookRepo;
use dbward_domain::entities::{Webhook, WebhookFormat, WebhookStatus};

pub struct SqliteWebhookRepo {
    conn: DbConn,
}

impl SqliteWebhookRepo {
    pub fn new(conn: DbConn) -> Self {
        Self { conn }
    }
}

impl WebhookRepo for SqliteWebhookRepo {
    fn create(&self, webhook: &Webhook) -> Result<(), AppError> {
        let conn = self.conn.lock();
        let events_json = serde_json::to_string(&webhook.events)
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO webhooks (id, url, events_json, format, secret, status, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            rusqlite::params![
                webhook.id, webhook.url, events_json,
                format_str(webhook.format), webhook.secret, wh_status_str(webhook.status),
                now, now,
            ],
        ).map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(())
    }

    fn get(&self, id: &str) -> Result<Option<Webhook>, AppError> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare(
                "SELECT id, url, events_json, format, secret, status FROM webhooks WHERE id = ?1",
            )
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let result = stmt.query_row(rusqlite::params![id], row_to_webhook);
        match result {
            Ok(w) => Ok(Some(w)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(AppError::Internal(e.to_string())),
        }
    }

    fn list(&self) -> Result<Vec<Webhook>, AppError> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT id, url, events_json, format, secret, status FROM webhooks")
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let rows = stmt
            .query_map([], row_to_webhook)
            .map_err(|e| AppError::Internal(e.to_string()))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| AppError::Internal(e.to_string()))
    }

    fn update(&self, webhook: &Webhook) -> Result<(), AppError> {
        let conn = self.conn.lock();
        let events_json = serde_json::to_string(&webhook.events)
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE webhooks SET url=?1, events_json=?2, format=?3, secret=?4, status=?5, updated_at=?6 WHERE id=?7",
            rusqlite::params![
                webhook.url, events_json, format_str(webhook.format),
                webhook.secret, wh_status_str(webhook.status), now, webhook.id,
            ],
        ).map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(())
    }

    fn delete(&self, id: &str) -> Result<(), AppError> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM webhooks WHERE id = ?1", rusqlite::params![id])
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(())
    }

    fn delete_by_source(&self, source: &str) -> Result<u64, AppError> {
        let conn = self.conn.lock();
        let n = conn
            .execute("DELETE FROM webhooks WHERE source = ?1", [source])
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(n as u64)
    }
}

fn format_str(f: WebhookFormat) -> &'static str {
    match f {
        WebhookFormat::Generic => "generic",
        WebhookFormat::Slack => "slack",
    }
}

fn parse_format(s: &str) -> WebhookFormat {
    match s {
        "slack" => WebhookFormat::Slack,
        _ => WebhookFormat::Generic,
    }
}

fn wh_status_str(s: WebhookStatus) -> &'static str {
    match s {
        WebhookStatus::Active => "active",
        WebhookStatus::Inactive => "inactive",
    }
}

fn parse_wh_status(s: &str) -> WebhookStatus {
    match s {
        "inactive" => WebhookStatus::Inactive,
        _ => WebhookStatus::Active,
    }
}

fn row_to_webhook(row: &rusqlite::Row) -> rusqlite::Result<Webhook> {
    let events_json: String = row.get(2)?;
    let format_s: String = row.get(3)?;
    let status_s: String = row.get(5)?;
    Ok(Webhook {
        id: row.get(0)?,
        url: row.get(1)?,
        events: serde_json::from_str(&events_json).unwrap_or_default(),
        format: parse_format(&format_s),
        secret: row.get(4)?,
        status: parse_wh_status(&status_s),
        created_at: None,
        updated_at: None,
    })
}
