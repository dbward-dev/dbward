use crate::sqlite::DbConn;
use crate::sqlite::error::{db_err, json_err};
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
        let events_json =
            serde_json::to_string(&webhook.events).map_err(json_err("webhook: create"))?;
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO webhooks (id, url, events_json, format, secret, status, source, lifecycle_state, created_at, updated_at) \
             VALUES (?1,?2,?3,?4,?5,?6,'config','active',?7,?8) \
             ON CONFLICT(id) DO UPDATE SET url=excluded.url, events_json=excluded.events_json, \
             format=excluded.format, secret=excluded.secret, status=excluded.status, \
             lifecycle_state='active', updated_at=excluded.updated_at",
            rusqlite::params![
                webhook.id, webhook.url, events_json,
                format_str(webhook.format), webhook.secret, wh_status_str(webhook.status),
                now, now,
            ],
        ).map_err(db_err("webhook: create"))?;
        Ok(())
    }

    fn get(&self, id: &str) -> Result<Option<Webhook>, AppError> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare(
                "SELECT id, url, events_json, format, secret, status FROM webhooks WHERE id = ?1",
            )
            .map_err(db_err("webhook: get"))?;
        let result = stmt.query_row(rusqlite::params![id], row_to_webhook);
        match result {
            Ok(w) => Ok(Some(w)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(db_err("webhook: get")(e)),
        }
    }

    fn list_active(&self) -> Result<Vec<Webhook>, AppError> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT id, url, events_json, format, secret, status FROM webhooks WHERE lifecycle_state = 'active'")
            .map_err(db_err("webhook: list_active"))?;
        let rows = stmt
            .query_map([], row_to_webhook)
            .map_err(db_err("webhook: list_active"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(db_err("webhook: list_active"))
    }

    fn update(&self, webhook: &Webhook) -> Result<(), AppError> {
        let conn = self.conn.lock();
        let events_json =
            serde_json::to_string(&webhook.events).map_err(json_err("webhook: update"))?;
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE webhooks SET url=?1, events_json=?2, format=?3, secret=?4, status=?5, updated_at=?6 WHERE id=?7",
            rusqlite::params![
                webhook.url, events_json, format_str(webhook.format),
                webhook.secret, wh_status_str(webhook.status), now, webhook.id,
            ],
        ).map_err(db_err("webhook: update"))?;
        Ok(())
    }

    fn delete(&self, id: &str) -> Result<(), AppError> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM webhooks WHERE id = ?1", rusqlite::params![id])
            .map_err(db_err("webhook: delete"))?;
        Ok(())
    }

    fn delete_by_source(&self, source: &str) -> Result<u64, AppError> {
        let conn = self.conn.lock();
        let n = conn
            .execute("DELETE FROM webhooks WHERE source = ?1", [source])
            .map_err(db_err("webhook: delete_by_source"))?;
        Ok(n as u64)
    }

    fn delete_stale_config(&self, active_ids: &[String]) -> Result<u64, AppError> {
        let conn = self.conn.lock();
        if active_ids.is_empty() {
            let n = conn
                .execute("DELETE FROM webhooks WHERE source = 'config'", [])
                .map_err(db_err("webhook: delete_stale"))?;
            return Ok(n as u64);
        }
        let placeholders: String = (1..=active_ids.len())
            .map(|i| format!("?{i}"))
            .collect::<Vec<_>>()
            .join(",");
        let sql =
            format!("DELETE FROM webhooks WHERE source = 'config' AND id NOT IN ({placeholders})");
        let params: Vec<&dyn rusqlite::types::ToSql> = active_ids
            .iter()
            .map(|s| s as &dyn rusqlite::types::ToSql)
            .collect();
        let n = conn
            .execute(&sql, params.as_slice())
            .map_err(db_err("webhook: delete_stale"))?;
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
        events: serde_json::from_str(&events_json).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(e))
        })?,
        format: parse_format(&format_s),
        secret: row.get(4)?,
        status: parse_wh_status(&status_s),
        created_at: None,
        updated_at: None,
    })
}
