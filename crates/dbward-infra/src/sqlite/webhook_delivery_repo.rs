use rusqlite::params;

use dbward_app::error::AppError;
use dbward_app::ports::WebhookDeliveryRepo;
use dbward_domain::entities::{DeliveryStatus, WebhookDelivery};

use crate::sqlite::DbConn;

pub struct SqliteWebhookDeliveryRepo {
    conn: DbConn,
}

impl SqliteWebhookDeliveryRepo {
    pub fn new(conn: DbConn) -> Self {
        Self { conn }
    }
}

fn parse_status(s: &str) -> DeliveryStatus {
    match s {
        "in_progress" => DeliveryStatus::InProgress,
        "delivered" => DeliveryStatus::Delivered,
        "dead" => DeliveryStatus::Dead,
        _ => DeliveryStatus::Pending,
    }
}

fn status_str(s: DeliveryStatus) -> &'static str {
    match s {
        DeliveryStatus::Pending => "pending",
        DeliveryStatus::InProgress => "in_progress",
        DeliveryStatus::Delivered => "delivered",
        DeliveryStatus::Dead => "dead",
    }
}

fn row_to_delivery(row: &rusqlite::Row<'_>) -> Result<WebhookDelivery, rusqlite::Error> {
    let status_str: String = row.get("status")?;
    Ok(WebhookDelivery {
        id: row.get("id")?,
        webhook_id: row.get("webhook_id")?,
        event_type: row.get("event_type")?,
        payload: row.get("payload")?,
        status: parse_status(&status_str),
        attempts: row.get("attempts")?,
        max_attempts: row.get("max_attempts")?,
        next_retry_at: row
            .get::<_, Option<String>>("next_retry_at")?
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
            .map(|d| d.with_timezone(&chrono::Utc)),
        last_error: row.get("last_error")?,
        created_at: {
            let s: String = row.get("created_at")?;
            super::parse_datetime(&s)?
        },
        last_attempted_at: row
            .get::<_, Option<String>>("last_attempted_at")?
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
            .map(|d| d.with_timezone(&chrono::Utc)),
        claimed_at: row
            .get::<_, Option<String>>("claimed_at")?
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
            .map(|d| d.with_timezone(&chrono::Utc)),
    })
}

impl WebhookDeliveryRepo for SqliteWebhookDeliveryRepo {
    fn insert(&self, d: &WebhookDelivery) -> Result<(), AppError> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO webhook_deliveries (id, webhook_id, event_type, payload, status, attempts, max_attempts, next_retry_at, last_error, created_at, last_attempted_at, claimed_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            params![
                d.id,
                d.webhook_id,
                d.event_type,
                d.payload,
                status_str(d.status),
                d.attempts,
                d.max_attempts,
                d.next_retry_at.map(|t| t.to_rfc3339()),
                d.last_error,
                d.created_at.to_rfc3339(),
                d.last_attempted_at.map(|t| t.to_rfc3339()),
                d.claimed_at.map(|t| t.to_rfc3339()),
            ],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(())
    }

    fn claim_for_retry(&self, now: &str, limit: u32) -> Result<Vec<WebhookDelivery>, AppError> {
        let conn = self.conn.lock();
        // Atomically claim rows
        conn.execute(
            "UPDATE webhook_deliveries SET status = 'in_progress', claimed_at = ?1 WHERE id IN (SELECT id FROM webhook_deliveries WHERE status = 'pending' AND next_retry_at <= ?1 ORDER BY next_retry_at ASC LIMIT ?2)",
            params![now, limit],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;
        // Fetch claimed rows
        let mut stmt = conn
            .prepare(
                "SELECT * FROM webhook_deliveries WHERE status = 'in_progress' AND claimed_at = ?1",
            )
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let rows = stmt
            .query_and_then(params![now], row_to_delivery)
            .map_err(|e| AppError::Internal(e.to_string()))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| AppError::Internal(e.to_string()))
    }

    fn mark_delivered(&self, id: &str, now: &str) -> Result<(), AppError> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE webhook_deliveries SET status = 'delivered', last_attempted_at = ?2 WHERE id = ?1",
            params![id, now],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(())
    }

    fn mark_failed(
        &self,
        id: &str,
        error: &str,
        next_retry_at: &str,
        attempts: u32,
    ) -> Result<(), AppError> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE webhook_deliveries SET status = 'pending', last_error = ?2, next_retry_at = ?3, attempts = ?4, last_attempted_at = ?3, claimed_at = NULL WHERE id = ?1",
            params![id, error, next_retry_at, attempts],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(())
    }

    fn mark_dead(&self, id: &str) -> Result<(), AppError> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE webhook_deliveries SET status = 'dead', claimed_at = NULL WHERE id = ?1",
            params![id],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(())
    }

    fn reclaim_stale(&self, older_than: &str) -> Result<u32, AppError> {
        let conn = self.conn.lock();
        let changed = conn
            .execute(
                "UPDATE webhook_deliveries SET status = 'pending', claimed_at = NULL WHERE status = 'in_progress' AND claimed_at < ?1",
                params![older_than],
            )
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(changed as u32)
    }

    fn list_by_status(
        &self,
        status: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> Result<(Vec<WebhookDelivery>, u32), AppError> {
        let conn = self.conn.lock();
        let total: u32 = if let Some(s) = status {
            conn.query_row(
                "SELECT COUNT(*) FROM webhook_deliveries WHERE status = ?1",
                params![s],
                |r| r.get(0),
            )
        } else {
            conn.query_row("SELECT COUNT(*) FROM webhook_deliveries", [], |r| r.get(0))
        }
        .map_err(|e| AppError::Internal(e.to_string()))?;

        let mut stmt = if status.is_some() {
            conn.prepare("SELECT * FROM webhook_deliveries WHERE status = ?1 ORDER BY created_at DESC LIMIT ?2 OFFSET ?3")
        } else {
            conn.prepare("SELECT * FROM webhook_deliveries ORDER BY created_at DESC LIMIT ?1 OFFSET ?2")
        }
        .map_err(|e| AppError::Internal(e.to_string()))?;

        let rows = if let Some(s) = status {
            stmt.query_and_then(params![s, limit, offset], row_to_delivery)
        } else {
            stmt.query_and_then(params![limit, offset], row_to_delivery)
        }
        .map_err(|e| AppError::Internal(e.to_string()))?;
        let items = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok((items, total))
    }

    fn purge_old(&self, before: &str) -> Result<u32, AppError> {
        let conn = self.conn.lock();
        let changed = conn
            .execute(
                "DELETE FROM webhook_deliveries WHERE status IN ('delivered', 'dead') AND created_at < ?1",
                params![before],
            )
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(changed as u32)
    }
}
