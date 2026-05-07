use rusqlite::Connection;

pub(crate) struct WebhookRow {
    pub(crate) id: String,
    pub(crate) url: String,
    pub(crate) events_json: String,
    pub(crate) format: String,
    pub(crate) has_secret: bool,
    pub(crate) status: String,
    pub(crate) source: String,
    pub(crate) created_at: String,
    pub(crate) updated_at: String,
}

pub(crate) fn insert_webhook(
    conn: &Connection,
    id: &str,
    url: &str,
    events_json: &str,
    format: &str,
    secret: Option<&str>,
    source: &str,
    now: &str,
) -> Result<(), rusqlite::Error> {
    conn.execute(
        "INSERT INTO webhooks (id, url, events_json, format, secret, source, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![id, url, events_json, format, secret, source, now, now],
    )?;
    Ok(())
}

pub(crate) fn list_webhooks(conn: &Connection) -> Result<Vec<WebhookRow>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT id, url, events_json, format, secret IS NOT NULL, status, source, created_at, updated_at FROM webhooks ORDER BY created_at DESC",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok(WebhookRow {
                id: row.get(0)?,
                url: row.get(1)?,
                events_json: row.get(2)?,
                format: row.get(3)?,
                has_secret: row.get(4)?,
                status: row.get(5)?,
                source: row.get(6)?,
                created_at: row.get(7)?,
                updated_at: row.get(8)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

pub(crate) fn get_webhook(conn: &Connection, id: &str) -> Result<Option<WebhookRow>, rusqlite::Error> {
    match conn.query_row(
        "SELECT id, url, events_json, format, secret IS NOT NULL, status, source, created_at, updated_at FROM webhooks WHERE id = ?1",
        rusqlite::params![id],
        |row| {
            Ok(WebhookRow {
                id: row.get(0)?,
                url: row.get(1)?,
                events_json: row.get(2)?,
                format: row.get(3)?,
                has_secret: row.get(4)?,
                status: row.get(5)?,
                source: row.get(6)?,
                created_at: row.get(7)?,
                updated_at: row.get(8)?,
            })
        },
    ) {
        Ok(row) => Ok(Some(row)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e),
    }
}

pub(crate) fn update_webhook(
    conn: &Connection,
    id: &str,
    url: Option<&str>,
    events_json: Option<&str>,
    format: Option<&str>,
    secret: Option<Option<&str>>,
    now: &str,
) -> Result<bool, rusqlite::Error> {
    // Read current values, apply changes
    let current = match get_webhook(conn, id)? {
        Some(c) => c,
        None => return Ok(false),
    };
    let new_url = url.unwrap_or(&current.url);
    let new_events = events_json.unwrap_or(&current.events_json);
    let new_format = format.unwrap_or(&current.format);

    let updated = if let Some(s) = secret {
        conn.execute(
            "UPDATE webhooks SET url = ?1, events_json = ?2, format = ?3, secret = ?4, updated_at = ?5 WHERE id = ?6",
            rusqlite::params![new_url, new_events, new_format, s, now, id],
        )?
    } else {
        conn.execute(
            "UPDATE webhooks SET url = ?1, events_json = ?2, format = ?3, updated_at = ?4 WHERE id = ?5",
            rusqlite::params![new_url, new_events, new_format, now, id],
        )?
    };
    Ok(updated > 0)
}

pub(crate) fn delete_webhook(conn: &Connection, id: &str) -> Result<bool, rusqlite::Error> {
    let deleted = conn.execute("DELETE FROM webhooks WHERE id = ?1", rusqlite::params![id])?;
    Ok(deleted > 0)
}

/// Delete all config-sourced webhooks (used during startup re-seed).
pub(crate) fn delete_config_webhooks(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute("DELETE FROM webhooks WHERE source = 'config'", [])?;
    Ok(())
}

/// Get the secret for a webhook (used by dispatcher for HMAC signing).
pub(crate) fn get_webhook_secret(conn: &Connection, id: &str) -> Result<Option<String>, rusqlite::Error> {
    match conn.query_row(
        "SELECT secret FROM webhooks WHERE id = ?1",
        rusqlite::params![id],
        |row| row.get::<_, Option<String>>(0),
    ) {
        Ok(secret) => Ok(secret),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e),
    }
}

pub(crate) fn count_active_webhooks(conn: &Connection) -> Result<i64, rusqlite::Error> {
    conn.query_row("SELECT COUNT(*) FROM webhooks WHERE status = 'active'", [], |row| row.get(0))
}

/// Sync config-file webhooks to DB. Deletes all source='config' entries and re-inserts.
pub fn seed_config_webhooks(
    conn: &Connection,
    configs: &[crate::webhook::WebhookConfig],
) -> Result<(), rusqlite::Error> {
    delete_config_webhooks(conn)?;
    let now = chrono::Utc::now().to_rfc3339();
    for cfg in configs {
        let id = uuid::Uuid::new_v4().to_string();
        let events_json = serde_json::to_string(&cfg.events).unwrap_or_else(|_| "[]".into());
        insert_webhook(conn, &id, &cfg.url, &events_json, &cfg.format, cfg.secret.as_deref(), "config", &now)?;
    }
    Ok(())
}

/// Load all active webhooks as WebhookConfig (for dispatcher initialization).
pub fn load_active_webhook_configs(conn: &Connection) -> Result<Vec<crate::webhook::WebhookConfig>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT url, events_json, format, secret FROM webhooks WHERE status = 'active'",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(rows
        .into_iter()
        .map(|(url, events_json, format, secret)| {
            let events: Vec<String> = serde_json::from_str(&events_json).unwrap_or_default();
            crate::webhook::WebhookConfig { url, events, format, secret }
        })
        .collect())
}
