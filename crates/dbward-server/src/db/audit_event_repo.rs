use rusqlite::Connection;
use sha2::{Digest, Sha256};

/// Parameters for inserting an audit event.
pub struct AuditEvent<'a> {
    pub event_type: &'a str,
    pub event_category: &'a str,
    pub outcome: &'a str,
    pub actor_id: &'a str,
    pub actor_type: &'a str,
    pub resource_type: Option<&'a str>,
    pub resource_id: Option<&'a str>,
    pub peer_ip: Option<&'a str>,
    pub client_ip: Option<&'a str>,
    pub client_ip_source: Option<&'a str>,
    pub request_id: Option<&'a str>,
    pub operation: Option<&'a str>,
    pub environment: Option<&'a str>,
    pub database_name: Option<&'a str>,
    pub detail_fingerprint: Option<&'a str>,
    pub detail_raw: Option<&'a str>,
    pub reason: Option<&'a str>,
    pub metadata_json: &'a str,
}

/// Insert an audit event with hash chain.
pub fn insert_audit_event(conn: &Connection, event: &AuditEvent) -> Result<String, rusqlite::Error> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    // Get previous hash for chain
    let prev_hash: Option<String> = conn
        .query_row(
            "SELECT event_hash FROM audit_events ORDER BY rowid DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .ok();

    // Compute event hash: SHA-256(prev_hash || event_type || actor_id || created_at || detail_fingerprint || outcome)
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_deref().unwrap_or("genesis"));
    hasher.update(event.event_type);
    hasher.update(event.actor_id);
    hasher.update(&now);
    hasher.update(event.detail_fingerprint.unwrap_or(""));
    hasher.update(event.outcome);
    let event_hash = hex::encode(hasher.finalize());

    conn.execute(
        "INSERT INTO audit_events (id, event_type, event_category, event_version, outcome, actor_id, actor_type, resource_type, resource_id, peer_ip, client_ip, client_ip_source, request_id, operation, environment, database_name, detail_fingerprint, detail_raw, reason, metadata_json, prev_hash, event_hash, created_at)
         VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22)",
        rusqlite::params![
            id,
            event.event_type,
            event.event_category,
            event.outcome,
            event.actor_id,
            event.actor_type,
            event.resource_type,
            event.resource_id,
            event.peer_ip,
            event.client_ip,
            event.client_ip_source,
            event.request_id,
            event.operation,
            event.environment,
            event.database_name,
            event.detail_fingerprint,
            event.detail_raw,
            event.reason,
            event.metadata_json,
            prev_hash,
            event_hash,
            now,
        ],
    )?;

    Ok(id)
}

/// Verify the hash chain integrity. Returns (total_events, first_broken_id).
pub fn verify_hash_chain(conn: &Connection) -> Result<(u64, Option<String>), rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT id, event_type, actor_id, created_at, detail_fingerprint, outcome, prev_hash, event_hash FROM audit_events ORDER BY rowid ASC",
    )?;

    let mut rows = stmt.query([])?;
    let mut count: u64 = 0;
    let mut last_hash: Option<String> = None;

    while let Some(row) = rows.next()? {
        let id: String = row.get(0)?;
        let event_type: String = row.get(1)?;
        let actor_id: String = row.get(2)?;
        let created_at: String = row.get(3)?;
        let detail_fp: Option<String> = row.get(4)?;
        let outcome: String = row.get(5)?;
        let stored_prev: Option<String> = row.get(6)?;
        let stored_hash: String = row.get(7)?;

        // Verify prev_hash matches last computed hash
        if stored_prev != last_hash {
            return Ok((count, Some(id)));
        }

        // Recompute hash
        let mut hasher = Sha256::new();
        hasher.update(stored_prev.as_deref().unwrap_or("genesis"));
        hasher.update(&event_type);
        hasher.update(&actor_id);
        hasher.update(&created_at);
        hasher.update(detail_fp.as_deref().unwrap_or(""));
        hasher.update(&outcome);
        let computed = hex::encode(hasher.finalize());

        if computed != stored_hash {
            return Ok((count, Some(id)));
        }

        last_hash = Some(stored_hash);
        count += 1;
    }

    Ok((count, None))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_conn() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        crate::db::init(&conn).unwrap();
        conn
    }

    fn minimal_event() -> AuditEvent<'static> {
        AuditEvent {
            event_type: "execution_completed",
            event_category: "execution",
            outcome: "success",
            actor_id: "alice",
            actor_type: "user",
            resource_type: Some("request"),
            resource_id: Some("req_123"),
            peer_ip: Some("127.0.0.1"),
            client_ip: Some("127.0.0.1"),
            client_ip_source: Some("peer"),
            request_id: Some("req_123"),
            operation: Some("execute_query"),
            environment: Some("production"),
            database_name: Some("app"),
            detail_fingerprint: Some("SELECT * FROM users WHERE id = ?"),
            detail_raw: Some("SELECT * FROM users WHERE id = 42"),
            reason: Some("debugging"),
            metadata_json: "{}",
        }
    }

    #[test]
    fn insert_and_verify_chain() {
        let conn = test_conn();

        insert_audit_event(&conn, &minimal_event()).unwrap();
        insert_audit_event(&conn, &minimal_event()).unwrap();
        insert_audit_event(&conn, &minimal_event()).unwrap();

        let (count, broken) = verify_hash_chain(&conn).unwrap();
        assert_eq!(count, 3);
        assert!(broken.is_none());
    }

    #[test]
    fn detect_tampered_hash() {
        let conn = test_conn();

        insert_audit_event(&conn, &minimal_event()).unwrap();
        let id2 = insert_audit_event(&conn, &minimal_event()).unwrap();
        insert_audit_event(&conn, &minimal_event()).unwrap();

        // Tamper with middle event
        conn.execute(
            "UPDATE audit_events SET event_hash = 'tampered' WHERE id = ?1",
            [&id2],
        )
        .unwrap();

        let (count, broken) = verify_hash_chain(&conn).unwrap();
        assert_eq!(count, 1); // first event OK
        assert!(broken.is_some()); // second event broken
    }
}
