use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};

/// Parameters for inserting an audit event.
/// `peer_ip`, `client_ip`, `client_ip_source` are populated by `record_audit_event`.
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

fn hash_field(hasher: &mut Sha256, name: &str, value: Option<&str>) {
    hasher.update(name.as_bytes());
    hasher.update([0x1f]);
    match value {
        Some(value) => {
            hasher.update([0x01]);
            hasher.update(value.len().to_string().as_bytes());
            hasher.update([0x1e]);
            hasher.update(value.as_bytes());
        }
        None => hasher.update([0x00]),
    }
    hasher.update([0x1d]);
}

fn compute_event_hash(
    prev_hash: Option<&str>,
    id: &str,
    created_at: &str,
    event: &AuditEvent<'_>,
) -> String {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, "prev_hash", prev_hash);
    hash_field(&mut hasher, "id", Some(id));
    hash_field(&mut hasher, "event_type", Some(event.event_type));
    hash_field(&mut hasher, "event_category", Some(event.event_category));
    hash_field(&mut hasher, "event_version", Some("1"));
    hash_field(&mut hasher, "outcome", Some(event.outcome));
    hash_field(&mut hasher, "actor_id", Some(event.actor_id));
    hash_field(&mut hasher, "actor_type", Some(event.actor_type));
    hash_field(&mut hasher, "resource_type", event.resource_type);
    hash_field(&mut hasher, "resource_id", event.resource_id);
    hash_field(&mut hasher, "peer_ip", event.peer_ip);
    hash_field(&mut hasher, "client_ip", event.client_ip);
    hash_field(&mut hasher, "client_ip_source", event.client_ip_source);
    hash_field(&mut hasher, "request_id", event.request_id);
    hash_field(&mut hasher, "operation", event.operation);
    hash_field(&mut hasher, "environment", event.environment);
    hash_field(&mut hasher, "database_name", event.database_name);
    hash_field(&mut hasher, "detail_fingerprint", event.detail_fingerprint);
    hash_field(&mut hasher, "detail_raw", event.detail_raw);
    hash_field(&mut hasher, "reason", event.reason);
    hash_field(&mut hasher, "metadata_json", Some(event.metadata_json));
    hash_field(&mut hasher, "created_at", Some(created_at));
    hex::encode(hasher.finalize())
}

/// Insert an audit event with hash chain.
pub fn insert_audit_event(
    conn: &mut Connection,
    event: &AuditEvent,
) -> Result<String, rusqlite::Error> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

    // Read the current chain head while holding the write lock so another writer
    // cannot insert between the head read and this append.
    let prev_hash: Option<String> = tx
        .query_row(
            "SELECT event_hash FROM audit_events ORDER BY rowid DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let event_hash = compute_event_hash(prev_hash.as_deref(), &id, &now, event);

    tx.execute(
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
    tx.commit()?;

    Ok(id)
}

/// High-level wrapper: resolves IP from headers, applies redaction, then inserts.
pub fn record_audit_event(
    conn: &mut Connection,
    event: AuditEvent,
    headers: &axum::http::HeaderMap,
    audit_config: &crate::server_config::AuditConfig,
    trusted_proxies: &[String],
) -> Result<String, rusqlite::Error> {
    let ip = if audit_config.record_ip {
        resolve_client_ip(headers, None, trusted_proxies)
    } else {
        ResolvedIp {
            peer_ip: None,
            client_ip: None,
            client_ip_source: None,
        }
    };

    let redacted: String;
    let detail_raw = match event.detail_raw {
        None => None,
        Some(raw) => match audit_config.redaction.as_str() {
            "full" => None,
            "literals" => {
                redacted = redact_literals(raw);
                Some(redacted.as_str())
            }
            _ => Some(raw),
        },
    };

    let resolved = AuditEvent {
        peer_ip: ip.peer_ip.as_deref(),
        client_ip: ip.client_ip.as_deref(),
        client_ip_source: ip.client_ip_source.as_deref(),
        detail_raw,
        ..event
    };

    insert_audit_event(conn, &resolved)
}

/// Verify the hash chain integrity. Returns (total_events, first_broken_id).
pub fn verify_hash_chain(conn: &Connection) -> Result<(u64, Option<String>), rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT id, event_type, event_category, event_version, outcome, actor_id, actor_type, resource_type, resource_id, peer_ip, client_ip, client_ip_source, request_id, operation, environment, database_name, detail_fingerprint, detail_raw, reason, metadata_json, created_at, prev_hash, event_hash
         FROM audit_events
         ORDER BY rowid ASC",
    )?;

    let mut rows = stmt.query([])?;
    let mut count: u64 = 0;
    let mut last_hash: Option<String> = None;

    while let Some(row) = rows.next()? {
        let id: String = row.get(0)?;
        let event_type: String = row.get(1)?;
        let event_category: String = row.get(2)?;
        let event_version: i64 = row.get(3)?;
        let outcome: String = row.get(4)?;
        let actor_id: String = row.get(5)?;
        let actor_type: String = row.get(6)?;
        let resource_type: Option<String> = row.get(7)?;
        let resource_id: Option<String> = row.get(8)?;
        let peer_ip: Option<String> = row.get(9)?;
        let client_ip: Option<String> = row.get(10)?;
        let client_ip_source: Option<String> = row.get(11)?;
        let request_id: Option<String> = row.get(12)?;
        let operation: Option<String> = row.get(13)?;
        let environment: Option<String> = row.get(14)?;
        let database_name: Option<String> = row.get(15)?;
        let detail_fp: Option<String> = row.get(16)?;
        let detail_raw: Option<String> = row.get(17)?;
        let reason: Option<String> = row.get(18)?;
        let metadata_json: String = row.get(19)?;
        let created_at: String = row.get(20)?;
        let stored_prev: Option<String> = row.get(21)?;
        let stored_hash: String = row.get(22)?;

        // Verify prev_hash matches last computed hash
        if stored_prev != last_hash {
            return Ok((count, Some(id)));
        }

        let event = AuditEvent {
            event_type: &event_type,
            event_category: &event_category,
            outcome: &outcome,
            actor_id: &actor_id,
            actor_type: &actor_type,
            resource_type: resource_type.as_deref(),
            resource_id: resource_id.as_deref(),
            peer_ip: peer_ip.as_deref(),
            client_ip: client_ip.as_deref(),
            client_ip_source: client_ip_source.as_deref(),
            request_id: request_id.as_deref(),
            operation: operation.as_deref(),
            environment: environment.as_deref(),
            database_name: database_name.as_deref(),
            detail_fingerprint: detail_fp.as_deref(),
            detail_raw: detail_raw.as_deref(),
            reason: reason.as_deref(),
            metadata_json: &metadata_json,
        };

        if event_version != 1 {
            return Ok((count, Some(id)));
        }

        let computed = compute_event_hash(stored_prev.as_deref(), &id, &created_at, &event);

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
        let mut conn = test_conn();

        insert_audit_event(&mut conn, &minimal_event()).unwrap();
        insert_audit_event(&mut conn, &minimal_event()).unwrap();
        insert_audit_event(&mut conn, &minimal_event()).unwrap();

        let (count, broken) = verify_hash_chain(&conn).unwrap();
        assert_eq!(count, 3);
        assert!(broken.is_none());
    }

    #[test]
    fn detect_tampered_hash() {
        let mut conn = test_conn();

        insert_audit_event(&mut conn, &minimal_event()).unwrap();
        let id2 = insert_audit_event(&mut conn, &minimal_event()).unwrap();
        insert_audit_event(&mut conn, &minimal_event()).unwrap();

        // Tamper with middle event
        conn.execute(
            "UPDATE audit_events SET event_hash = ?2 WHERE id = ?1",
            rusqlite::params![id2, "0".repeat(64)],
        )
        .unwrap();

        let (count, broken) = verify_hash_chain(&conn).unwrap();
        assert_eq!(count, 1); // first event OK
        assert!(broken.is_some()); // second event broken
    }

    #[test]
    fn detect_tampered_unhashed_field() {
        let mut conn = test_conn();

        let id = insert_audit_event(&mut conn, &minimal_event()).unwrap();

        conn.execute(
            "UPDATE audit_events SET metadata_json = '{\"tampered\":true}' WHERE id = ?1",
            [&id],
        )
        .unwrap();

        let (count, broken) = verify_hash_chain(&conn).unwrap();
        assert_eq!(count, 0);
        assert_eq!(broken.as_deref(), Some(id.as_str()));
    }
}

/// Redact SQL literals: replace string/number literals with '?'
pub fn redact_literals(sql: &str) -> String {
    let mut result = String::with_capacity(sql.len());
    let mut chars = sql.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                result.push('?');
                // Skip until closing quote (handle escaped quotes)
                loop {
                    match chars.next() {
                        Some('\'') => {
                            if chars.peek() == Some(&'\'') {
                                chars.next(); // escaped quote
                            } else {
                                break;
                            }
                        }
                        None => break,
                        _ => {}
                    }
                }
            }
            '0'..='9' if !result.ends_with(|c: char| c.is_alphanumeric() || c == '_') => {
                result.push('?');
                while chars
                    .peek()
                    .is_some_and(|c| c.is_ascii_digit() || *c == '.')
                {
                    chars.next();
                }
            }
            _ => result.push(c),
        }
    }
    result
}

/// Resolve client IP from headers and peer address.
pub struct ResolvedIp {
    pub peer_ip: Option<String>,
    pub client_ip: Option<String>,
    pub client_ip_source: Option<String>,
}

pub fn resolve_client_ip(
    headers: &axum::http::HeaderMap,
    peer_ip: Option<&str>,
    trusted_proxies: &[String],
) -> ResolvedIp {
    let peer = peer_ip.map(|s| s.to_string());

    if trusted_proxies.is_empty() {
        return ResolvedIp {
            client_ip: peer.clone(),
            peer_ip: peer,
            client_ip_source: Some("peer".into()),
        };
    }

    // Check if peer is a trusted proxy
    let peer_is_trusted = peer.as_deref().is_some_and(|p| {
        trusted_proxies
            .iter()
            .any(|tp| tp == p || cidr_contains(tp, p))
    });

    if peer_is_trusted {
        // Trust X-Forwarded-For rightmost entry
        let xff = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.rsplit(',').next())
            .map(|s| s.trim().to_string());
        ResolvedIp {
            peer_ip: peer,
            client_ip: xff,
            client_ip_source: Some("trusted_proxy".into()),
        }
    } else {
        ResolvedIp {
            client_ip: peer.clone(),
            peer_ip: peer,
            client_ip_source: Some("peer".into()),
        }
    }
}

fn cidr_contains(cidr: &str, ip: &str) -> bool {
    // Simple prefix match for common CIDRs (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    if let Some(prefix) = cidr.split('/').next() {
        ip.starts_with(prefix.trim_end_matches('0').trim_end_matches('.'))
    } else {
        cidr == ip
    }
}

#[cfg(test)]
mod redaction_tests {
    use super::*;

    #[test]
    fn redact_string_literals() {
        assert_eq!(
            redact_literals("SELECT * FROM users WHERE email = 'alice@example.com'"),
            "SELECT * FROM users WHERE email = ?"
        );
    }

    #[test]
    fn redact_numeric_literals() {
        assert_eq!(
            redact_literals("SELECT * FROM users WHERE id = 42"),
            "SELECT * FROM users WHERE id = ?"
        );
    }

    #[test]
    fn redact_mixed() {
        assert_eq!(
            redact_literals("UPDATE users SET name = 'Bob' WHERE id = 123"),
            "UPDATE users SET name = ? WHERE id = ?"
        );
    }

    #[test]
    fn preserve_identifiers() {
        assert_eq!(
            redact_literals("SELECT col1 FROM table2"),
            "SELECT col1 FROM table2"
        );
    }
}
