use dbward_domain::entities::AuditEvent;
use rusqlite::{Connection, Transaction, params};
use sha2::{Digest, Sha256};

use super::audit_repo::{actor_type_str, category_str, outcome_str};

/// Controls whether the helper generates a new UUID or uses the event's existing id.
pub(crate) enum IdPolicy {
    /// Use `event.id` if non-empty, otherwise generate.
    UseExisting,
    /// Always generate a new UUID (for TX-internal audit records).
    AlwaysGenerate,
}

/// Insert an audit event into an existing transaction, maintaining the hash chain.
pub(crate) fn insert_audit_event_in_tx(
    tx: &Transaction,
    event: &AuditEvent,
    id_policy: IdPolicy,
) -> rusqlite::Result<()> {
    let id = match id_policy {
        IdPolicy::UseExisting if !event.id.is_empty() => event.id.clone(),
        _ => uuid::Uuid::new_v4().to_string(),
    };
    insert_audit_event_on_conn(tx, &id, event)
}

/// Insert an audit event using a bare Connection (participates in caller's transaction).
/// Always generates a new UUID — used by UoW path where event.id is unset.
pub(crate) fn insert_audit_event_raw(
    conn: &Connection,
    event: &AuditEvent,
) -> rusqlite::Result<()> {
    let id = uuid::Uuid::new_v4().to_string();
    insert_audit_event_on_conn(conn, &id, event)
}

/// Shared implementation: compute hash chain and INSERT.
fn insert_audit_event_on_conn(
    conn: &Connection,
    id: &str,
    event: &AuditEvent,
) -> rusqlite::Result<()> {
    let prev_hash: Option<String> = match conn.query_row(
        "SELECT event_hash FROM audit_events ORDER BY rowid DESC LIMIT 1",
        [],
        |row| row.get(0),
    ) {
        Ok(h) => Some(h),
        Err(rusqlite::Error::QueryReturnedNoRows) => None,
        Err(e) => return Err(e),
    };

    let outcome = outcome_str(event.outcome);
    let event_hash = compute_v2_hash(id, event, prev_hash.as_deref(), outcome);

    conn.execute(
        "INSERT INTO audit_events (id, event_type, event_category, event_version, outcome, actor_id, actor_type, resource_type, resource_id, peer_ip, client_ip, client_ip_source, request_id, operation, database_name, environment, detail_fingerprint, detail_raw, reason, metadata_json, prev_hash, event_hash, chain_version, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24)",
        params![
            id,
            event.event_type,
            category_str(event.event_category),
            event.event_version,
            outcome,
            event.actor_id,
            actor_type_str(event.actor_type),
            event.resource_type,
            event.resource_id,
            event.peer_ip,
            event.client_ip,
            event.client_ip_source,
            event.request_id,
            event.operation,
            event.database_name,
            event.environment,
            event.detail_fingerprint,
            event.detail_raw,
            event.reason,
            event.metadata_json,
            prev_hash,
            event_hash,
            2i64, // chain_version = 2 for all new events
            event.created_at.to_rfc3339(),
        ],
    )?;
    Ok(())
}

/// V2 hash: length-prefixed fields for unambiguous serialization.
pub(crate) fn compute_v2_hash(
    id: &str,
    event: &AuditEvent,
    prev_hash: Option<&str>,
    outcome: &str,
) -> String {
    let fields: &[&str] = &[
        id,
        &event.event_type,
        category_str(event.event_category),
        &event.event_version.to_string(),
        outcome,
        &event.actor_id,
        actor_type_str(event.actor_type),
        event.resource_type.as_deref().unwrap_or(""),
        event.resource_id.as_deref().unwrap_or(""),
        event.peer_ip.as_deref().unwrap_or(""),
        event.client_ip.as_deref().unwrap_or(""),
        event.client_ip_source.as_deref().unwrap_or(""),
        event.request_id.as_deref().unwrap_or(""),
        event.operation.as_deref().unwrap_or(""),
        event.database_name.as_deref().unwrap_or(""),
        event.environment.as_deref().unwrap_or(""),
        event.detail_fingerprint.as_deref().unwrap_or(""),
        event.detail_raw.as_deref().unwrap_or(""),
        event.reason.as_deref().unwrap_or(""),
        &event.metadata_json,
        prev_hash.unwrap_or(""),
        &event.created_at.to_rfc3339(),
    ];
    let hash_input: String = fields
        .iter()
        .map(|f| format!("{}:{}", f.len(), f))
        .collect::<Vec<_>>()
        .join("\n");
    hex::encode(Sha256::digest(hash_input.as_bytes()))
}
