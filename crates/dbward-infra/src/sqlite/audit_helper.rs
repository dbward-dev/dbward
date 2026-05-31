use dbward_domain::entities::AuditEvent;
use rusqlite::{params, Transaction};
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

    let prev_hash: Option<String> = tx
        .query_row(
            "SELECT event_hash FROM audit_events ORDER BY rowid DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .ok();

    let outcome = outcome_str(event.outcome);
    let hash_input = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        id,
        event.event_type,
        event.actor_id,
        event.created_at.to_rfc3339(),
        prev_hash.as_deref().unwrap_or(""),
        outcome,
        event.request_id.as_deref().unwrap_or(""),
        event.operation.as_deref().unwrap_or(""),
        event.database_name.as_deref().unwrap_or(""),
        event.environment.as_deref().unwrap_or(""),
        event.reason.as_deref().unwrap_or(""),
        event.detail_raw.as_deref().unwrap_or(""),
        event.metadata_json,
    );
    let event_hash = hex::encode(Sha256::digest(hash_input.as_bytes()));

    tx.execute(
        "INSERT INTO audit_events (id, event_type, event_category, event_version, outcome, actor_id, actor_type, resource_type, resource_id, peer_ip, client_ip, client_ip_source, request_id, operation, database_name, environment, detail_fingerprint, detail_raw, reason, metadata_json, prev_hash, event_hash, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23)",
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
            event.created_at.to_rfc3339(),
        ],
    )?;
    Ok(())
}
