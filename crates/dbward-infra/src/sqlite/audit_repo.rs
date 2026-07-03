use crate::sqlite::DbConn;
use crate::sqlite::error::db_err;
use dbward_app::error::AppError;
use dbward_app::ports::{
    AuditFilter, AuditLogger, AuditRepo, AuditVerifyFailure, AuditVerifyResult, VerifyFailureReason,
};
use dbward_domain::entities::{ActorType, AuditEvent, EventCategory, EventOutcome};

/// Internal struct for verify_chain row iteration.
struct VerifyRow {
    rowid: i64,
    id: String,
    event_type: String,
    event_category: String,
    event_version: i64,
    actor_id: String,
    actor_type: String,
    resource_type: Option<String>,
    resource_id: Option<String>,
    peer_ip: Option<String>,
    client_ip: Option<String>,
    client_ip_source: Option<String>,
    created_at: String,
    prev_hash: Option<String>,
    event_hash: String,
    outcome: String,
    request_id: Option<String>,
    operation: Option<String>,
    database_name: Option<String>,
    environment: Option<String>,
    reason: Option<String>,
    detail_fingerprint: Option<String>,
    detail_raw: Option<String>,
    metadata_json: String,
    chain_version: i64,
}

pub struct SqliteAuditLogger {
    conn: DbConn,
}

impl SqliteAuditLogger {
    pub fn new(conn: DbConn) -> Self {
        Self { conn }
    }
}

impl AuditLogger for SqliteAuditLogger {
    fn record(&self, event: &AuditEvent) -> Result<(), AppError> {
        let mut conn = self.conn.lock();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(db_err("audit: record"))?;

        super::audit_helper::insert_audit_event_in_tx(
            &tx,
            event,
            super::audit_helper::IdPolicy::UseExisting,
        )
        .map_err(db_err("audit: record"))?;

        tx.commit().map_err(db_err("audit: record"))?;
        Ok(())
    }
}

pub struct SqliteAuditRepo {
    conn: DbConn,
}

impl SqliteAuditRepo {
    pub fn new(conn: DbConn) -> Self {
        Self { conn }
    }
}

impl AuditRepo for SqliteAuditRepo {
    fn list(&self, filter: &AuditFilter) -> Result<Vec<AuditEvent>, AppError> {
        let conn = self.conn.lock();

        let mut conditions: Vec<String> = Vec::new();
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        let mut idx = 1u32;

        if let Some(ref v) = filter.actor_id {
            conditions.push(format!("actor_id = ?{idx}"));
            param_values.push(Box::new(v.clone()));
            idx += 1;
        }
        if let Some(ref v) = filter.event_type {
            conditions.push(format!("event_type = ?{idx}"));
            param_values.push(Box::new(v.clone()));
            idx += 1;
        }
        if let Some(ref v) = filter.event_category {
            conditions.push(format!("event_category = ?{idx}"));
            param_values.push(Box::new(v.clone()));
            idx += 1;
        }
        if let Some(ref v) = filter.outcome {
            conditions.push(format!("outcome = ?{idx}"));
            param_values.push(Box::new(v.clone()));
            idx += 1;
        }
        if let Some(ref v) = filter.environment {
            conditions.push(format!("environment = ?{idx}"));
            param_values.push(Box::new(v.clone()));
            idx += 1;
        }
        if let Some(ref v) = filter.database {
            conditions.push(format!("database_name = ?{idx}"));
            param_values.push(Box::new(v.clone()));
            idx += 1;
        }
        if let Some(ref v) = filter.since {
            conditions.push(format!("created_at >= ?{idx}"));
            param_values.push(Box::new(v.to_rfc3339()));
            idx += 1;
        }
        if let Some(ref v) = filter.until {
            conditions.push(format!("created_at <= ?{idx}"));
            param_values.push(Box::new(v.to_rfc3339()));
            idx += 1;
        }

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        let sql = format!(
            "SELECT id, event_type, event_category, event_version, outcome, actor_id, actor_type, resource_type, resource_id, peer_ip, client_ip, client_ip_source, request_id, operation, database_name, environment, detail_fingerprint, detail_raw, reason, metadata_json, prev_hash, event_hash, created_at FROM audit_events {where_clause} ORDER BY created_at DESC LIMIT ?{idx} OFFSET ?{}",
            idx + 1
        );

        param_values.push(Box::new(filter.limit));
        param_values.push(Box::new(filter.offset));

        let params_ref: Vec<&dyn rusqlite::types::ToSql> =
            param_values.iter().map(|p| p.as_ref()).collect();
        let mut stmt = conn.prepare(&sql).map_err(db_err("audit: list"))?;
        let rows = stmt
            .query_map(params_ref.as_slice(), row_to_audit_event)
            .map_err(db_err("audit: list"))?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(db_err("audit: list"))
    }

    fn verify_chain(
        &self,
        verifier: Option<&dyn dbward_app::ports::crypto::AuditVerifier>,
    ) -> Result<AuditVerifyResult, AppError> {
        use sha2::{Digest, Sha256};

        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT rowid, id, event_type, event_category, event_version, actor_id, actor_type, resource_type, resource_id, peer_ip, client_ip, client_ip_source, created_at, prev_hash, event_hash, outcome, request_id, operation, database_name, environment, reason, detail_fingerprint, detail_raw, metadata_json, chain_version FROM audit_events ORDER BY rowid ASC"
        ).map_err(db_err("audit: verify_chain"))?;

        let rows = stmt
            .query_map([], |row| {
                Ok(VerifyRow {
                    rowid: row.get(0)?,
                    id: row.get(1)?,
                    event_type: row.get(2)?,
                    event_category: row.get(3)?,
                    event_version: row.get(4)?,
                    actor_id: row.get(5)?,
                    actor_type: row.get(6)?,
                    resource_type: row.get(7)?,
                    resource_id: row.get(8)?,
                    peer_ip: row.get(9)?,
                    client_ip: row.get(10)?,
                    client_ip_source: row.get(11)?,
                    created_at: row.get(12)?,
                    prev_hash: row.get(13)?,
                    event_hash: row.get(14)?,
                    outcome: row.get(15)?,
                    request_id: row.get(16)?,
                    operation: row.get(17)?,
                    database_name: row.get(18)?,
                    environment: row.get(19)?,
                    reason: row.get(20)?,
                    detail_fingerprint: row.get(21)?,
                    detail_raw: row.get(22)?,
                    metadata_json: row.get(23)?,
                    chain_version: row.get(24)?,
                })
            })
            .map_err(db_err("audit: verify_chain"))?;

        let mut total: u64 = 0;
        let mut expected_prev: Option<String> = None;
        let mut event_count_since_checkpoint: u64 = 0;
        let mut is_first = true;

        for row in rows {
            let r = row.map_err(db_err("audit: verify_chain"))?;
            total += 1;

            if is_first {
                is_first = false;
                if let Some(ref prev) = r.prev_hash {
                    let exists: bool = conn
                        .query_row(
                            "SELECT EXISTS(SELECT 1 FROM audit_events WHERE event_hash = ?1)",
                            rusqlite::params![prev],
                            |row| row.get(0),
                        )
                        .map_err(db_err("audit: verify_chain"))?;
                    if exists {
                        return Ok(AuditVerifyResult {
                            total_events: total,
                            first_broken_id: Some(r.id.clone()),
                            failure: Some(AuditVerifyFailure {
                                rowid: Some(r.rowid),
                                event_id: r.id.clone(),
                                event_type: r.event_type,
                                reason: VerifyFailureReason::PurgeBoundaryUnauthenticated,
                            }),
                        });
                    }
                    // Orphan prev_hash: check audit_purge_checkpoints for signed proof
                    let checkpoint_row: Option<(String, String, i64, String, String)> = conn
                        .query_row(
                            "SELECT purged_before, last_purged_hash, retained_count, signature, key_id FROM audit_purge_checkpoints WHERE last_purged_hash = ?1",
                            rusqlite::params![prev],
                            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get::<_, String>(4).unwrap_or_default())),
                        )
                        .ok();
                    match checkpoint_row {
                        None => {
                            return Ok(AuditVerifyResult {
                                total_events: total,
                                first_broken_id: Some(r.id.clone()),
                                failure: Some(AuditVerifyFailure {
                                    rowid: Some(r.rowid),
                                    event_id: r.id.clone(),
                                    event_type: r.event_type,
                                    reason: VerifyFailureReason::PurgeBoundaryUnauthenticated,
                                }),
                            });
                        }
                        Some((purged_before, last_hash, retained, sig_hex, key_id)) => {
                            // Verify signature if verifier provided
                            if let Some(v) = verifier {
                                let payload = format!(
                                    "purge-checkpoint:v1|{}|{}|{}",
                                    last_hash, purged_before, retained
                                );
                                let sig_bytes = match hex::decode(&sig_hex) {
                                    Ok(b) => b,
                                    Err(_) => {
                                        return Ok(AuditVerifyResult {
                                            total_events: total,
                                            first_broken_id: Some(r.id.clone()),
                                            failure: Some(AuditVerifyFailure {
                                                rowid: Some(r.rowid),
                                                event_id: r.id.clone(),
                                                event_type: r.event_type.clone(),
                                                reason: VerifyFailureReason::PurgeBoundaryUnauthenticated,
                                            }),
                                        });
                                    }
                                };
                                let valid = if key_id.is_empty() {
                                    v.verify(payload.as_bytes(), &sig_bytes)
                                } else {
                                    v.verify_with_key(&key_id, payload.as_bytes(), &sig_bytes)
                                };
                                if !valid {
                                    return Ok(AuditVerifyResult {
                                        total_events: total,
                                        first_broken_id: Some(r.id.clone()),
                                        failure: Some(AuditVerifyFailure {
                                            rowid: Some(r.rowid),
                                            event_id: r.id.clone(),
                                            event_type: r.event_type,
                                            reason:
                                                VerifyFailureReason::PurgeBoundaryUnauthenticated,
                                        }),
                                    });
                                }
                            }
                        }
                    }
                }
            } else if r.prev_hash.as_deref() != expected_prev.as_deref() {
                return Ok(AuditVerifyResult {
                    total_events: total,
                    first_broken_id: Some(r.id.clone()),
                    failure: Some(AuditVerifyFailure {
                        rowid: Some(r.rowid),
                        event_id: r.id.clone(),
                        event_type: r.event_type,
                        reason: VerifyFailureReason::PrevHashMismatch,
                    }),
                });
            }

            let computed = match r.chain_version {
                1 => {
                    // V1: pipe-delimited subset
                    let hash_input = format!(
                        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
                        r.id,
                        r.event_type,
                        r.actor_id,
                        r.created_at,
                        r.prev_hash.as_deref().unwrap_or(""),
                        r.outcome,
                        r.request_id.as_deref().unwrap_or(""),
                        r.operation.as_deref().unwrap_or(""),
                        r.database_name.as_deref().unwrap_or(""),
                        r.environment.as_deref().unwrap_or(""),
                        r.reason.as_deref().unwrap_or(""),
                        r.detail_raw.as_deref().unwrap_or(""),
                        r.metadata_json,
                    );
                    hex::encode(Sha256::digest(hash_input.as_bytes()))
                }
                2 => {
                    // V2: length-prefixed all fields
                    let fields: &[&str] = &[
                        &r.id,
                        &r.event_type,
                        &r.event_category,
                        &r.event_version.to_string(),
                        &r.outcome,
                        &r.actor_id,
                        &r.actor_type,
                        r.resource_type.as_deref().unwrap_or(""),
                        r.resource_id.as_deref().unwrap_or(""),
                        r.peer_ip.as_deref().unwrap_or(""),
                        r.client_ip.as_deref().unwrap_or(""),
                        r.client_ip_source.as_deref().unwrap_or(""),
                        r.request_id.as_deref().unwrap_or(""),
                        r.operation.as_deref().unwrap_or(""),
                        r.database_name.as_deref().unwrap_or(""),
                        r.environment.as_deref().unwrap_or(""),
                        r.detail_fingerprint.as_deref().unwrap_or(""),
                        r.detail_raw.as_deref().unwrap_or(""),
                        r.reason.as_deref().unwrap_or(""),
                        &r.metadata_json,
                        r.prev_hash.as_deref().unwrap_or(""),
                        &r.created_at,
                    ];
                    let hash_input: String = fields
                        .iter()
                        .map(|f| format!("{}:{}", f.len(), f))
                        .collect::<Vec<_>>()
                        .join("\n");
                    hex::encode(Sha256::digest(hash_input.as_bytes()))
                }
                v => {
                    tracing::warn!(chain_version = v, event_id = %r.id, "unknown chain version");
                    return Ok(AuditVerifyResult {
                        total_events: total,
                        first_broken_id: Some(r.id.clone()),
                        failure: Some(AuditVerifyFailure {
                            rowid: Some(r.rowid),
                            event_id: r.id.clone(),
                            event_type: r.event_type,
                            reason: VerifyFailureReason::UnknownChainVersion(v),
                        }),
                    });
                }
            };

            if computed != r.event_hash {
                return Ok(AuditVerifyResult {
                    total_events: total,
                    first_broken_id: Some(r.id.clone()),
                    failure: Some(AuditVerifyFailure {
                        rowid: Some(r.rowid),
                        event_id: r.id.clone(),
                        event_type: r.event_type,
                        reason: VerifyFailureReason::HashMismatch,
                    }),
                });
            }

            // Verify signed checkpoint metadata if this is a checkpoint event
            if r.event_type == "audit.signed_checkpoint" {
                let meta = match serde_json::from_str::<serde_json::Value>(&r.metadata_json) {
                    Ok(m) => m,
                    Err(_) => {
                        return Ok(AuditVerifyResult {
                            total_events: total,
                            first_broken_id: Some(r.id.clone()),
                            failure: Some(AuditVerifyFailure {
                                rowid: Some(r.rowid),
                                event_id: r.id.clone(),
                                event_type: r.event_type,
                                reason: VerifyFailureReason::CheckpointSignatureInvalid,
                            }),
                        });
                    }
                };
                let claimed_head = meta["chain_head_hash"].as_str().unwrap_or("");
                let claimed_count = meta["event_count_since_last_checkpoint"]
                    .as_u64()
                    .unwrap_or(0);
                let signature_hex = meta["signature"].as_str().unwrap_or("");
                let key_id = meta["key_id"].as_str().unwrap_or("");

                // 1. Verify head hash matches prev_hash
                if r.prev_hash.as_deref() != Some(claimed_head) && !claimed_head.is_empty() {
                    return Ok(AuditVerifyResult {
                        total_events: total,
                        first_broken_id: Some(r.id.clone()),
                        failure: Some(AuditVerifyFailure {
                            rowid: Some(r.rowid),
                            event_id: r.id.clone(),
                            event_type: r.event_type,
                            reason: VerifyFailureReason::CheckpointSignatureInvalid,
                        }),
                    });
                }

                // 2. Verify event count
                if event_count_since_checkpoint != claimed_count {
                    return Ok(AuditVerifyResult {
                        total_events: total,
                        first_broken_id: Some(r.id.clone()),
                        failure: Some(AuditVerifyFailure {
                            rowid: Some(r.rowid),
                            event_id: r.id.clone(),
                            event_type: r.event_type,
                            reason: VerifyFailureReason::CheckpointCountMismatch,
                        }),
                    });
                }

                // 3. Verify Ed25519 signature if verifier available
                if let Some(v) = verifier {
                    let sig_bytes = match hex::decode(signature_hex) {
                        Ok(b) => b,
                        Err(_) => {
                            return Ok(AuditVerifyResult {
                                total_events: total,
                                first_broken_id: Some(r.id.clone()),
                                failure: Some(AuditVerifyFailure {
                                    rowid: Some(r.rowid),
                                    event_id: r.id.clone(),
                                    event_type: r.event_type,
                                    reason: VerifyFailureReason::CheckpointSignatureInvalid,
                                }),
                            });
                        }
                    };
                    let msg = format!(
                        "audit-checkpoint:v1|{}|{}|{}",
                        claimed_head, claimed_count, r.created_at
                    );
                    let valid = if key_id.is_empty() {
                        v.verify(msg.as_bytes(), &sig_bytes)
                    } else {
                        v.verify_with_key(key_id, msg.as_bytes(), &sig_bytes)
                    };
                    if !valid {
                        return Ok(AuditVerifyResult {
                            total_events: total,
                            first_broken_id: Some(r.id.clone()),
                            failure: Some(AuditVerifyFailure {
                                rowid: Some(r.rowid),
                                event_id: r.id.clone(),
                                event_type: r.event_type,
                                reason: VerifyFailureReason::CheckpointSignatureInvalid,
                            }),
                        });
                    }
                }

                event_count_since_checkpoint = 0;
            } else {
                event_count_since_checkpoint += 1;
            }

            expected_prev = Some(r.event_hash);
        }

        Ok(AuditVerifyResult {
            total_events: total,
            first_broken_id: None,
            failure: None,
        })
    }

    fn purge_old(&self, before: &str) -> Result<u32, AppError> {
        let conn = self.conn.lock();
        let n = conn
            .execute(
                "DELETE FROM audit_events WHERE created_at < ?1",
                rusqlite::params![before],
            )
            .map_err(db_err("audit: purge_old"))?;
        Ok(n as u32)
    }

    fn purge_authenticated(
        &self,
        before: &str,
        signer: &dyn dbward_app::ports::crypto::AuditSigner,
    ) -> Result<(u32, String), AppError> {
        let mut conn = self.conn.lock();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(db_err("audit: purge begin"))?;

        // Find the latest signed checkpoint AT OR BEFORE the cutoff
        let checkpoint: Option<(i64, String)> = match tx.query_row(
            "SELECT rowid, event_hash FROM audit_events WHERE event_type = 'audit.signed_checkpoint' AND created_at <= ?1 ORDER BY rowid DESC LIMIT 1",
            rusqlite::params![before],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ) {
            Ok(v) => Some(v),
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(e) => return Err(AppError::Internal(format!("purge checkpoint query: {e}"))),
        };

        let Some((checkpoint_rowid, last_hash)) = checkpoint else {
            return Err(AppError::Validation(
                "no signed checkpoint found before cutoff; purge refused".into(),
            ));
        };

        // Delete all rows up to and including that checkpoint
        let deleted = tx
            .execute(
                "DELETE FROM audit_events WHERE rowid <= ?1",
                rusqlite::params![checkpoint_rowid],
            )
            .map_err(db_err("audit: purge_authenticated delete"))?;

        // Count retained
        let retained: i64 = tx
            .query_row("SELECT COUNT(*) FROM audit_events", [], |row| row.get(0))
            .map_err(db_err("audit: purge_authenticated count"))?;

        // Sign the purge checkpoint
        let key_id = signer.current_key_id().to_string();
        let now = chrono::Utc::now();
        let payload = format!("purge-checkpoint:v1|{}|{}|{}", last_hash, before, retained);
        let sig = hex::encode(signer.sign(payload.as_bytes()));
        let checkpoint_id = uuid::Uuid::new_v4().to_string();

        tx.execute(
            "INSERT INTO audit_purge_checkpoints (id, purged_before, last_purged_hash, retained_count, key_id, signature, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            rusqlite::params![
                checkpoint_id,
                before,
                last_hash,
                retained,
                key_id,
                sig,
                now.to_rfc3339(),
            ],
        ).map_err(db_err("audit: purge_authenticated checkpoint"))?;

        // Insert audit.purge_checkpoint event into main chain (informational)
        let purge_event = dbward_domain::entities::AuditEvent {
            id: String::new(),
            event_type: "audit.purge_checkpoint".to_string(),
            event_category: dbward_domain::entities::EventCategory::Policy,
            event_version: 1,
            outcome: dbward_domain::entities::EventOutcome::Info,
            actor_id: "system".to_string(),
            actor_type: dbward_domain::entities::ActorType::System,
            resource_type: None,
            resource_id: None,
            peer_ip: None,
            client_ip: None,
            client_ip_source: None,
            request_id: None,
            operation: None,
            database_name: None,
            environment: None,
            detail_fingerprint: None,
            detail_raw: None,
            reason: None,
            metadata_json: serde_json::json!({
                "purged_before": before,
                "last_purged_hash": last_hash,
                "retained_count": retained,
            })
            .to_string(),
            prev_hash: None,
            event_hash: String::new(),
            created_at: now,
        };
        super::audit_helper::insert_audit_event_raw(&tx, &purge_event)
            .map_err(|e| AppError::Internal(format!("purge audit event: {e}")))?;

        tx.commit().map_err(db_err("audit: purge commit"))?;

        Ok((deleted as u32, checkpoint_id))
    }
}

pub(crate) fn category_str(c: EventCategory) -> &'static str {
    match c {
        EventCategory::Approval => "approval",
        EventCategory::Execution => "execution",
        EventCategory::Agent => "agent",
        EventCategory::Auth => "auth",
        EventCategory::Token => "token",
        EventCategory::Identity => "identity",
        EventCategory::Policy => "policy",
        EventCategory::Request => "request",
        EventCategory::Preflight => "preflight",
    }
}

fn parse_category(s: &str) -> EventCategory {
    EventCategory::parse(s)
}

pub(crate) fn outcome_str(o: EventOutcome) -> &'static str {
    match o {
        EventOutcome::Success => "success",
        EventOutcome::Denied => "denied",
        EventOutcome::Failure => "failure",
        EventOutcome::Info => "info",
    }
}

fn parse_outcome(s: &str) -> EventOutcome {
    match s {
        "success" => EventOutcome::Success,
        "denied" => EventOutcome::Denied,
        "failure" => EventOutcome::Failure,
        _ => EventOutcome::Info,
    }
}

pub(crate) fn actor_type_str(a: ActorType) -> &'static str {
    match a {
        ActorType::User => "user",
        ActorType::Agent => "agent",
        ActorType::System => "system",
    }
}

fn parse_actor_type(s: &str) -> ActorType {
    match s {
        "user" => ActorType::User,
        "agent" => ActorType::Agent,
        _ => ActorType::System,
    }
}

fn row_to_audit_event(row: &rusqlite::Row) -> rusqlite::Result<AuditEvent> {
    let category_str: String = row.get(2)?;
    let outcome_str: String = row.get(4)?;
    let actor_type_str: String = row.get(6)?;
    let created_str: String = row.get(22)?;

    Ok(AuditEvent {
        id: row.get(0)?,
        event_type: row.get(1)?,
        event_category: parse_category(&category_str),
        event_version: row.get(3)?,
        outcome: parse_outcome(&outcome_str),
        actor_id: row.get(5)?,
        actor_type: parse_actor_type(&actor_type_str),
        resource_type: row.get(7)?,
        resource_id: row.get(8)?,
        peer_ip: row.get(9)?,
        client_ip: row.get(10)?,
        client_ip_source: row.get(11)?,
        request_id: row.get(12)?,
        operation: row.get(13)?,
        database_name: row.get(14)?,
        environment: row.get(15)?,
        detail_fingerprint: row.get(16)?,
        detail_raw: row.get(17)?,
        reason: row.get(18)?,
        metadata_json: row.get(19)?,
        prev_hash: row.get(20)?,
        event_hash: row.get(21)?,
        created_at: super::parse_datetime(&created_str)?,
    })
}

/// A2: Generate retroactive purge checkpoint for pre-v0.1.6 deployments.
/// If the first audit_events row has a prev_hash pointing to a deleted predecessor
/// and no corresponding entry in audit_purge_checkpoints, generate one.
pub fn migrate_legacy_purge_boundary(
    conn: &super::DbConn,
    signer: &dyn dbward_app::ports::crypto::AuditSigner,
) {
    let guard = conn.lock();
    let first_prev: Option<String> = guard
        .query_row(
            "SELECT prev_hash FROM audit_events ORDER BY rowid ASC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .ok();

    let Some(prev_hash) = first_prev else {
        return; // No events or first event has NULL prev_hash (fresh chain)
    };

    // Check if checkpoint already exists
    let exists: bool = guard
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM audit_purge_checkpoints WHERE last_purged_hash = ?1)",
            rusqlite::params![&prev_hash],
            |row| row.get(0),
        )
        .unwrap_or(false);

    if exists {
        return; // Already migrated
    }

    // Generate retroactive checkpoint
    let retained: i64 = guard
        .query_row("SELECT COUNT(*) FROM audit_events", [], |row| row.get(0))
        .unwrap_or(0);

    let payload = format!(
        "purge-checkpoint:v1|{}|{}|{}",
        prev_hash, "legacy-migration", retained
    );
    let sig = signer.sign(payload.as_bytes());
    let sig_hex = hex::encode(&sig);
    let id = format!("purge-legacy-{}", &prev_hash[..8.min(prev_hash.len())]);
    let now = chrono::Utc::now().to_rfc3339();

    if let Err(e) = guard.execute(
        "INSERT OR IGNORE INTO audit_purge_checkpoints (id, purged_before, last_purged_hash, retained_count, signature, key_id, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![id, "legacy-migration", prev_hash, retained, sig_hex, signer.current_key_id(), now],
    ) {
        tracing::warn!(error = %e, "failed to insert legacy purge checkpoint (may already exist)");
    } else {
        tracing::info!("generated legacy purge checkpoint for pre-v0.1.6 boundary");
    }
}
