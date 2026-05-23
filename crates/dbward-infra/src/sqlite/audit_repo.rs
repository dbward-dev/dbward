use crate::sqlite::DbConn;
use dbward_app::error::AppError;
use dbward_app::ports::{AuditFilter, AuditLogger, AuditRepo, AuditVerifyResult};
use dbward_domain::entities::{ActorType, AuditEvent, EventCategory, EventOutcome};

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
        use sha2::{Digest, Sha256};

        let mut conn = self.conn.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|e| AppError::Internal(e.to_string()))?;

        // Get last hash for chain continuity
        let prev_hash: Option<String> = tx
            .query_row(
                "SELECT event_hash FROM audit_events ORDER BY rowid DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .ok();

        // Infra generates id if caller left it empty
        let id = if event.id.is_empty() {
            uuid::Uuid::new_v4().to_string()
        } else {
            event.id.clone()
        };

        // Infra computes event_hash from ALL content fields (tamper detection)
        let hash_input = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            id,
            event.event_type,
            event.actor_id,
            event.created_at.to_rfc3339(),
            prev_hash.as_deref().unwrap_or(""),
            outcome_str(event.outcome),
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
            rusqlite::params![
                id, event.event_type, category_str(event.event_category),
                event.event_version, outcome_str(event.outcome),
                event.actor_id, actor_type_str(event.actor_type),
                event.resource_type, event.resource_id,
                event.peer_ip, event.client_ip, event.client_ip_source,
                event.request_id, event.operation,
                event.database_name, event.environment,
                event.detail_fingerprint, event.detail_raw, event.reason,
                event.metadata_json, prev_hash, event_hash,
                event.created_at.to_rfc3339(),
            ],
        ).map_err(|e| AppError::Internal(e.to_string()))?;

        tx.commit().map_err(|e| AppError::Internal(e.to_string()))?;
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
        let conn = self.conn.lock().unwrap();

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
        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let rows = stmt
            .query_map(params_ref.as_slice(), row_to_audit_event)
            .map_err(|e| AppError::Internal(e.to_string()))?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| AppError::Internal(e.to_string()))
    }

    fn verify_chain(&self) -> Result<AuditVerifyResult, AppError> {
        use sha2::{Digest, Sha256};

        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, event_type, actor_id, created_at, prev_hash, event_hash, outcome, request_id, operation, database_name, environment, reason, detail_raw, metadata_json FROM audit_events ORDER BY rowid ASC"
        ).map_err(|e| AppError::Internal(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, Option<String>>(10)?,
                    row.get::<_, Option<String>>(11)?,
                    row.get::<_, Option<String>>(12)?,
                    row.get::<_, String>(13)?,
                ))
            })
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let mut total: u64 = 0;
        let mut expected_prev: Option<String> = None;

        for row in rows {
            let (
                id,
                event_type,
                actor_id,
                created_at,
                prev_hash,
                event_hash,
                outcome,
                request_id,
                operation,
                database_name,
                environment,
                reason,
                detail_raw,
                metadata_json,
            ) = row.map_err(|e| AppError::Internal(e.to_string()))?;
            total += 1;

            if prev_hash.as_deref() != expected_prev.as_deref() {
                return Ok(AuditVerifyResult {
                    total_events: total,
                    first_broken_id: Some(id),
                });
            }

            let hash_input = format!(
                "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
                id,
                event_type,
                actor_id,
                created_at,
                prev_hash.as_deref().unwrap_or(""),
                outcome,
                request_id.as_deref().unwrap_or(""),
                operation.as_deref().unwrap_or(""),
                database_name.as_deref().unwrap_or(""),
                environment.as_deref().unwrap_or(""),
                reason.as_deref().unwrap_or(""),
                detail_raw.as_deref().unwrap_or(""),
                metadata_json,
            );
            let computed = hex::encode(Sha256::digest(hash_input.as_bytes()));
            if computed != event_hash {
                return Ok(AuditVerifyResult {
                    total_events: total,
                    first_broken_id: Some(id),
                });
            }

            expected_prev = Some(event_hash);
        }

        Ok(AuditVerifyResult {
            total_events: total,
            first_broken_id: None,
        })
    }

    fn purge_old(&self, before: &str) -> Result<u32, AppError> {
        let conn = self.conn.lock().unwrap();
        let n = conn
            .execute(
                "DELETE FROM audit_events WHERE created_at < ?1",
                rusqlite::params![before],
            )
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(n as u32)
    }
}

fn category_str(c: EventCategory) -> &'static str {
    match c {
        EventCategory::Approval => "approval",
        EventCategory::Execution => "execution",
        EventCategory::Agent => "agent",
        EventCategory::Auth => "auth",
        EventCategory::Token => "token",
        EventCategory::Identity => "identity",
        EventCategory::Policy => "policy",
        EventCategory::Request => "request",
    }
}

fn parse_category(s: &str) -> EventCategory {
    EventCategory::parse(s)
}

fn outcome_str(o: EventOutcome) -> &'static str {
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

fn actor_type_str(a: ActorType) -> &'static str {
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
