//! Pure-function audit event construction from TransitionEvents.
//!
//! Extracted from CompositeEventDispatcher to be usable inside UoW closures.

use chrono::{DateTime, Utc};
use dbward_domain::entities::{AuditEvent, RequestStatus};
use dbward_domain::services::status_machine::{EventMetadata, TransitionEvent};

/// SQL literal redaction mode for audit detail field.
#[derive(Clone, Copy, Default)]
pub enum RedactionMode {
    None,
    #[default]
    Literals,
    Full,
}

/// Build an AuditEvent from a TransitionEvent.
///
/// This is a pure function with no side effects — suitable for use inside UoW closures.
pub fn build_audit_event(
    event: &TransitionEvent,
    now: DateTime<Utc>,
    redaction_mode: RedactionMode,
    redact_fn: impl Fn(&str) -> String,
) -> AuditEvent {
    let (event_type, category) = event_type_and_category(event);

    let mut audit_event = AuditEvent::simple(
        event_type,
        category,
        &event.actor_id,
        Some(&event.request_id),
        now,
        &event.audit_context,
    );
    audit_event.request_id = Some(event.request_id.clone());
    audit_event.database_name = Some(event.database.as_str().to_string());
    audit_event.environment = Some(event.environment.as_str().to_string());
    audit_event.operation = Some(event.operation.as_str().to_string());

    // For execution events, resource_id should be the execution_id (the entity key),
    // not the request_id (which is the correlation key stored in request_id field).
    match &event.metadata {
        EventMetadata::Claimed { execution_id, .. }
        | EventMetadata::Completed { execution_id, .. }
        | EventMetadata::ExecutionLost { execution_id } => {
            audit_event.resource_id = Some(execution_id.clone());
        }
        _ => {}
    }

    if let EventMetadata::Created { ref detail, .. } = event.metadata {
        audit_event.detail_fingerprint = Some(redact_fn(detail));
        match redaction_mode {
            RedactionMode::None => audit_event.detail_raw = Some(detail.clone()),
            RedactionMode::Literals => audit_event.detail_raw = Some(redact_fn(detail)),
            RedactionMode::Full => {}
        }
    }

    if let EventMetadata::Rejected { ref comment, .. } = event.metadata {
        audit_event.reason = comment.clone();
    }

    match &event.metadata {
        EventMetadata::Approved {
            comment,
            matched_selector,
        } => {
            let mut meta = parse_metadata_object(&audit_event.metadata_json);
            if let Some(c) = comment {
                meta["approval_comment"] = serde_json::Value::String(c.clone());
            }
            meta["matched_selector"] = serde_json::Value::String(matched_selector.clone());
            if let Some(ref tid) = event.auth_token_id {
                meta["auth_token_id"] = serde_json::Value::String(tid.clone());
            }
            audit_event.metadata_json = meta.to_string();
        }
        EventMetadata::StepApproved {
            comment,
            step_index,
            total_steps,
            matched_selector,
        } => {
            let mut meta = parse_metadata_object(&audit_event.metadata_json);
            if let Some(c) = comment {
                meta["approval_comment"] = serde_json::Value::String(c.clone());
            }
            meta["step_number"] = (*step_index + 1).into();
            meta["total_steps"] = (*total_steps).into();
            meta["matched_selector"] = serde_json::Value::String(matched_selector.clone());
            if let Some(ref tid) = event.auth_token_id {
                meta["auth_token_id"] = serde_json::Value::String(tid.clone());
            }
            audit_event.metadata_json = meta.to_string();
        }
        _ => {
            // For all other events, still record auth_token_id if present
            if let Some(ref tid) = event.auth_token_id {
                let mut meta = parse_metadata_object(&audit_event.metadata_json);
                meta["auth_token_id"] = serde_json::Value::String(tid.clone());
                audit_event.metadata_json = meta.to_string();
            }
        }
    }

    audit_event
}

/// Map TransitionEvent to (event_type, category) strings.
/// Uses new dotted format for V2 events.
pub fn event_type_and_category(event: &TransitionEvent) -> (&'static str, &'static str) {
    match &event.metadata {
        EventMetadata::Created {
            emergency: true, ..
        } => ("request.break_glass", "approval"),
        EventMetadata::Created { .. } if event.new_status == RequestStatus::AutoApproved => {
            ("request.auto_approved", "approval")
        }
        EventMetadata::Created { .. } => ("request.created", "approval"),
        EventMetadata::StepApproved { .. } => ("step.approved", "approval"),
        EventMetadata::Approved { .. } => ("request.approved", "approval"),
        EventMetadata::Rejected { .. } => ("request.rejected", "approval"),
        EventMetadata::Cancelled { .. } => ("request.cancelled", "approval"),
        EventMetadata::Dispatched => ("request.dispatched", "approval"),
        EventMetadata::Claimed { .. } => ("execution.started", "execution"),
        EventMetadata::Completed { success: true, .. } => ("execution.completed", "execution"),
        EventMetadata::Completed { success: false, .. } => ("execution.failed", "execution"),
        EventMetadata::ExecutionLost { .. } => ("execution.lost", "agent"),
        EventMetadata::Expired => ("request.expired", "approval"),
    }
}

fn parse_metadata_object(json_str: &str) -> serde_json::Value {
    serde_json::from_str::<serde_json::Value>(json_str)
        .ok()
        .filter(|v| v.is_object())
        .unwrap_or_else(|| serde_json::json!({}))
}

/// No-op redaction function (passes detail through unchanged).
pub fn noop_redact(s: &str) -> String {
    s.to_string()
}

/// Build a WebhookEvent from a TransitionEvent for post-commit notification.
pub fn build_webhook_event(event: &TransitionEvent) -> crate::ports::WebhookEvent {
    use dbward_domain::services::status_machine::EventMetadata;
    let (event_type, _) = event_type_and_category(event);

    crate::ports::WebhookEvent {
        event_type: event_type.to_string(),
        request_id: Some(event.request_id.clone()),
        database: Some(event.database.as_str().to_string()),
        environment: Some(event.environment.as_str().to_string()),
        actor: Some(event.actor_id.clone()),
        detail: None,
        requester: Some(event.requester_id.clone()),
        operation: Some(event.operation.as_str().to_string()),
        reason: match &event.metadata {
            EventMetadata::Rejected { comment, .. } => comment.clone(),
            EventMetadata::Cancelled { reason, .. } => reason.clone(),
            _ => None,
        },
        redacted_detail: match &event.metadata {
            EventMetadata::Created { detail, .. } => {
                Some(redact_webhook_detail(event.operation.as_str(), detail))
            }
            _ => None,
        },
        error_summary: match &event.metadata {
            EventMetadata::Completed {
                success: false,
                execution_id,
            } => Some(format!("execution {} failed", execution_id)),
            EventMetadata::ExecutionLost { execution_id } => {
                Some(format!("execution {} lost", execution_id))
            }
            _ => None,
        },
        approval_hint: None,
        step_index: match &event.metadata {
            EventMetadata::StepApproved { step_index, .. } => Some(*step_index),
            _ => None,
        },
        total_steps: match &event.metadata {
            EventMetadata::StepApproved { total_steps, .. } => Some(*total_steps),
            _ => None,
        },
        expires_at: None,
        approvers: None,
        matched_selector: match &event.metadata {
            EventMetadata::StepApproved {
                matched_selector, ..
            }
            | EventMetadata::Approved {
                matched_selector, ..
            } => Some(matched_selector.clone()),
            _ => None,
        },
    }
}

/// Redact webhook detail: summarize version list for migrate operations,
/// pass through unchanged for normal queries (users filter externally).
fn redact_webhook_detail(operation: &str, detail: &str) -> String {
    match operation {
        "migrate_up" | "migrate_down" => summarize_migrate_detail(operation, detail),
        _ => detail.to_string(),
    }
}

/// Parse migrate detail JSON and produce a human-readable summary without SQL content.
fn summarize_migrate_detail(operation: &str, detail: &str) -> String {
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(detail);
    match parsed {
        Ok(v) => {
            let versions = v["versions"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .map(sanitize_version)
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .unwrap_or_default();
            let max_count = v["max_count"].as_u64();
            match max_count {
                Some(n) => format!("{operation}: versions=[{versions}] max_count={n}"),
                None => format!("{operation}: versions=[{versions}]"),
            }
        }
        Err(_) => format!("{operation}: <parse error>"),
    }
}

/// Sanitize a version string: only allow alphanumeric, underscore, hyphen, dot.
/// Anything else is replaced to prevent injection of SQL or sensitive content.
fn sanitize_version(v: &str) -> String {
    if v.len() > 64
        || v.chars()
            .any(|c| !c.is_ascii_alphanumeric() && c != '_' && c != '-' && c != '.')
    {
        format!("<invalid:{}>", v.len())
    } else {
        v.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use dbward_domain::entities::{AuditContext, RequestStatus};
    use dbward_domain::services::status_machine::{EventMetadata, TransitionEvent};
    use dbward_domain::values::{DatabaseName, Environment, Operation};

    fn make_event(metadata: EventMetadata) -> TransitionEvent {
        TransitionEvent {
            request_id: "req-001".to_string(),
            previous_status: RequestStatus::Approved,
            new_status: RequestStatus::Running,
            actor_id: "agent-1".to_string(),
            actor_type: dbward_domain::auth::SubjectType::Agent,
            database: DatabaseName::new("testdb").unwrap(),
            environment: Environment::new("production").unwrap(),
            operation: Operation::ExecuteSelect,
            timestamp: Utc::now(),
            metadata,
            requester_id: "user-alice".to_string(),
            audit_context: AuditContext::System,
            auth_token_id: None,
        }
    }

    #[test]
    fn p0_claimed_sets_execution_id_as_resource_id_and_request_id() {
        let event = make_event(EventMetadata::Claimed {
            execution_id: "exec-123".to_string(),
            agent_id: "agent-1".to_string(),
        });
        let audit = build_audit_event(&event, Utc::now(), RedactionMode::Full, noop_redact);
        assert_eq!(audit.resource_id.as_deref(), Some("exec-123"));
        assert_eq!(audit.request_id.as_deref(), Some("req-001"));
    }

    #[test]
    fn p0_completed_sets_execution_id_as_resource_id_and_request_id() {
        let event = make_event(EventMetadata::Completed {
            success: true,
            execution_id: "exec-456".to_string(),
        });
        let audit = build_audit_event(&event, Utc::now(), RedactionMode::Full, noop_redact);
        assert_eq!(audit.resource_id.as_deref(), Some("exec-456"));
        assert_eq!(audit.request_id.as_deref(), Some("req-001"));
    }

    #[test]
    fn p0_execution_lost_sets_execution_id_as_resource_id_and_request_id() {
        let event = make_event(EventMetadata::ExecutionLost {
            execution_id: "exec-789".to_string(),
        });
        let audit = build_audit_event(&event, Utc::now(), RedactionMode::Full, noop_redact);
        assert_eq!(audit.resource_id.as_deref(), Some("exec-789"));
        assert_eq!(audit.request_id.as_deref(), Some("req-001"));
    }

    #[test]
    fn p0_created_keeps_request_id_as_resource_id() {
        let event = make_event(EventMetadata::Created {
            detail: "SELECT 1".to_string(),
            emergency: false,
        });
        let audit = build_audit_event(&event, Utc::now(), RedactionMode::Full, noop_redact);
        // Non-execution events keep request_id as resource_id
        assert_eq!(audit.resource_id.as_deref(), Some("req-001"));
        assert_eq!(audit.request_id.as_deref(), Some("req-001"));
    }

    #[test]
    fn p1b_webhook_passes_through_normal_query() {
        let event = make_event(EventMetadata::Created {
            detail: "SELECT * FROM users WHERE id = 42".to_string(),
            emergency: false,
        });
        let wh = build_webhook_event(&event);
        let detail = wh.redacted_detail.unwrap();
        // Normal queries pass through unchanged (users filter externally)
        assert_eq!(detail, "SELECT * FROM users WHERE id = 42");
    }

    #[test]
    fn p1b_webhook_summarizes_migrate_detail() {
        let mut event = make_event(EventMetadata::Created {
            detail: r#"{"format":"v2","direction":"up","versions":["100247","100301"],"migrations":[{"version":"100247","sql":"CREATE TABLE x()","transactional":true}],"dir_sha256":"abc","max_count":2}"#.to_string(),
            emergency: false,
        });
        event.operation = Operation::MigrateUp;
        let wh = build_webhook_event(&event);
        let detail = wh.redacted_detail.unwrap();
        assert!(
            detail.contains("migrate_up"),
            "should contain operation: {detail}"
        );
        assert!(
            detail.contains("100247"),
            "should contain versions: {detail}"
        );
        assert!(
            !detail.contains("CREATE TABLE"),
            "should not contain SQL: {detail}"
        );
    }

    #[test]
    fn p1b_webhook_migrate_parse_error_does_not_leak_sql() {
        let mut event = make_event(EventMetadata::Created {
            detail: "not valid json CREATE TABLE secret()".to_string(),
            emergency: false,
        });
        event.operation = Operation::MigrateUp;
        let wh = build_webhook_event(&event);
        let detail = wh.redacted_detail.unwrap();
        assert!(
            detail.contains("<parse error>"),
            "should indicate error: {detail}"
        );
        assert!(
            !detail.contains("CREATE TABLE"),
            "should not contain SQL: {detail}"
        );
    }
}
