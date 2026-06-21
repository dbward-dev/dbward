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
    audit_event.database_name = Some(event.database.as_str().to_string());
    audit_event.environment = Some(event.environment.as_str().to_string());
    audit_event.operation = Some(event.operation.as_str().to_string());

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
            audit_event.metadata_json = meta.to_string();
        }
        _ => {}
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
            EventMetadata::Created { detail, .. } => Some(detail.clone()),
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
