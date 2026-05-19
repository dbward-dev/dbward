use dbward_app::ports::WebhookEvent;
use serde_json::{Value, json};

/// Build Block Kit blocks for a new approval request.
pub fn build_request_created(event: &WebhookEvent) -> Vec<Value> {
    let requester = event.requester.as_deref().unwrap_or("unknown");
    let db = event.database.as_deref().unwrap_or("—");
    let env = event.environment.as_deref().unwrap_or("—");
    let operation = event.operation.as_deref().unwrap_or("—");
    let req_id = event.request_id.as_deref().unwrap_or("—");
    let short_id = &req_id[..req_id.len().min(12)];

    let (emoji, title) = match event.event_type.as_str() {
        "break_glass" => ("🚨", "Break-Glass Request"),
        "request_auto_approved" => ("⚡", "Auto-Approved"),
        _ => ("📋", "New Approval Request"),
    };

    let mut blocks: Vec<Value> = vec![
        json!({
            "type": "header",
            "text": {"type": "plain_text", "text": format!("{emoji} {title}")}
        }),
        json!({
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": format!("*Requester:*\n{requester}")},
                {"type": "mrkdwn", "text": format!("*Database:*\n{db} / {env}")},
                {"type": "mrkdwn", "text": format!("*Operation:*\n{operation}")},
                {"type": "mrkdwn", "text": format!("*Request ID:*\n`{short_id}`")}
            ]
        }),
    ];

    if let Some(ref sql) = event.redacted_detail {
        let truncated: String = sql.chars().take(500).collect();
        blocks.push(json!({
            "type": "section",
            "text": {"type": "mrkdwn", "text": format!("```{truncated}```")}
        }));
    }

    // Step progress context
    if let (Some(step), Some(total)) = (event.step_index, event.total_steps) {
        let expires_info = event
            .expires_at
            .as_deref()
            .map(|e| format!(" • Expires: {e}"))
            .unwrap_or_default();
        blocks.push(json!({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": format!("📋 Step {}/{total}{expires_info}", step + 1)}]
        }));
    }

    // Approve/reject buttons (only for requests needing approval)
    if event.event_type == "request_created" {
        blocks.push(json!({
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "✅ Approve"},
                    "style": "primary",
                    "action_id": "dbward_approve",
                    "value": req_id
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "❌ Reject"},
                    "style": "danger",
                    "action_id": "dbward_reject",
                    "value": req_id
                }
            ]
        }));
    }

    blocks
}

/// Build blocks for a thread reply (approval/rejection/completion notification).
pub fn build_thread_reply(event: &WebhookEvent) -> Vec<Value> {
    let actor = event.actor.as_deref().unwrap_or("system");

    let (emoji, text) = match event.event_type.as_str() {
        "step_approved" => {
            let step_info = match (event.step_index, event.total_steps) {
                (Some(s), Some(t)) => format!(" (step {}/{})", s + 1, t),
                _ => String::new(),
            };
            ("✅", format!("Approved by {actor}{step_info}"))
        }
        "request_approved" => ("✅", format!("Approved by {actor}")),
        "request_rejected" => {
            let reason = event
                .reason
                .as_deref()
                .map(|r| format!(": {r}"))
                .unwrap_or_default();
            ("❌", format!("Rejected by {actor}{reason}"))
        }
        "request_completed" => ("🎉", "Execution completed successfully".into()),
        "request_failed" => {
            let err = event.error_summary.as_deref().unwrap_or("unknown error");
            ("⚠️", format!("Execution failed: {err}"))
        }
        "request_expired" => ("⏰", "Request expired".into()),
        "execution_lost" => ("💀", "Execution lost (agent disconnected)".into()),
        "request_cancelled" => {
            let reason = event
                .reason
                .as_deref()
                .map(|r| format!(": {r}"))
                .unwrap_or_default();
            ("🚫", format!("Cancelled{reason}"))
        }
        _ => ("🔔", format!("{}: {actor}", event.event_type)),
    };

    vec![json!({
        "type": "section",
        "text": {"type": "mrkdwn", "text": format!("{emoji} {text}")}
    })]
}

/// Build updated blocks for the original message after resolution.
pub fn build_resolved_message(event: &WebhookEvent, original_blocks: &[Value]) -> Vec<Value> {
    // Keep header and info sections, replace actions with status
    let mut blocks: Vec<Value> = original_blocks
        .iter()
        .filter(|b| b["type"].as_str() != Some("actions"))
        .cloned()
        .collect();

    let actor = event.actor.as_deref().unwrap_or("system");
    let status_text = match event.event_type.as_str() {
        "request_approved" => format!("✅ Approved by {actor}"),
        "request_rejected" => format!("❌ Rejected by {actor}"),
        "request_expired" => "⏰ Expired".into(),
        "request_cancelled" => "🚫 Cancelled".into(),
        _ => return blocks,
    };

    blocks.push(json!({
        "type": "context",
        "elements": [{"type": "mrkdwn", "text": status_text}]
    }));

    blocks
}

/// Fallback text (shown in notifications/previews).
pub fn fallback_text(event: &WebhookEvent) -> String {
    let req_id = event.request_id.as_deref().unwrap_or("—");
    match event.event_type.as_str() {
        "request_created" => format!("📋 New approval request {req_id}"),
        "request_approved" => format!("✅ Request {req_id} approved"),
        "request_rejected" => format!("❌ Request {req_id} rejected"),
        "request_completed" => format!("🎉 Request {req_id} completed"),
        "request_failed" => format!("⚠️ Request {req_id} failed"),
        _ => format!("🔔 {}: {req_id}", event.event_type),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event() -> WebhookEvent {
        WebhookEvent {
            event_type: "request_created".into(),
            request_id: Some("req-abc12345".into()),
            database: Some("app".into()),
            environment: Some("production".into()),
            actor: Some("alice".into()),
            detail: None,
            requester: Some("alice".into()),
            reason: None,
            redacted_detail: Some("DELETE FROM orders WHERE created_at < ?".into()),
            error_summary: None,
            approval_hint: None,
            operation: Some("execute_dml".into()),
            step_index: Some(0),
            total_steps: Some(2),
            expires_at: None,
        }
    }

    #[test]
    fn request_created_has_approve_reject_buttons() {
        let blocks = build_request_created(&sample_event());
        let actions = blocks.iter().find(|b| b["type"] == "actions");
        assert!(actions.is_some());
        let elements = actions.unwrap()["elements"].as_array().unwrap();
        assert_eq!(elements.len(), 2);
        assert_eq!(elements[0]["action_id"], "dbward_approve");
        assert_eq!(elements[1]["action_id"], "dbward_reject");
    }

    #[test]
    fn break_glass_has_no_buttons() {
        let mut event = sample_event();
        event.event_type = "break_glass".into();
        let blocks = build_request_created(&event);
        let actions = blocks.iter().find(|b| b["type"] == "actions");
        assert!(actions.is_none());
    }

    #[test]
    fn thread_reply_formats_correctly() {
        let mut event = sample_event();
        event.event_type = "request_approved".into();
        let blocks = build_thread_reply(&event);
        let text = blocks[0]["text"]["text"].as_str().unwrap();
        assert!(text.contains("Approved by alice"));
    }
}
