use dbward_app::ports::{RequestContextRecord, WebhookEvent};
use dbward_domain::entities::{Request, RequestStatus};
use serde_json::{Value, json};

/// Build Block Kit blocks for channel notification (no SQL, single Review button).
pub fn build_request_created(
    event: &WebhookEvent,
    context: Option<&RequestContextRecord>,
) -> Vec<Value> {
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

    let mut fields = vec![
        json!({"type": "mrkdwn", "text": format!("*Requester:*\n{requester}")}),
        json!({"type": "mrkdwn", "text": format!("*Database:*\n{db} / {env}")}),
        json!({"type": "mrkdwn", "text": format!("*Operation:*\n{operation}")}),
    ];
    if let Some(ref approvers) = event.approvers
        && !approvers.is_empty()
    {
        fields.push(
            json!({"type": "mrkdwn", "text": format!("*Approvers:*\n{}", approvers.join(", "))}),
        );
    }
    fields.push(json!({"type": "mrkdwn", "text": format!("*Request ID:*\n`{short_id}`")}));

    let mut blocks: Vec<Value> = vec![
        json!({
            "type": "header",
            "text": {"type": "plain_text", "text": format!("{emoji} {title}")}
        }),
        json!({
            "type": "section",
            "fields": fields
        }),
    ];

    // Summary context (risk + step)
    let mut summary_parts: Vec<String> = Vec::new();
    if let Some(ctx) = context
        && let Some(ref risk_json) = ctx.risk_json
        && let Ok(risk) = serde_json::from_str::<Value>(risk_json)
    {
        let level = risk["level"].as_str().unwrap_or("Unknown");
        let risk_emoji = match level {
            "High" => "🔴",
            "Medium" => "🟡",
            "Low" => "🟢",
            _ => "⚪",
        };
        summary_parts.push(format!("{risk_emoji} Risk: {level}"));
    }
    if let (Some(step), Some(total)) = (event.step_index, event.total_steps) {
        summary_parts.push(format!("📋 Step {}/{total}", step + 1));
    }
    if !summary_parts.is_empty() {
        blocks.push(json!({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": summary_parts.join(" • ")}]
        }));
    }

    // Single "Review Request" button
    if event.event_type == "request_created" {
        blocks.push(json!({
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Review Request"},
                    "style": "primary",
                    "action_id": "dbward_review",
                    "value": req_id
                }
            ]
        }));
    }

    blocks
}

/// Build Review Modal: SQL + Context + Decision radio + Comment + Confirm checkbox.
pub fn build_review_modal(
    request_id: &str,
    sql: Option<&str>,
    context: Option<&RequestContextRecord>,
) -> Value {
    let mut blocks: Vec<Value> = Vec::new();

    // SQL
    if let Some(sql) = sql {
        let truncated: String = sql.chars().take(2000).collect();
        blocks.push(json!({
            "type": "section",
            "text": {"type": "mrkdwn", "text": format!("```{truncated}```")}
        }));
    }

    // Context Enrichment
    if let Some(ctx) = context {
        let mut ctx_lines: Vec<String> = Vec::new();

        if let Some(ref risk_json) = ctx.risk_json
            && let Ok(risk) = serde_json::from_str::<Value>(risk_json)
        {
            let level = risk["level"].as_str().unwrap_or("?");
            let factors: Vec<&str> = risk["factors"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
                .unwrap_or_default();
            let factors_str = if factors.is_empty() {
                String::new()
            } else {
                format!(" ({})", factors.join(", "))
            };
            ctx_lines.push(format!("Risk: {level}{factors_str}"));
        }

        if let Some(ref tables_json) = ctx.tables_json
            && let Ok(tables) = serde_json::from_str::<Vec<Value>>(tables_json)
        {
            for t in tables.iter().take(3) {
                let name = t["name"].as_str().unwrap_or("?");
                let rows = t["estimated_rows"].as_i64().unwrap_or(0);
                let has_cascade = t["constraints"]
                    .as_array()
                    .map(|cs| {
                        cs.iter()
                            .any(|c| c["on_delete"].as_str() == Some("CASCADE"))
                    })
                    .unwrap_or(false);
                let cascade = if has_cascade { " ⚠️ CASCADE" } else { "" };
                ctx_lines.push(format!("📊 {name}: ~{rows} rows{cascade}"));
            }
        }

        if let Some(ref review_json) = ctx.sql_review_json
            && let Ok(review) = serde_json::from_str::<Value>(review_json)
            && let Some(findings) = review["findings"].as_array()
        {
            for f in findings.iter().take(3) {
                let msg = f["message"].as_str().unwrap_or("");
                ctx_lines.push(format!("⚠️ {msg}"));
            }
        }

        if !ctx_lines.is_empty() {
            blocks.push(json!({
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": ctx_lines.join("\n")}]
            }));
        }
    }

    blocks.push(json!({"type": "divider"}));

    // Decision radio (required — inside input block)
    blocks.push(json!({
        "type": "input",
        "block_id": "decision_block",
        "element": {
            "type": "radio_buttons",
            "action_id": "decision_input",
            "options": [
                {"text": {"type": "plain_text", "text": "Approve"}, "value": "approve"},
                {"text": {"type": "plain_text", "text": "Reject"}, "value": "reject"}
            ]
        },
        "label": {"type": "plain_text", "text": "Decision"}
    }));

    // Comment (always required)
    blocks.push(json!({
        "type": "input",
        "block_id": "comment_block",
        "element": {
            "type": "plain_text_input",
            "action_id": "comment_input",
            "multiline": true,
            "placeholder": {"type": "plain_text", "text": "Reason or comment..."}
        },
        "label": {"type": "plain_text", "text": "Comment"}
    }));

    json!({
        "type": "modal",
        "callback_id": "dbward_review_modal",
        "private_metadata": request_id,
        "title": {"type": "plain_text", "text": "Review Request"},
        "submit": {"type": "plain_text", "text": "Submit"},
        "blocks": blocks
    })
}

/// Build blocks for a thread reply.
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
/// Build full message blocks from canonical request state (for chat.update).
pub fn build_message_from_state(
    req: &Request,
    workflow_json: Option<&str>,
    context: Option<&RequestContextRecord>,
    current_step: u32,
    reject_reason: Option<&str>,
) -> Vec<Value> {
    let requester = &req.requester;
    let db = req.database.as_str();
    let env = req.environment.as_str();
    let operation = req.operation.as_str();
    let short_id = &req.id[..req.id.len().min(12)];

    // Preserve special headers for break_glass / auto_approved
    let (emoji, title) = if req.emergency {
        ("🚨", "Break-Glass Request")
    } else {
        match req.status {
            RequestStatus::Pending => ("📋", "Approval Request"),
            RequestStatus::AutoApproved => ("⚡", "Auto-Approved"),
            RequestStatus::Approved | RequestStatus::BreakGlass => ("✅", "Request Approved"),
            RequestStatus::Dispatched | RequestStatus::Running => ("⏳", "Executing"),
            RequestStatus::Executed => ("✅", "Request Completed"),
            RequestStatus::Failed => ("❌", "Request Failed"),
            RequestStatus::Rejected => ("❌", "Request Rejected"),
            RequestStatus::Cancelled => ("🚫", "Request Cancelled"),
            RequestStatus::Expired => ("⏰", "Request Expired"),
            RequestStatus::ExecutionLost => ("⚠️", "Execution Lost"),
        }
    };

    // Fields
    let mut fields = vec![
        json!({"type": "mrkdwn", "text": format!("*Requester:*\n{requester}")}),
        json!({"type": "mrkdwn", "text": format!("*Database:*\n{db} / {env}")}),
        json!({"type": "mrkdwn", "text": format!("*Operation:*\n{operation}")}),
    ];
    if let Some(wf_json) = workflow_json
        && let Some(approvers_text) = format_approvers_field(wf_json, current_step)
    {
        fields.push(json!({"type": "mrkdwn", "text": format!("*Approvers:*\n{approvers_text}")}));
    }
    fields.push(json!({"type": "mrkdwn", "text": format!("*Request ID:*\n`{short_id}`")}));

    let mut blocks: Vec<Value> = vec![
        json!({"type": "header", "text": {"type": "plain_text", "text": format!("{emoji} {title}")}}),
        json!({"type": "section", "fields": fields}),
    ];

    // Context line (risk + step progress)
    let mut ctx_parts: Vec<String> = Vec::new();
    if let Some(ctx) = context
        && let Some(ref risk_json) = ctx.risk_json
        && let Ok(risk) = serde_json::from_str::<Value>(risk_json)
    {
        let level = risk["level"].as_str().unwrap_or("Unknown");
        let risk_emoji = match level {
            "High" => "🔴",
            "Medium" => "🟡",
            "Low" => "🟢",
            _ => "⚪",
        };
        ctx_parts.push(format!("{risk_emoji} Risk: {level}"));
    }
    // Step progress (from workflow, only if steps still pending)
    if let Some(wf_json) = workflow_json
        && let Ok(wf) = serde_json::from_str::<Value>(wf_json)
        && let Some(steps) = wf["steps"].as_array()
        && steps.len() > 1
        && (current_step as usize) < steps.len()
    {
        ctx_parts.push(format!("📋 Step {}/{}", current_step + 1, steps.len()));
    }
    if !ctx_parts.is_empty() {
        blocks.push(json!({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": ctx_parts.join(" • ")}]
        }));
    }

    // Status line for non-pending states (include actor where relevant)
    let status_text: Option<String> = match req.status {
        RequestStatus::Pending => None,
        RequestStatus::Approved | RequestStatus::AutoApproved | RequestStatus::BreakGlass => {
            Some("✅ Approved".into())
        }
        RequestStatus::Dispatched | RequestStatus::Running => Some("⏳ Executing...".into()),
        RequestStatus::Executed => Some("✅ Completed successfully".into()),
        RequestStatus::Failed => Some("❌ Execution failed".into()),
        RequestStatus::Rejected => {
            let reason = reject_reason.unwrap_or("");
            if reason.is_empty() {
                Some("❌ Rejected".into())
            } else {
                let truncated: String = reason.chars().take(100).collect();
                Some(format!("❌ Rejected: {truncated}"))
            }
        }
        RequestStatus::Cancelled => {
            let by = req.cancelled_by.as_deref().unwrap_or("");
            if by.is_empty() {
                Some("🚫 Cancelled".into())
            } else {
                Some(format!("🚫 Cancelled by {by}"))
            }
        }
        RequestStatus::Expired => Some("⏰ Expired".into()),
        RequestStatus::ExecutionLost => Some("⚠️ Execution lost — re-dispatch possible".into()),
    };
    if let Some(ref text) = status_text {
        blocks.push(json!({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": text}]
        }));
    }

    // Button: only for Pending (ExecutionLost cannot be approved via Slack)
    if req.status == RequestStatus::Pending {
        blocks.push(json!({
            "type": "actions",
            "elements": [{
                "type": "button",
                "text": {"type": "plain_text", "text": "Review Request"},
                "style": "primary",
                "action_id": "dbward_review",
                "value": &req.id
            }]
        }));
    }

    blocks
}

/// Fallback text.
pub fn fallback_text(event: &WebhookEvent) -> String {
    let req_id = event.request_id.as_deref().unwrap_or("—");
    match event.event_type.as_str() {
        "request_created" => format!("📋 New approval request {req_id}"),
        "break_glass" => format!("🚨 Break-glass request {req_id}"),
        "request_auto_approved" => format!("⚡ Auto-approved {req_id}"),
        "step_approved" => format!("✅ Step approved for {req_id}"),
        "request_approved" => format!("✅ Request {req_id} approved"),
        "request_rejected" => format!("❌ Request {req_id} rejected"),
        "request_cancelled" => format!("🚫 Request {req_id} cancelled"),
        "request_completed" => format!("🎉 Request {req_id} completed"),
        "request_failed" => format!("⚠️ Request {req_id} failed"),
        "request_expired" => format!("⏰ Request {req_id} expired"),
        "execution_lost" => format!("💀 Execution lost for {req_id}"),
        _ => format!("🔔 {}: {req_id}", event.event_type),
    }
}

/// Format workflow approvers for Slack field display.
/// Parses workflow_snapshot_json and produces human-readable text.
pub fn format_approvers_field(workflow_json: &str, current_step: u32) -> Option<String> {
    let wf: Value = serde_json::from_str(workflow_json).ok()?;
    let steps = wf["steps"].as_array()?;
    if steps.is_empty() {
        return None;
    }

    let format_step = |step: &Value| -> String {
        let mode = step["mode"].as_str().unwrap_or("any");
        let approvers = step["approvers"].as_array();
        let parts: Vec<String> = approvers
            .map(|arr| {
                arr.iter()
                    .map(|a| {
                        let sel = a["selector"].as_str().unwrap_or("?");
                        let min = a["min"].as_u64().unwrap_or(1);
                        if min > 1 {
                            format!("{min}× {sel}")
                        } else {
                            sel.to_string()
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
        let joiner = if mode == "all" { " AND " } else { " OR " };
        parts.join(joiner)
    };

    if steps.len() == 1 {
        Some(format_step(&steps[0]))
    } else {
        let mut lines: Vec<String> = Vec::new();
        for (i, step) in steps.iter().enumerate() {
            let prefix = if i == current_step as usize {
                "▶"
            } else if i < current_step as usize {
                "✓"
            } else {
                " "
            };
            lines.push(format!("{prefix} Step {}: {}", i + 1, format_step(step)));
        }
        Some(lines.join("\n"))
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
            approvers: None,
        }
    }

    #[test]
    fn channel_message_has_single_review_button() {
        let blocks = build_request_created(&sample_event(), None);
        let actions = blocks.iter().find(|b| b["type"] == "actions").unwrap();
        let elements = actions["elements"].as_array().unwrap();
        assert_eq!(elements.len(), 1);
        assert_eq!(elements[0]["action_id"], "dbward_review");
    }

    #[test]
    fn channel_message_has_no_sql() {
        let blocks = build_request_created(&sample_event(), None);
        let json_str = serde_json::to_string(&blocks).unwrap();
        assert!(!json_str.contains("DELETE FROM"));
    }

    #[test]
    fn review_modal_contains_sql_and_decision() {
        let modal = build_review_modal("req-123", Some("DELETE FROM orders"), None);
        let blocks_str = serde_json::to_string(&modal["blocks"]).unwrap();
        assert!(blocks_str.contains("DELETE FROM orders"));
        assert!(blocks_str.contains("decision_input"));
        assert!(blocks_str.contains("comment_input"));
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
