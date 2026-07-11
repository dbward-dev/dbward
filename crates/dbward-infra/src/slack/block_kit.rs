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

    let (emoji, title) = crate::notification_display::event_display(&event.event_type);

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
    if let Some(ref reason) = event.reason
        && !reason.is_empty()
    {
        let truncated: String = reason
            .chars()
            .take(100)
            .collect::<String>()
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");
        fields.push(json!({"type": "mrkdwn", "text": format!("*Reason:*\n{truncated}")}));
    }

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
    if let (Some(step), Some(total)) = (event.step_index, event.total_steps)
        && total > 0
    {
        summary_parts.push(format!("📋 Step {}/{total}", step + 1));
    }
    if !summary_parts.is_empty() {
        blocks.push(json!({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": summary_parts.join(" • ")}]
        }));
    }

    // Single "Review Request" button
    if event.event_type == "request.created" {
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
    selector_options: Option<&[String]>,
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
        // DX-11: Explain results
        if let Some(ref explain_json) = ctx.explain_json
            && let Ok(explains) = serde_json::from_str::<Vec<Value>>(explain_json)
            && !explains.is_empty()
        {
            let mut explain_text = String::from("*📊 Execution Plan*\n```");
            for entry in explains.iter().take(5) {
                let sql_preview: String = entry["sql"]
                    .as_str()
                    .unwrap_or("")
                    .chars()
                    .take(60)
                    .collect::<String>()
                    .replace('`', "'");

                if let Some(plan) = entry.get("plan")
                    && !plan.is_null()
                {
                    let opts = dbward_app::services::explain_formatter::FormatOptions::slack();
                    let lines =
                        dbward_app::services::explain_formatter::format_explain_tree(entry, &opts);
                    let tree_text = lines.join("\n").replace('`', "'");
                    explain_text.push_str(&format!("{sql_preview}\n{tree_text}\n"));
                } else if let Some(err) = entry.get("error") {
                    let msg = err.as_str().unwrap_or("unavailable").replace('`', "'");
                    explain_text.push_str(&format!("{sql_preview}\n⚠️ {msg}\n"));
                } else {
                    explain_text.push_str(&format!("{sql_preview}\n⚠️ unavailable\n"));
                }
            }
            explain_text.push_str("```");
            // Truncate to Slack's 3000 char limit for mrkdwn (char-boundary safe)
            if explain_text.len() > 2900 {
                let boundary = explain_text
                    .char_indices()
                    .take_while(|(i, _)| *i <= 2900)
                    .last()
                    .map(|(i, _)| i)
                    .unwrap_or(2900);
                explain_text.truncate(boundary);
                explain_text.push_str("...```");
            }
            blocks.push(json!({
                "type": "section",
                "text": {"type": "mrkdwn", "text": explain_text}
            }));
        }

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

        if let Some(ref tables_json) = ctx.tables_json {
            let entries =
                dbward_app::services::tables_display::parse_tables_json(Some(tables_json));
            for entry in entries.iter().take(5) {
                let display_name = match &entry.schema_name {
                    Some(s) if s != "public" => format!("{}.{}", s, entry.name),
                    _ => entry.name.clone(),
                };
                let row_info = entry
                    .estimated_rows
                    .filter(|&r| r > 0)
                    .map(|r| format!(" (~{r} rows)"))
                    .unwrap_or_default();
                let cascade = if entry.has_cascade_fk {
                    let targets: String = entry
                        .cascade_targets
                        .iter()
                        .take(3)
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ");
                    let suffix = if entry.cascade_targets.len() > 3 {
                        format!(" +{}", entry.cascade_targets.len() - 3)
                    } else {
                        String::new()
                    };
                    format!(" ⚠️ CASCADE → {targets}{suffix}")
                } else {
                    String::new()
                };
                ctx_lines.push(format!("📊 {display_name}{row_info}{cascade}"));
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
            let ctx_text = ctx_lines.join("\n");
            let ctx_text = if ctx_text.chars().count() > 2800 {
                let truncated: String = ctx_text.chars().take(2800).collect();
                format!("{truncated}...")
            } else {
                ctx_text
            };
            blocks.push(json!({
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": ctx_text}]
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

    // Selector (only shown when user matches multiple approver groups)
    if let Some(options) = selector_options
        && options.len() >= 2
    {
        let select_opts: Vec<Value> = options
            .iter()
            .map(|s| json!({"text": {"type": "plain_text", "text": s}, "value": s}))
            .collect();
        blocks.push(json!({
                "type": "input",
                "block_id": "selector_block",
                "element": {
                    "type": "static_select",
                    "action_id": "selector_input",
                    "options": select_opts
                },
                "label": {"type": "plain_text", "text": "Approve as"},
                "hint": {"type": "plain_text", "text": "Required for Approve. You match multiple groups — select which role to approve as."}
            }));
    }

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
pub fn build_thread_reply(event: &WebhookEvent, mention_suffix: &str) -> Vec<Value> {
    let actor = event.actor.as_deref().unwrap_or("system");
    let (default_emoji, _) = crate::notification_display::event_display(&event.event_type);

    let (emoji, text) = match event.event_type.as_str() {
        "step.approved" => {
            let step_info = match (event.step_index, event.total_steps) {
                (Some(s), Some(t)) => format!(" (step {}/{})", s + 1, t),
                _ => String::new(),
            };
            let selector_info = event
                .matched_selector
                .as_deref()
                .map(|s| format!(" as {s}"))
                .unwrap_or_default();
            (
                default_emoji,
                format!("Step approved by {actor}{selector_info}{step_info}"),
            )
        }
        "request.approved" => {
            let selector_info = event
                .matched_selector
                .as_deref()
                .map(|s| format!(" as {s}"))
                .unwrap_or_default();
            (
                default_emoji,
                format!("Request approved by {actor}{selector_info}"),
            )
        }
        "request.rejected" => {
            let reason = event
                .reason
                .as_deref()
                .map(|r| format!(": {r}"))
                .unwrap_or_default();
            (default_emoji, format!("Rejected by {actor}{reason}"))
        }
        "execution.completed" => (default_emoji, "Execution completed successfully".into()),
        "execution.failed" => {
            let err = event.error_summary.as_deref().unwrap_or("unknown error");
            (default_emoji, format!("Execution failed: {err}"))
        }
        "request.expired" => (default_emoji, "Request expired".into()),
        "execution.lost" => (default_emoji, "Execution lost (agent disconnected)".into()),
        "request.cancelled" => {
            let reason = event
                .reason
                .as_deref()
                .map(|r| format!(": {r}"))
                .unwrap_or_default();
            (default_emoji, format!("Cancelled{reason}"))
        }
        "request.dispatched" => (default_emoji, format!("Dispatched by {actor}")),
        "request.dispatch_timeout" => (
            default_emoji,
            "Dispatch timed out — reverted to approved, ready for retry".into(),
        ),
        _ => (default_emoji, format!("{}: {actor}", event.event_type)),
    };

    let display_text = if mention_suffix.is_empty() {
        format!("{emoji} {text}")
    } else {
        format!("{emoji} {text}\n{mention_suffix}")
    };

    let blocks = vec![json!({
        "type": "section",
        "text": {"type": "mrkdwn", "text": display_text}
    })];

    blocks
}

/// Whether the "View Result" button should be shown for a request.
/// Failed results are always stored (even with no_result_store=true).
fn should_show_view_result(req: &Request) -> bool {
    matches!(req.status, RequestStatus::Executed | RequestStatus::Failed)
        && (!req.no_result_store || req.status == RequestStatus::Failed)
}

/// Build updated blocks for the original message after resolution.
/// Build full message blocks from canonical request state (for chat.update).
pub fn build_message_from_state(
    req: &Request,
    workflow_json: Option<&str>,
    context: Option<&RequestContextRecord>,
    current_step: u32,
    reject_reason: Option<&str>,
    requester_mention: Option<&str>,
    approvals: &[dbward_domain::entities::Approval],
) -> Vec<Value> {
    let requester = requester_mention.unwrap_or(&req.requester);
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
        && let Some(approvers_text) = format_approvers_field(
            wf_json,
            current_step,
            if approvals.is_empty() {
                None
            } else {
                Some(approvals)
            },
        )
    {
        fields.push(json!({"type": "mrkdwn", "text": format!("*Approvers:*\n{approvers_text}")}));
    }
    fields.push(json!({"type": "mrkdwn", "text": format!("*Request ID:*\n`{short_id}`")}));
    if let Some(ref reason) = req.reason
        && !reason.is_empty()
    {
        let truncated: String = reason
            .chars()
            .take(100)
            .collect::<String>()
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");
        fields.push(json!({"type": "mrkdwn", "text": format!("*Reason:*\n{truncated}")}));
    }

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
        // Check if current step has partial group satisfaction (mode=all)
        let step = &steps[current_step as usize];
        let mode = step["mode"].as_str().unwrap_or("any");
        let groups_suffix = if mode == "all" && !approvals.is_empty() {
            if let Some(approver_arr) = step["approvers"].as_array() {
                let total_groups = approver_arr.len();
                let satisfied = approver_arr
                    .iter()
                    .filter(|a| {
                        let sel = a["selector"].as_str().unwrap_or("");
                        let min = a["min"].as_u64().unwrap_or(1);
                        let count = approvals
                            .iter()
                            .filter(|ap| {
                                ap.step_index == current_step
                                    && ap.action == dbward_domain::entities::ApprovalAction::Approve
                                    && ap.matched_selector == sel
                            })
                            .count() as u64;
                        count >= min
                    })
                    .count();
                if satisfied > 0 && satisfied < total_groups {
                    format!(" ({satisfied}/{total_groups} groups approved)")
                } else {
                    String::new()
                }
            } else {
                String::new()
            }
        } else {
            String::new()
        };
        ctx_parts.push(format!(
            "📋 Step {}/{}{}",
            current_step + 1,
            steps.len(),
            groups_suffix
        ));
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
                let truncated: String = reason
                    .chars()
                    .take(100)
                    .collect::<String>()
                    .replace('&', "&amp;")
                    .replace('<', "&lt;")
                    .replace('>', "&gt;");
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
        RequestStatus::ExecutionLost => Some("⚠️ Execution lost — retry possible".into()),
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

    // DX-12: Resume button for Approved status
    if matches!(
        req.status,
        RequestStatus::Approved | RequestStatus::AutoApproved | RequestStatus::BreakGlass
    ) {
        blocks.push(json!({
            "type": "actions",
            "elements": [{
                "type": "button",
                "text": {"type": "plain_text", "text": "Resume"},
                "style": "primary",
                "action_id": "dbward_resume",
                "value": &req.id
            }]
        }));
    }

    // DX-13: View Result button for terminal states
    if should_show_view_result(req) {
        blocks.push(json!({
            "type": "actions",
            "elements": [{
                "type": "button",
                "text": {"type": "plain_text", "text": "View Result"},
                "style": "primary",
                "action_id": "dbward_view_result",
                "value": &req.id
            }]
        }));
    }

    blocks
}

/// DX-13: Build modal showing execution result.
pub fn build_result_modal(
    request_id: &str,
    sql: Option<&str>,
    data: &str,
    content_length: Option<u64>,
) -> Value {
    let mut blocks: Vec<Value> = Vec::new();

    // SQL
    if let Some(sql) = sql {
        let truncated: String = sql.chars().take(200).collect::<String>().replace('`', "'");
        blocks.push(json!({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": format!("```{}```", truncated)}]
        }));
    }

    let display = if let Ok(parsed) = serde_json::from_str::<Value>(data) {
        let mut cleaned = parsed.clone();
        if let Some(obj) = cleaned.as_object_mut() {
            obj.remove("truncated");
            obj.remove("truncation_reason");
            obj.remove("storage_backend");
            obj.remove("checksum_sha256");
        }
        serde_json::to_string_pretty(&cleaned).unwrap_or_else(|_| data.to_string())
    } else {
        data.to_string()
    }
    .replace('`', "'");

    let truncated = display.len() > 2500;
    let text: String = if truncated {
        let boundary = display
            .char_indices()
            .take_while(|(i, _)| *i <= 2500)
            .last()
            .map(|(i, _)| i)
            .unwrap_or(2500);
        format!("```{}```\n_...truncated_", &display[..boundary])
    } else {
        format!("```{}```", display)
    };

    blocks.push(json!({
        "type": "section",
        "text": {"type": "mrkdwn", "text": text}
    }));

    let size_str = content_length
        .map(|l| {
            if l > 1024 * 1024 {
                format!("{:.1} MB", l as f64 / (1024.0 * 1024.0))
            } else if l > 1024 {
                format!("{:.1} KB", l as f64 / 1024.0)
            } else {
                format!("{l} bytes")
            }
        })
        .unwrap_or_default();

    let hint = if truncated || content_length.unwrap_or(0) > 2500 {
        format!("Size: {size_str}\nRun `dbward request result {request_id}` for full output")
    } else if !size_str.is_empty() {
        format!("Size: {size_str}")
    } else {
        String::new()
    };

    if !hint.is_empty() {
        blocks.push(json!({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": hint}]
        }));
    }

    json!({
        "type": "modal",
        "title": {"type": "plain_text", "text": "Execution Result"},
        "blocks": blocks
    })
}

/// DX-13: Build modal for unavailable result.
pub fn build_result_modal_unavailable(request_id: &str, reason: &str) -> Value {
    json!({
        "type": "modal",
        "title": {"type": "plain_text", "text": "Execution Result"},
        "blocks": [{
            "type": "section",
            "text": {"type": "mrkdwn", "text": format!("⚠️ Result not available\n_{reason}_\n\nRequest: `{}`", &request_id[..8.min(request_id.len())])}
        }]
    })
}

/// Fallback text.
pub fn fallback_text(event: &WebhookEvent) -> String {
    let (emoji, _) = crate::notification_display::event_display(&event.event_type);
    let req_id = event.request_id.as_deref().unwrap_or("—");
    match event.event_type.as_str() {
        "request.created" => format!("{emoji} New approval request {req_id}"),
        "request.break_glass" => format!("{emoji} Break-glass request {req_id}"),
        "request.auto_approved" => format!("{emoji} Auto-approved {req_id}"),
        "step.approved" => format!("{emoji} Step approved for {req_id}"),
        "request.approved" => format!("{emoji} Request {req_id} approved"),
        "request.rejected" => format!("{emoji} Request {req_id} rejected"),
        "request.cancelled" => format!("{emoji} Request {req_id} cancelled"),
        "execution.completed" => format!("{emoji} Request {req_id} completed"),
        "execution.failed" => format!("{emoji} Request {req_id} failed"),
        "request.expired" => format!("{emoji} Request {req_id} expired"),
        "execution.lost" => format!("{emoji} Execution lost for {req_id}"),
        "request.dispatch_timeout" => format!("{emoji} Dispatch timeout for {req_id}"),
        _ => format!("{emoji} {}: {req_id}", event.event_type),
    }
}

/// Format workflow approvers for Slack field display.
/// Parses workflow_snapshot_json and produces human-readable text.
pub fn format_approvers_field(
    workflow_json: &str,
    current_step: u32,
    approvals: Option<&[dbward_domain::entities::Approval]>,
) -> Option<String> {
    let wf: Value = serde_json::from_str(workflow_json).ok()?;
    let steps = wf["steps"].as_array()?;
    if steps.is_empty() {
        return None;
    }

    let single_step = steps.len() == 1;

    let format_step = |step: &Value, step_idx: usize| -> String {
        let mode = step["mode"].as_str().unwrap_or("any");
        let approvers = step["approvers"].as_array();
        let parts: Vec<String> = approvers
            .map(|arr| {
                arr.iter()
                    .map(|a| {
                        let sel = a["selector"].as_str().unwrap_or("?");
                        let min = a["min"].as_u64().unwrap_or(1);
                        let label = if min > 1 {
                            format!("{min}× {sel}")
                        } else {
                            sel.to_string()
                        };
                        // Show progress for current step when approvals available
                        if let Some(appr) = approvals
                            && (step_idx == current_step as usize || single_step)
                        {
                            let count = appr
                                .iter()
                                .filter(|ap| {
                                    ap.step_index == step_idx as u32
                                        && ap.action
                                            == dbward_domain::entities::ApprovalAction::Approve
                                        && ap.matched_selector == sel
                                })
                                .count() as u64;
                            if count >= min {
                                format!("{label} ✓")
                            } else if count > 0 {
                                format!("{label} ({count}/{min})")
                            } else {
                                format!("{label} ⏳")
                            }
                        } else {
                            label
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
        let joiner = if mode == "all" { " AND " } else { " OR " };
        parts.join(joiner)
    };

    if single_step {
        Some(format_step(&steps[0], 0))
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
            lines.push(format!("{prefix} Step {}: {}", i + 1, format_step(step, i)));
        }
        Some(lines.join("\n"))
    }
}

/// Build confirmation modal before executing a resumed request.
pub fn build_resume_confirm_modal(request_id: &str, sql: &str, db: &str, env: &str) -> Value {
    let sql_display: String = sql.chars().take(2000).collect::<String>().replace('`', "'");
    let blocks: Vec<Value> = vec![
        json!({
            "type": "section",
            "text": {"type": "mrkdwn", "text": format!("*Database:* {db} / {env}")}
        }),
        json!({
            "type": "section",
            "text": {"type": "mrkdwn", "text": format!("```{sql_display}```")}
        }),
        json!({
            "type": "section",
            "text": {"type": "mrkdwn", "text": "⚠️ This will execute the query on the target database."}
        }),
    ];

    json!({
        "type": "modal",
        "callback_id": "dbward_resume_modal",
        "private_metadata": request_id,
        "title": {"type": "plain_text", "text": "Confirm Execution"},
        "submit": {"type": "plain_text", "text": "Execute"},
        "close": {"type": "plain_text", "text": "Cancel"},
        "blocks": blocks
    })
}

/// Build the "Create Request" modal for `/dbward` slash command.
/// `databases` should already be filtered to accessible pairs only.
pub fn build_create_request_modal(
    databases: &[(
        dbward_domain::values::DatabaseName,
        dbward_domain::values::Environment,
    )],
    prefill_sql: Option<&str>,
) -> Value {
    let mut options: Vec<Value> = databases
        .iter()
        .map(|(db, env)| {
            let value = format!("{}/{}", db.as_str(), env.as_str());
            let text = format!("{} / {}", db.as_str(), env.as_str());
            json!({
                "text": {"type": "plain_text", "text": text},
                "value": value
            })
        })
        .collect();
    options.sort_by(|a, b| {
        a["value"]
            .as_str()
            .unwrap_or("")
            .cmp(b["value"].as_str().unwrap_or(""))
    });
    options.truncate(100);

    if options.is_empty() {
        options.push(json!({
            "text": {"type": "plain_text", "text": "No databases available"},
            "value": "none/none"
        }));
    }

    let mut sql_element = json!({
        "type": "plain_text_input",
        "action_id": "sql_input",
        "multiline": true,
        "max_length": 3000,
        "placeholder": {"type": "plain_text", "text": "SELECT * FROM ..."}
    });
    if let Some(sql) = prefill_sql {
        let truncated: String = sql.chars().take(3000).collect();
        sql_element["initial_value"] = json!(truncated);
    }

    let blocks: Vec<Value> = vec![
        json!({
            "type": "input",
            "block_id": "db_env_block",
            "element": {
                "type": "static_select",
                "action_id": "db_env_input",
                "placeholder": {"type": "plain_text", "text": "Select database / environment"},
                "options": options
            },
            "label": {"type": "plain_text", "text": "Database / Environment"}
        }),
        json!({
            "type": "input",
            "block_id": "sql_block",
            "element": sql_element,
            "label": {"type": "plain_text", "text": "SQL"}
        }),
        json!({
            "type": "input",
            "block_id": "reason_block",
            "element": {
                "type": "plain_text_input",
                "action_id": "reason_input",
                "placeholder": {"type": "plain_text", "text": "Why do you need to run this query?"}
            },
            "label": {"type": "plain_text", "text": "Reason"}
        }),
    ];

    json!({
        "type": "modal",
        "callback_id": "dbward_create_modal",
        "title": {"type": "plain_text", "text": "Execute SQL"},
        "submit": {"type": "plain_text", "text": "Submit"},
        "blocks": blocks
    })
}
#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event() -> WebhookEvent {
        WebhookEvent {
            event_type: "request.created".into(),
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
            matched_selector: None,
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
        let modal = build_review_modal("req-123", Some("DELETE FROM orders"), None, None);
        let blocks_str = serde_json::to_string(&modal["blocks"]).unwrap();
        assert!(blocks_str.contains("DELETE FROM orders"));
        assert!(blocks_str.contains("decision_input"));
        assert!(blocks_str.contains("comment_input"));
    }

    #[test]
    fn thread_reply_formats_correctly() {
        let mut event = sample_event();
        event.event_type = "request.approved".into();
        let blocks = build_thread_reply(&event, "");
        let text = blocks[0]["text"]["text"].as_str().unwrap();
        assert!(text.contains("Request approved by alice"));
    }

    #[test]
    fn thread_reply_approved_has_no_button() {
        let mut event = sample_event();
        event.event_type = "request.approved".into();
        let blocks = build_thread_reply(&event, "");
        let actions = blocks.iter().find(|b| b["type"] == "actions");
        assert!(
            actions.is_none(),
            "approved thread reply should not have button (moved to channel)"
        );
    }

    #[test]
    fn thread_reply_non_approved_has_no_button() {
        let mut event = sample_event();
        event.event_type = "request.rejected".into();
        let blocks = build_thread_reply(&event, "");
        let actions = blocks.iter().find(|b| b["type"] == "actions");
        assert!(actions.is_none(), "rejected reply should not have actions");
    }

    #[test]
    fn review_modal_shows_explain_plan() {
        use dbward_app::ports::RequestContextRecord;
        let ctx = RequestContextRecord {
            request_id: "req-1".into(),
            status: "ready".into(),
            schema_snapshot_collected_at: None,
            tables_json: None,
            sql_review_json: None,
            risk_json: None,
            explain_json: Some(r#"[{"sql":"SELECT 1","plan":{"Plan":{"Node Type":"Result","Plan Rows":1,"Total Cost":0.01}}}]"#.into()),
            created_at: "2026-01-01".into(),
            updated_at: "2026-01-01".into(),
        };
        let modal = build_review_modal("req-1", Some("SELECT 1"), Some(&ctx), None);
        let blocks_str = serde_json::to_string(&modal["blocks"]).unwrap();
        assert!(blocks_str.contains("Execution Plan"));
        assert!(blocks_str.contains("Result"));
    }

    #[test]
    fn review_modal_shows_explain_error() {
        use dbward_app::ports::RequestContextRecord;
        let ctx = RequestContextRecord {
            request_id: "req-2".into(),
            status: "partial".into(),
            schema_snapshot_collected_at: None,
            tables_json: None,
            sql_review_json: None,
            risk_json: None,
            explain_json: Some(r#"[{"sql":"DROP TABLE x","error":"permission denied"}]"#.into()),
            created_at: "2026-01-01".into(),
            updated_at: "2026-01-01".into(),
        };
        let modal = build_review_modal("req-2", Some("DROP TABLE x"), Some(&ctx), None);
        let blocks_str = serde_json::to_string(&modal["blocks"]).unwrap();
        assert!(blocks_str.contains("permission denied"));
    }

    #[test]
    fn review_modal_no_explain_when_empty() {
        use dbward_app::ports::RequestContextRecord;
        let ctx = RequestContextRecord {
            request_id: "req-3".into(),
            status: "ready".into(),
            schema_snapshot_collected_at: None,
            tables_json: None,
            sql_review_json: None,
            risk_json: None,
            explain_json: Some("[]".into()),
            created_at: "2026-01-01".into(),
            updated_at: "2026-01-01".into(),
        };
        let modal = build_review_modal("req-3", Some("SELECT 1"), Some(&ctx), None);
        let blocks_str = serde_json::to_string(&modal["blocks"]).unwrap();
        assert!(!blocks_str.contains("Execution Plan"));
    }

    #[test]
    fn explain_truncation_is_char_safe() {
        use dbward_app::ports::RequestContextRecord;
        // Create a long explain with multibyte chars
        let long_sql = "あ".repeat(600);
        let explain = format!(
            r#"[{{"sql":"{}","plan":{{"Plan":{{"Node Type":"Seq Scan","Plan Rows":9999,"Total Cost":999.99}}}}}}]"#,
            long_sql
        );
        let ctx = RequestContextRecord {
            request_id: "req-4".into(),
            status: "ready".into(),
            schema_snapshot_collected_at: None,
            tables_json: None,
            sql_review_json: None,
            risk_json: None,
            explain_json: Some(explain),
            created_at: "2026-01-01".into(),
            updated_at: "2026-01-01".into(),
        };
        // Should not panic
        let modal = build_review_modal("req-4", Some("SELECT 1"), Some(&ctx), None);
        let blocks_str = serde_json::to_string(&modal["blocks"]).unwrap();
        assert!(blocks_str.contains("Execution Plan"));
    }

    #[test]
    fn format_approvers_field_mode_all_partial_shows_progress() {
        let wf_json = r#"{"steps":[{"mode":"all","approvers":[{"selector":"role:dba","min":1},{"selector":"role:cto","min":1}]}]}"#;
        let approvals = vec![dbward_domain::entities::Approval {
            id: "a1".into(),
            request_id: "r1".into(),
            action: dbward_domain::entities::ApprovalAction::Approve,
            actor_id: "bob".into(),
            matched_selector: "role:dba".into(),
            step_index: 0,
            comment: None,
            created_at: chrono::Utc::now(),
        }];
        let result = format_approvers_field(wf_json, 0, Some(&approvals)).unwrap();
        assert!(result.contains("role:dba ✓"), "dba should show ✓: {result}");
        assert!(
            result.contains("role:cto ⏳"),
            "cto should show ⏳: {result}"
        );
        assert!(result.contains("AND"), "mode=all uses AND: {result}");
    }

    #[test]
    fn format_approvers_field_mode_any_shows_or() {
        let wf_json = r#"{"steps":[{"mode":"any","approvers":[{"selector":"role:dba","min":1},{"selector":"role:cto","min":1}]}]}"#;
        let result = format_approvers_field(wf_json, 0, None).unwrap();
        assert!(result.contains("OR"), "mode=any uses OR: {result}");
        // No progress markers without approvals
        assert!(!result.contains("✓"), "no ✓ without approvals: {result}");
        assert!(!result.contains("⏳"), "no ⏳ without approvals: {result}");
    }

    #[test]
    fn format_approvers_field_mode_any_with_approvals() {
        let wf_json = r#"{"steps":[{"mode":"any","approvers":[{"selector":"role:dba","min":1},{"selector":"role:cto","min":1}]}]}"#;
        let approvals = vec![dbward_domain::entities::Approval {
            id: "a1".into(),
            request_id: "r1".into(),
            action: dbward_domain::entities::ApprovalAction::Approve,
            actor_id: "bob".into(),
            matched_selector: "role:dba".into(),
            step_index: 0,
            comment: None,
            created_at: chrono::Utc::now(),
        }];
        let result = format_approvers_field(wf_json, 0, Some(&approvals)).unwrap();
        assert!(result.contains("role:dba ✓"), "dba satisfied: {result}");
        assert!(result.contains("role:cto ⏳"), "cto unsatisfied: {result}");
    }
}

#[cfg(test)]
mod view_result_tests {
    use super::*;
    use dbward_domain::entities::RequestStatus;
    use dbward_domain::values::{DatabaseName, Environment, Operation};

    fn make_request(status: RequestStatus, no_result_store: bool) -> Request {
        Request {
            id: "req-1".into(),
            requester: "alice".into(),
            database: DatabaseName::new("app").unwrap(),
            environment: Environment::new("production").unwrap(),
            operation: Operation::ExecuteSelect,
            detail: "SELECT 1".into(),
            status,
            emergency: false,
            reason: None,
            idempotency_key: None,
            idempotency_fingerprint: None,
            metadata_json: "{}".into(),
            share_with: vec![],
            no_result_store,
            workflow_snapshot_json: None,
            decision_trace_json: None,
            execution_plan_json: None,
            cancel_reason: None,
            cancelled_by: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            resolved_at: None,
            expires_at: None,
        }
    }

    #[test]
    fn view_result_button_shown_for_failed_no_result_store() {
        let req = make_request(RequestStatus::Failed, true);
        assert!(should_show_view_result(&req));
    }

    #[test]
    fn view_result_button_hidden_for_executed_no_result_store() {
        let req = make_request(RequestStatus::Executed, true);
        assert!(!should_show_view_result(&req));
    }

    #[test]
    fn view_result_button_shown_for_executed_normal() {
        let req = make_request(RequestStatus::Executed, false);
        assert!(should_show_view_result(&req));
    }

    #[test]
    fn view_result_button_hidden_for_execution_lost() {
        let req = make_request(RequestStatus::ExecutionLost, false);
        assert!(!should_show_view_result(&req));
    }

    #[test]
    fn fallback_text_step_approved_uses_ballot_box_emoji() {
        let event = WebhookEvent {
            event_type: "step.approved".into(),
            request_id: Some("req-1".into()),
            database: None,
            environment: None,
            actor: None,
            detail: None,
            requester: None,
            reason: None,
            redacted_detail: None,
            error_summary: None,
            approval_hint: None,
            operation: None,
            step_index: None,
            total_steps: None,
            expires_at: None,
            approvers: None,
            matched_selector: None,
        };
        let text = fallback_text(&event);
        assert!(text.contains("☑️"), "expected ☑️ in: {text}");
    }

    #[test]
    fn thread_reply_dispatch_timeout() {
        let event = WebhookEvent {
            event_type: "request.dispatch_timeout".into(),
            request_id: Some("req-1".into()),
            database: None,
            environment: None,
            actor: Some("system".into()),
            detail: None,
            requester: None,
            reason: None,
            redacted_detail: None,
            error_summary: None,
            approval_hint: None,
            operation: None,
            step_index: None,
            total_steps: None,
            expires_at: None,
            approvers: None,
            matched_selector: None,
        };
        let blocks = build_thread_reply(&event, "");
        let text = blocks[0]["text"]["text"].as_str().unwrap();
        assert!(
            text.contains("Dispatch timed out"),
            "expected dispatch timeout text in: {text}"
        );
    }

    #[test]
    fn fallback_text_dispatch_timeout() {
        let event = WebhookEvent {
            event_type: "request.dispatch_timeout".into(),
            request_id: Some("req-42".into()),
            database: None,
            environment: None,
            actor: None,
            detail: None,
            requester: None,
            reason: None,
            redacted_detail: None,
            error_summary: None,
            approval_hint: None,
            operation: None,
            step_index: None,
            total_steps: None,
            expires_at: None,
            approvers: None,
            matched_selector: None,
        };
        let text = fallback_text(&event);
        assert!(
            text.contains("🔄") && text.contains("Dispatch timeout for req-42"),
            "expected dispatch timeout fallback in: {text}"
        );
    }
}
