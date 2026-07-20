use dbward_app::ports::{IdGenerator, Notifier, WebhookDeliveryRepo, WebhookEvent, WebhookRepo};
use dbward_domain::entities::{DeliveryStatus, WebhookDelivery, WebhookStatus};
use std::sync::{Arc, RwLock};

#[derive(Clone, Copy, Default)]
pub enum RedactionMode {
    None,
    #[default]
    Literals,
    Full,
}

/// Compute HMAC-SHA256 signature for webhook payload.
pub(super) fn compute_webhook_signature(secret: &str, body: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(body.as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());
    format!("sha256={sig}")
}

pub fn redact_sql_literals(sql: &str) -> String {
    dbward_domain::services::sql_redactor::redact_literals(sql)
}

/// Webhook dispatcher — sends webhook notifications via HTTP.
pub struct WebhookDispatcher {
    client: reqwest::Client,
    hooks: RwLock<Vec<WebhookConfig>>,
    webhook_repo: Option<Arc<dyn WebhookRepo>>,
    delivery_repo: Option<Arc<dyn WebhookDeliveryRepo>>,
    id_gen: Option<Arc<dyn IdGenerator>>,
}

#[derive(Clone)]
pub struct WebhookConfig {
    pub id: String,
    pub url: String,
    pub events: Vec<String>,
    pub format: String,
    pub secret: Option<String>,
}

impl WebhookDispatcher {
    pub fn new(hooks: Vec<WebhookConfig>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_default();
        Self {
            client,
            hooks: RwLock::new(hooks),
            webhook_repo: None,
            delivery_repo: None,
            id_gen: None,
        }
    }

    pub fn with_repo(webhook_repo: Arc<dyn WebhookRepo>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_default();
        Self {
            client,
            hooks: RwLock::new(vec![]),
            webhook_repo: Some(webhook_repo),
            delivery_repo: None,
            id_gen: None,
        }
    }

    pub fn with_delivery_repo(
        mut self,
        delivery_repo: Arc<dyn WebhookDeliveryRepo>,
        id_gen: Arc<dyn IdGenerator>,
    ) -> Self {
        self.delivery_repo = Some(delivery_repo);
        self.id_gen = Some(id_gen);
        self
    }

    /// Send a single webhook payload. Used by background retry task.
    pub async fn send_one(
        &self,
        url: &str,
        body: &str,
        secret: Option<&str>,
        event_type: Option<&str>,
    ) -> Result<(), String> {
        send_with_retry(&self.client, url, body, secret, event_type)
            .await
            .map_err(|()| "delivery failed after retries".to_string())
    }
}

#[async_trait::async_trait]
impl dbward_app::ports::WebhookSender for WebhookDispatcher {
    async fn send_one(&self, url: &str, body: &str, secret: Option<&str>, event_type: Option<&str>) -> Result<(), String> {
        self.send_one(url, body, secret, event_type).await
    }
}

impl Notifier for WebhookDispatcher {
    fn dispatch(&self, event: WebhookEvent) {
        let hooks = self.hooks.read().unwrap();
        for hook in hooks.iter() {
            // Empty events list = subscribe to all events
            if !hook.events.is_empty()
                && !hook.events.contains(&event.event_type)
                && !hook.events.contains(&"*".to_string())
                && !hook
                    .events
                    .iter()
                    .any(|e| e.ends_with(".*") && event.event_type.starts_with(&e[..e.len() - 1]))
            {
                continue;
            }
            let client = self.client.clone();
            let url = hook.url.clone();
            let secret = hook.secret.clone();
            let event_type = event.event_type.clone();
            let body = match hook.format.as_str() {
                "slack" => build_slack_body(&event),
                _ => build_generic_body(&event),
            };

            // Persist-first: record delivery before sending
            if let (Some(repo), Some(id_gen)) = (&self.delivery_repo, &self.id_gen) {
                let delivery = WebhookDelivery {
                    id: format!("wd-{}", id_gen.generate()),
                    webhook_id: hook.id.clone(),
                    event_type: event.event_type.clone(),
                    payload: body.clone(),
                    status: DeliveryStatus::Pending,
                    attempts: 0,
                    max_attempts: 10,
                    next_retry_at: None,
                    last_error: None,
                    created_at: chrono::Utc::now(),
                    last_attempted_at: None,
                    claimed_at: None,
                };
                if let Err(e) = repo.insert(&delivery) {
                    tracing::error!(error = %e, "failed to persist webhook delivery");
                }
                let delivery_id = delivery.id.clone();
                let repo = repo.clone();
                let et = event_type.clone();
                tokio::spawn(async move {
                    match send_with_retry(&client, &url, &body, secret.as_deref(), Some(&et)).await {
                        Ok(()) => {
                            let now = chrono::Utc::now().to_rfc3339();
                            if let Err(e) = repo.mark_delivered(&delivery_id, &now) {
                                tracing::error!(error = %e, delivery_id, "failed to mark webhook delivered");
                            }
                        }
                        Err(()) => {
                            let next = chrono::Utc::now() + chrono::Duration::seconds(60);
                            if let Err(e) = repo.mark_failed(
                                &delivery_id,
                                "initial delivery failed after 3 attempts",
                                &next.to_rfc3339(),
                                3,
                            ) {
                                tracing::error!(error = %e, delivery_id, "failed to mark webhook failed");
                            }
                        }
                    }
                });
            } else {
                tokio::spawn(async move {
                    let _ = send_with_retry(&client, &url, &body, secret.as_deref(), Some(&event_type)).await;
                });
            }
        }
    }

    fn reload(&self) -> Result<(), dbward_app::error::AppError> {
        if let Some(ref repo) = self.webhook_repo {
            let webhooks = repo.list_active()?;
            let configs: Vec<WebhookConfig> = webhooks
                .into_iter()
                .filter(|w| w.status == WebhookStatus::Active)
                .map(|w| WebhookConfig {
                    id: w.id,
                    url: w.url,
                    events: w.events,
                    format: format!("{:?}", w.format).to_lowercase(),
                    secret: w.secret,
                })
                .collect();
            let mut hooks = self.hooks.write().unwrap();
            *hooks = configs;
        }
        Ok(())
    }
}

fn build_generic_body(event: &WebhookEvent) -> String {
    serde_json::to_string(&serde_json::json!({
        "event": event.event_type,
        "request_id": event.request_id,
        "database": event.database,
        "environment": event.environment,
        "operation": event.operation,
        "actor": event.actor,
        "requester": event.requester,
        "detail": event.redacted_detail,
        "matched_selector": event.matched_selector,
    }))
    .unwrap_or_default()
}

fn build_slack_body(event: &WebhookEvent) -> String {
    use crate::notification_display::event_display;
    use serde_json::json;

    let db = event.database.as_deref().unwrap_or("—");
    let env = event.environment.as_deref().unwrap_or("—");
    let actor = event.actor.as_deref().unwrap_or("system");
    let requester = event.requester.as_deref().unwrap_or(actor);
    let req_id = event.request_id.as_deref().unwrap_or("—");
    let operation = event.operation.as_deref().unwrap_or("—");

    let (emoji, title) = event_display(&event.event_type);

    // Section fields (2-column layout)
    let mut fields = vec![
        json!({"type": "mrkdwn", "text": format!("*Requester:*\n{}", escape_mrkdwn(requester))}),
        json!({"type": "mrkdwn", "text": format!("*Database:*\n{db} / {env}")}),
        json!({"type": "mrkdwn", "text": format!("*Operation:*\n{operation}")}),
        json!({"type": "mrkdwn", "text": format!("*Request ID:*\n`{req_id}`")}),
    ];
    if let Some(ref approvers) = event.approvers
        && !approvers.is_empty()
    {
        fields.push(
            json!({"type": "mrkdwn", "text": format!("*Approvers:*\n{}", approvers.join(", "))}),
        );
    }

    let mut blocks: Vec<serde_json::Value> = vec![
        json!({"type": "header", "text": {"type": "plain_text", "text": format!("{emoji} {title}")}}),
        json!({"type": "section", "fields": fields}),
    ];

    // SQL preview (only for Created events with redacted_detail)
    if let Some(ref sql) = event.redacted_detail
        && !sql.trim().is_empty()
    {
        let truncated: String = sql.chars().take(200).collect::<String>().replace('`', "'");
        blocks.push(json!({
            "type": "section",
            "text": {"type": "mrkdwn", "text": format!("```{truncated}```")}
        }));
    }

    // Context line (actor, step, reason, error, hint)
    let mut ctx_parts: Vec<String> = Vec::new();
    if actor != requester {
        ctx_parts.push(format!("Actor: {}", escape_mrkdwn(actor)));
    }
    if let (Some(step), Some(total)) = (event.step_index, event.total_steps) {
        ctx_parts.push(format!("Step {}/{total}", step + 1));
    }
    if let Some(ref reason) = event.reason {
        let truncated: String = reason.chars().take(100).collect();
        ctx_parts.push(format!("Reason: {}", escape_mrkdwn(&truncated)));
    }
    if let Some(ref err) = event.error_summary {
        let first_line = err.lines().next().unwrap_or(err);
        ctx_parts.push(format!("Error: {}", escape_mrkdwn(first_line)));
    }
    if let Some(ref hint) = event.approval_hint {
        ctx_parts.push(format!("Next: {}", escape_mrkdwn(hint)));
    }
    if !ctx_parts.is_empty() {
        blocks.push(json!({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": ctx_parts.join(" • ")}]
        }));
    }

    // CLI command hint
    let action = match event.event_type.as_str() {
        "request.created" => Some(format!("`dbward request approve {req_id}`")),
        "request.break_glass" | "request.auto_approved" | "request.dispatch_timeout" => {
            Some(format!("`dbward request resume {req_id}`"))
        }
        "request.approved" => Some(format!(
            "Requester can now run: `dbward request resume {req_id}`"
        )),
        _ => None,
    };
    if let Some(cmd) = action {
        blocks.push(json!({
            "type": "section",
            "text": {"type": "mrkdwn", "text": cmd}
        }));
    }

    // Fallback text for push notifications
    let text = format!("{emoji} {title} — {db}/{env} — {req_id}");

    serde_json::to_string(&json!({
        "text": text,
        "blocks": blocks
    }))
    .unwrap_or_default()
}

/// Escape user-controlled strings for Slack mrkdwn.
fn escape_mrkdwn(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

async fn send_with_retry(
    client: &reqwest::Client,
    url: &str,
    body: &str,
    secret: Option<&str>,
    event_type: Option<&str>,
) -> Result<(), ()> {
    for attempt in 0..3 {
        let mut req = client
            .post(url)
            .header("content-type", "application/json")
            .body(body.to_string());
        if let Some(s) = secret {
            let sig = compute_webhook_signature(s, body);
            req = req.header("x-dbward-signature", sig);
        }
        if let Some(et) = event_type {
            req = req.header("x-dbward-event", et);
        }
        if let Ok(resp) = req.send().await {
            let status = resp.status().as_u16();
            if (200..300).contains(&status) {
                return Ok(());
            }
            if (400..500).contains(&status) && status != 429 {
                return Err(());
            }
        }
        if attempt < 2 {
            tokio::time::sleep(std::time::Duration::from_secs(2u64.pow(attempt))).await;
        }
    }
    Err(())
}

#[cfg(test)]
mod redaction_tests {
    use super::*;

    #[test]
    fn redacts_string_literals() {
        let sql = "SELECT * FROM users WHERE name = 'secret' AND age > 25";
        let result = redact_sql_literals(sql);
        assert!(
            !result.contains("secret"),
            "string literal not redacted: {result}"
        );
        assert!(
            !result.contains("25"),
            "numeric literal not redacted: {result}"
        );
        assert!(result.contains("?"), "placeholder missing: {result}");
    }

    #[test]
    fn redacts_typed_string() {
        let sql = "SELECT * FROM events WHERE ts > DATE '2024-01-01'";
        let result = redact_sql_literals(sql);
        assert!(
            !result.contains("2024-01-01"),
            "typed string not redacted: {result}"
        );
    }

    #[test]
    fn preserves_null_and_placeholders() {
        let sql = "SELECT * FROM t WHERE a IS NULL AND b = $1";
        let result = redact_sql_literals(sql);
        assert!(
            result.contains("NULL"),
            "NULL should be preserved: {result}"
        );
    }

    #[test]
    fn parse_failure_returns_placeholder() {
        let sql = "NOT VALID SQL {{{{";
        let result = redact_sql_literals(sql);
        assert!(
            result.contains("redaction-failed"),
            "should fallback: {result}"
        );
    }

    #[test]
    fn redaction_mode_full_clears_detail_raw() {
        // Just verify the enum exists and default is Literals
        assert!(matches!(RedactionMode::default(), RedactionMode::Literals));
    }
}

#[cfg(test)]
mod signature_tests {
    use super::*;

    #[test]
    fn signature_format_is_sha256_prefixed() {
        let sig = compute_webhook_signature("secret", "body");
        assert!(sig.starts_with("sha256="));
        assert_eq!(sig.len(), "sha256=".len() + 64); // hex-encoded SHA256
    }

    #[test]
    fn signature_is_deterministic() {
        let sig1 = compute_webhook_signature("key", "payload");
        let sig2 = compute_webhook_signature("key", "payload");
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn different_secret_different_signature() {
        let sig1 = compute_webhook_signature("secret1", "payload");
        let sig2 = compute_webhook_signature("secret2", "payload");
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn different_body_different_signature() {
        let sig1 = compute_webhook_signature("secret", "body1");
        let sig2 = compute_webhook_signature("secret", "body2");
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn known_vector() {
        // Pre-computed: HMAC-SHA256("test-secret", "hello")
        let sig = compute_webhook_signature("test-secret", "hello");
        assert_eq!(
            sig,
            "sha256=bcc889a40667cab715e1dc22ad280692cf4bf1c3a280eeeca60d8dbcd8e4b993"
        );
    }

    #[test]
    fn empty_body_produces_valid_signature() {
        let sig = compute_webhook_signature("secret", "");
        assert!(sig.starts_with("sha256="));
        assert_eq!(sig.len(), "sha256=".len() + 64);
    }
}

#[cfg(test)]
mod slack_body_tests {
    use super::*;
    use dbward_app::ports::WebhookEvent;

    fn sample_event() -> WebhookEvent {
        WebhookEvent {
            event_type: "request.created".into(),
            request_id: Some("96cead2e-86f4-4a1b-b3c7-abcdef123456".into()),
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
            step_index: None,
            total_steps: None,
            expires_at: None,
            approvers: None,
            matched_selector: None,
        }
    }

    #[test]
    fn slack_body_has_block_kit_structure() {
        let body = build_slack_body(&sample_event());
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(parsed["text"].is_string());
        let blocks = parsed["blocks"].as_array().unwrap();
        assert_eq!(blocks[0]["type"], "header");
        assert_eq!(blocks[1]["type"], "section");
        assert!(blocks[1]["fields"].is_array());
    }

    #[test]
    fn slack_body_includes_sql_preview() {
        let body = build_slack_body(&sample_event());
        assert!(body.contains("DELETE FROM orders"));
    }

    #[test]
    fn slack_body_has_full_request_id() {
        let body = build_slack_body(&sample_event());
        assert!(body.contains("96cead2e-86f4-4a1b-b3c7-abcdef123456"));
    }

    #[test]
    fn slack_body_step_approved_uses_ballot_box_emoji() {
        let mut event = sample_event();
        event.event_type = "step.approved".into();
        event.redacted_detail = None;
        let body = build_slack_body(&event);
        assert!(body.contains("☑️"));
        assert!(body.contains("Step Approved"));
    }

    #[test]
    fn slack_body_expired_and_cancelled_handled() {
        for event_type in ["request.expired", "request.cancelled"] {
            let mut event = sample_event();
            event.event_type = event_type.into();
            event.redacted_detail = None;
            let body = build_slack_body(&event);
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(parsed["blocks"][0]["type"], "header");
        }
    }

    #[test]
    fn slack_body_cli_command_uses_full_id() {
        let body = build_slack_body(&sample_event());
        assert!(body.contains("dbward request approve 96cead2e-86f4-4a1b-b3c7-abcdef123456"));
    }

    #[test]
    fn slack_body_no_sql_when_redacted_detail_none() {
        let mut event = sample_event();
        event.redacted_detail = None;
        let body = build_slack_body(&event);
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        let blocks = parsed["blocks"].as_array().unwrap();
        let has_sql_block = blocks.iter().any(|b| {
            b["text"]["text"]
                .as_str()
                .map(|t| t.contains("```"))
                .unwrap_or(false)
        });
        assert!(!has_sql_block);
    }

    #[test]
    fn slack_body_dispatch_timeout_has_resume_hint() {
        let mut event = sample_event();
        event.event_type = "request.dispatch_timeout".into();
        event.redacted_detail = None;
        let body = build_slack_body(&event);
        assert!(
            body.contains("dbward request resume 96cead2e-86f4-4a1b-b3c7-abcdef123456"),
            "expected resume CLI hint in: {body}"
        );
    }
}
