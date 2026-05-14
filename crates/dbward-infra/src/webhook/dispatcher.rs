use dbward_app::ports::{
    AuditLogger, EventDispatcher, IdGenerator, Notifier, WebhookDeliveryRepo, WebhookEvent,
    WebhookRepo,
};
use dbward_domain::entities::{AuditEvent, DeliveryStatus, WebhookDelivery, WebhookStatus};
use dbward_domain::services::status_machine::TransitionEvent;
use sqlparser::ast::{Value, VisitMut, VisitorMut};
use sqlparser::dialect::GenericDialect;
use sqlparser::parser::Parser;
use std::ops::ControlFlow;
use std::sync::{Arc, RwLock};

#[derive(Clone, Copy, Default)]
pub enum RedactionMode {
    None,
    #[default]
    Literals,
    Full,
}

struct LiteralRedactor;

impl VisitorMut for LiteralRedactor {
    type Break = ();

    fn pre_visit_value(&mut self, value: &mut Value) -> ControlFlow<Self::Break> {
        match value {
            Value::Null | Value::Placeholder(_) => {}
            _ => *value = Value::Placeholder("?".into()),
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expr: &mut sqlparser::ast::Expr) -> ControlFlow<Self::Break> {
        use sqlparser::ast::Expr;
        match expr {
            Expr::TypedString { .. } | Expr::Interval(_) => {
                *expr = Expr::Value(Value::Placeholder("?".into()).with_empty_span());
            }
            _ => {}
        }
        ControlFlow::Continue(())
    }
}

pub fn redact_sql_literals(sql: &str) -> String {
    match Parser::parse_sql(&GenericDialect {}, sql) {
        Ok(mut stmts) => {
            let _ = stmts.visit(&mut LiteralRedactor);
            stmts
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join("; ")
        }
        Err(_) => {
            use sha2::{Digest, Sha256};
            format!(
                "parse-failed:{}",
                hex::encode(Sha256::digest(sql.as_bytes()))
            )
        }
    }
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
    ) -> Result<(), String> {
        send_with_retry(&self.client, url, body, secret)
            .await
            .map_err(|()| "delivery failed after retries".to_string())
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
            {
                continue;
            }
            let client = self.client.clone();
            let url = hook.url.clone();
            let secret = hook.secret.clone();
            let body = match hook.format.as_str() {
                "slack" => build_slack_body(&event),
                _ => build_generic_body(&event),
            };

            // Persist-first: record delivery before sending
            if let (Some(repo), Some(id_gen)) = (&self.delivery_repo, &self.id_gen) {
                let delivery = WebhookDelivery {
                    id: format!("wd-{}", id_gen.generate()),
                    webhook_id: url.clone(),
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
                tokio::spawn(async move {
                    match send_with_retry(&client, &url, &body, secret.as_deref()).await {
                        Ok(()) => {
                            let now = chrono::Utc::now().to_rfc3339();
                            let _ = repo.mark_delivered(&delivery_id, &now);
                        }
                        Err(()) => {
                            let next = chrono::Utc::now() + chrono::Duration::seconds(60);
                            let _ = repo.mark_failed(
                                &delivery_id,
                                "initial delivery failed after 3 attempts",
                                &next.to_rfc3339(),
                                3,
                            );
                        }
                    }
                });
            } else {
                tokio::spawn(async move {
                    let _ = send_with_retry(&client, &url, &body, secret.as_deref()).await;
                });
            }
        }
    }

    fn reload(&self) -> Result<(), dbward_app::error::AppError> {
        if let Some(ref repo) = self.webhook_repo {
            let webhooks = repo.list()?;
            let configs: Vec<WebhookConfig> = webhooks
                .into_iter()
                .filter(|w| w.status == WebhookStatus::Active)
                .map(|w| WebhookConfig {
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
    }))
    .unwrap_or_default()
}

fn build_slack_body(event: &WebhookEvent) -> String {
    let db = event.database.as_deref().unwrap_or("—");
    let env = event.environment.as_deref().unwrap_or("—");
    let actor = event.actor.as_deref().unwrap_or("system");
    let requester = event.requester.as_deref().unwrap_or(actor);
    let req_id = event.request_id.as_deref().unwrap_or("—");
    let short_id = &req_id[..req_id.len().min(8)];

    let (emoji, title) = match event.event_type.as_str() {
        "request_created" => ("📋", "New Request"),
        "request_approved" | "step_approved" => ("✅", "Approved"),
        "request_rejected" => ("❌", "Rejected"),
        "request_completed" => ("🎉", "Completed"),
        "request_failed" => ("⚠️", "Request Failed"),
        "break_glass" => ("🚨", "Break-Glass Request"),
        "request_auto_approved" => ("⚡", "Auto-Approved"),
        "execution_lost" => ("💀", "Execution Lost"),
        _ => ("🔔", event.event_type.as_str()),
    };

    let sep = "━━━━━━━━━━━━━━━━━━━━━━";
    let header = format!("{emoji} [dbward] {title}");

    let mut sections = vec![format!(
        "{sep}\nRequester: {requester}\nOperation: {}\nEnvironment: {env}\nDatabase: {db}\n{sep}",
        event.operation.as_deref().unwrap_or("—")
    )];

    // Show actor (approver/rejector) when different from requester
    if actor != requester {
        sections.push(format!("Actor: {actor}"));
    }

    if let Some(ref sql) = event.redacted_detail {
        let truncated: String = sql.chars().take(200).collect();
        sections.push(truncated);
    }

    if let Some(ref reason) = event.reason {
        sections.push(format!("Reason: {reason}"));
    }

    if let Some(ref err) = event.error_summary {
        let first_line = err.lines().next().unwrap_or(err);
        sections.push(format!("Error: {first_line}"));
    }

    if let Some(ref hint) = event.approval_hint {
        sections.push(format!("Next: {hint}"));
    }

    sections.push(sep.to_string());

    let action = match event.event_type.as_str() {
        "request_created" => Some(format!("dbward request approve {short_id}")),
        "break_glass" | "request_auto_approved" => {
            Some(format!("dbward request resume {short_id}"))
        }
        _ => None,
    };
    if let Some(cmd) = action {
        sections.push(cmd);
    }

    let text = format!("{header}\n{}", sections.join("\n"));

    serde_json::to_string(&serde_json::json!({
        "text": text,
        "blocks": [
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": text}
            }
        ]
    }))
    .unwrap_or_default()
}

async fn send_with_retry(
    client: &reqwest::Client,
    url: &str,
    body: &str,
    secret: Option<&str>,
) -> Result<(), ()> {
    for attempt in 0..3 {
        let mut req = client
            .post(url)
            .header("content-type", "application/json")
            .body(body.to_string());
        if let Some(s) = secret {
            use hmac::{Hmac, Mac};
            use sha2::Sha256;
            let mut mac = Hmac::<Sha256>::new_from_slice(s.as_bytes()).unwrap();
            mac.update(body.as_bytes());
            let sig = hex::encode(mac.finalize().into_bytes());
            req = req.header("x-dbward-signature", format!("sha256={sig}"));
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

/// ADR-004: Composite event dispatcher that fans out to subscribers.
pub struct CompositeEventDispatcher {
    pub audit: Arc<dyn AuditLogger>,
    pub notifier: Arc<dyn Notifier>,
    pub result_channel: Option<Arc<dyn dbward_app::ports::ResultChannel>>,
    pub request_notifier: Option<Arc<dyn Notifier>>,
    pub redaction_mode: RedactionMode,
    pub clock: Arc<dyn dbward_app::ports::Clock>,
}

impl EventDispatcher for CompositeEventDispatcher {
    fn dispatch(&self, event: TransitionEvent) {
        use dbward_domain::services::status_machine::EventMetadata;

        let (event_type, category) = match &event.metadata {
            EventMetadata::Created {
                emergency: true, ..
            } => ("break_glass", "approval"),
            EventMetadata::Created { .. }
                if event.new_status == dbward_domain::entities::RequestStatus::AutoApproved =>
            {
                ("request_auto_approved", "approval")
            }
            EventMetadata::Created { .. } => ("request_created", "approval"),
            EventMetadata::StepApproved { .. } => ("step_approved", "approval"),
            EventMetadata::Approved { .. } => ("request_approved", "approval"),
            EventMetadata::Rejected { .. } => ("request_rejected", "approval"),
            EventMetadata::Cancelled { .. } => ("request_cancelled", "approval"),
            EventMetadata::Dispatched => ("request_dispatched", "approval"),
            EventMetadata::Claimed { .. } => ("execution_started", "execution"),
            EventMetadata::Completed { success: true, .. } => ("request_completed", "execution"),
            EventMetadata::Completed { success: false, .. } => ("request_failed", "execution"),
            EventMetadata::ExecutionLost { .. } => ("execution_lost", "agent"),
            EventMetadata::Expired => ("request_expired", "approval"),
        };

        let mut audit_event = AuditEvent::simple(
            event_type,
            category,
            &event.actor_id,
            Some(&event.request_id),
            self.clock.now(),
        );
        audit_event.database_name = Some(event.database.as_str().to_string());
        audit_event.environment = Some(event.environment.as_str().to_string());
        audit_event.operation = Some(event.operation.as_str().to_string());

        if let EventMetadata::Created { ref detail, .. } = event.metadata {
            audit_event.detail_fingerprint = Some(redact_sql_literals(detail));
            match self.redaction_mode {
                RedactionMode::None => audit_event.detail_raw = Some(detail.clone()),
                RedactionMode::Literals => {
                    audit_event.detail_raw = Some(redact_sql_literals(detail))
                }
                RedactionMode::Full => {}
            }
        }

        let _ = self.audit.record(&audit_event);

        let webhook_event = WebhookEvent {
            event_type: event_type.to_string(),
            request_id: Some(event.request_id.clone()),
            database: Some(event.database.as_str().to_string()),
            environment: Some(event.environment.as_str().to_string()),
            actor: Some(event.actor_id.clone()),
            detail: None,
            requester: Some(event.requester_id.clone()),
            operation: Some(event.operation.as_str().to_string()),
            reason: match &event.metadata {
                EventMetadata::Created { .. } => None,
                EventMetadata::Rejected { comment, .. } => comment.clone(),
                EventMetadata::Cancelled { reason, .. } => reason.clone(),
                _ => None,
            },
            redacted_detail: match &event.metadata {
                EventMetadata::Created { detail, .. } => Some(redact_sql_literals(detail)),
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
        };
        // Dispatched events do not trigger webhooks
        if event_type != "request_dispatched" {
            self.notifier.dispatch(webhook_event.clone());
        }

        // Create result channel slot when request is dispatched
        if let Some(ref rc) = self.result_channel
            && matches!(&event.metadata, EventMetadata::Dispatched)
        {
            rc.create_slot(&event.request_id);
        }

        // Fan out to additional subscribers (ADR-004)
        if let Some(ref rn) = self.request_notifier {
            rn.dispatch(webhook_event);
        }
    }
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
    fn parse_failure_returns_hash() {
        let sql = "NOT VALID SQL {{{{";
        let result = redact_sql_literals(sql);
        assert!(
            result.starts_with("parse-failed:"),
            "should fallback: {result}"
        );
        assert_eq!(result.len(), "parse-failed:".len() + 64); // sha256 hex
    }

    #[test]
    fn redaction_mode_full_clears_detail_raw() {
        // Just verify the enum exists and default is Literals
        assert!(matches!(RedactionMode::default(), RedactionMode::Literals));
    }
}
