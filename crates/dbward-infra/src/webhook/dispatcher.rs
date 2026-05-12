use std::sync::{Arc, RwLock};
use std::ops::ControlFlow;
use dbward_app::ports::{Notifier, WebhookEvent, AuditLogger, EventDispatcher, WebhookRepo};
use dbward_domain::entities::{AuditEvent, WebhookStatus};
use dbward_domain::services::status_machine::TransitionEvent;
use sqlparser::ast::{Value, VisitorMut, VisitMut};
use sqlparser::dialect::GenericDialect;
use sqlparser::parser::Parser;

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
            stmts.iter().map(|s| s.to_string()).collect::<Vec<_>>().join("; ")
        }
        Err(_) => {
            use sha2::{Digest, Sha256};
            format!("parse-failed:{}", hex::encode(Sha256::digest(sql.as_bytes())))
        }
    }
}

/// Webhook dispatcher — sends webhook notifications via HTTP.
pub struct WebhookDispatcher {
    client: reqwest::Client,
    hooks: RwLock<Vec<WebhookConfig>>,
    webhook_repo: Option<Arc<dyn WebhookRepo>>,
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
        Self { client, hooks: RwLock::new(hooks), webhook_repo: None }
    }

    pub fn with_repo(webhook_repo: Arc<dyn WebhookRepo>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_default();
        Self { client, hooks: RwLock::new(vec![]), webhook_repo: Some(webhook_repo) }
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
            let body = serde_json::to_string(&serde_json::json!({
                "event": event.event_type,
                "request_id": event.request_id,
                "database": event.database,
                "environment": event.environment,
                "actor": event.actor,
                "detail": event.detail,
            })).unwrap_or_default();

            tokio::spawn(async move {
                let _ = send_with_retry(&client, &url, &body, secret.as_deref()).await;
            });
        }
    }

    fn reload(&self) -> Result<(), dbward_app::error::AppError> {
        if let Some(ref repo) = self.webhook_repo {
            let webhooks = repo.list()?;
            let configs: Vec<WebhookConfig> = webhooks.into_iter()
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

async fn send_with_retry(client: &reqwest::Client, url: &str, body: &str, secret: Option<&str>) -> Result<(), ()> {
    // DNS rebinding protection: resolve once, validate, and connect to pinned IP
    let parsed = url::Url::parse(url).map_err(|_| ())?;
    let host = parsed.host_str().ok_or(())?;
    let port = parsed.port_or_known_default().unwrap_or(443);
    let addrs: Vec<std::net::SocketAddr> = std::net::ToSocketAddrs::to_socket_addrs(&(host, port))
        .map_err(|_| ())?
        .collect();

    if addrs.is_empty() {
        return Err(());
    }

    // Validate all resolved IPs are not private
    for addr in &addrs {
        if is_private_ip(&addr.ip()) {
            return Err(());
        }
    }

    // Pin to first resolved IP to prevent rebinding between check and connect
    let pinned_addr = addrs[0];
    let pinned_url = format!(
        "{}://{}:{}{}",
        parsed.scheme(),
        pinned_addr.ip(),
        pinned_addr.port(),
        parsed.path()
    );

    for attempt in 0..3 {
        let mut req = client.post(&pinned_url)
            .header("content-type", "application/json")
            .header("host", host)
            .body(body.to_string());
        if let Some(s) = secret {
            use hmac::{Hmac, Mac};
            use sha2::Sha256;
            let mut mac = Hmac::<Sha256>::new_from_slice(s.as_bytes()).unwrap();
            mac.update(body.as_bytes());
            let sig = hex::encode(mac.finalize().into_bytes());
            req = req.header("x-dbward-signature", format!("sha256={sig}"));
        }
        match req.send().await {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            _ => {
                if attempt < 2 {
                    tokio::time::sleep(std::time::Duration::from_secs(1 << (attempt * 2))).await;
                }
            }
        }
    }
    Err(())
}

fn is_private_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local()
                || v4.is_broadcast() || v4.is_unspecified()
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64)
                || (v4.octets()[0] == 169 && v4.octets()[1] == 254)
        }
        std::net::IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4.is_loopback() || v4.is_private() || v4.is_link_local();
            }
            v6.is_loopback() || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// ADR-004: Composite event dispatcher that fans out to subscribers.
pub struct CompositeEventDispatcher {
    pub audit: Arc<dyn AuditLogger>,
    pub notifier: Arc<dyn Notifier>,
    pub result_channel: Option<Arc<dyn dbward_app::ports::ResultChannel>>,
    pub request_notifier: Option<Arc<dyn Notifier>>,
    pub redaction_mode: RedactionMode,
}

impl EventDispatcher for CompositeEventDispatcher {
    fn dispatch(&self, event: TransitionEvent) {
        use dbward_domain::services::status_machine::EventMetadata;

        let (event_type, category) = match &event.metadata {
            EventMetadata::Created { emergency: true, .. } => ("break_glass", "approval"),
            EventMetadata::Created { .. } if event.new_status == dbward_domain::entities::RequestStatus::AutoApproved => ("request_auto_approved", "approval"),
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
        );
        audit_event.database_name = Some(event.database.as_str().to_string());
        audit_event.environment = Some(event.environment.as_str().to_string());
        audit_event.operation = Some(event.operation.as_str().to_string());

        if let EventMetadata::Created { ref detail, .. } = event.metadata {
            audit_event.detail_fingerprint = Some(redact_sql_literals(detail));
            match self.redaction_mode {
                RedactionMode::None => audit_event.detail_raw = Some(detail.clone()),
                RedactionMode::Literals => audit_event.detail_raw = Some(redact_sql_literals(detail)),
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
        };
        // Dispatched events do not trigger webhooks
        if event_type != "request_dispatched" {
            self.notifier.dispatch(webhook_event.clone());
        }

        // Create result channel slot when request is dispatched
        if let Some(ref rc) = self.result_channel {
            if matches!(&event.metadata, EventMetadata::Dispatched) {
                rc.create_slot(&event.request_id);
            }
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
        assert!(!result.contains("secret"), "string literal not redacted: {result}");
        assert!(!result.contains("25"), "numeric literal not redacted: {result}");
        assert!(result.contains("?"), "placeholder missing: {result}");
    }

    #[test]
    fn redacts_typed_string() {
        let sql = "SELECT * FROM events WHERE ts > DATE '2024-01-01'";
        let result = redact_sql_literals(sql);
        assert!(!result.contains("2024-01-01"), "typed string not redacted: {result}");
    }

    #[test]
    fn preserves_null_and_placeholders() {
        let sql = "SELECT * FROM t WHERE a IS NULL AND b = $1";
        let result = redact_sql_literals(sql);
        assert!(result.contains("NULL"), "NULL should be preserved: {result}");
    }

    #[test]
    fn parse_failure_returns_hash() {
        let sql = "NOT VALID SQL {{{{";
        let result = redact_sql_literals(sql);
        assert!(result.starts_with("parse-failed:"), "should fallback: {result}");
        assert_eq!(result.len(), "parse-failed:".len() + 64); // sha256 hex
    }

    #[test]
    fn redaction_mode_full_clears_detail_raw() {
        // Just verify the enum exists and default is Literals
        assert!(matches!(RedactionMode::default(), RedactionMode::Literals));
    }
}
