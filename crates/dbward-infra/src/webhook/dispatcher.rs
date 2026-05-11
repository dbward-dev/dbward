use std::sync::Arc;
use dbward_app::ports::{Notifier, WebhookEvent, AuditLogger, EventDispatcher};
use dbward_domain::entities::AuditEvent;
use dbward_domain::services::status_machine::TransitionEvent;

/// Webhook dispatcher — sends webhook notifications via HTTP.
pub struct WebhookDispatcher {
    client: reqwest::Client,
    hooks: Vec<WebhookConfig>,
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
            .timeout(std::time::Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_default();
        Self { client, hooks }
    }
}

impl Notifier for WebhookDispatcher {
    fn dispatch(&self, event: WebhookEvent) {
        for hook in &self.hooks {
            if !hook.events.contains(&event.event_type) && !hook.events.contains(&"*".to_string()) {
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
}

impl EventDispatcher for CompositeEventDispatcher {
    fn dispatch(&self, event: TransitionEvent) {
        use dbward_domain::services::status_machine::EventMetadata;

        let (event_type, category) = match &event.metadata {
            EventMetadata::Created { emergency: true, .. } => ("break_glass", "approval"),
            EventMetadata::Created { .. } => ("request_created", "approval"),
            EventMetadata::StepApproved { .. } => ("step_approved", "approval"),
            EventMetadata::Approved { .. } => ("request_approved", "approval"),
            EventMetadata::Rejected { .. } => ("request_rejected", "approval"),
            EventMetadata::Cancelled { .. } => ("request_cancelled", "approval"),
            EventMetadata::Dispatched => ("request_dispatched", "approval"),
            EventMetadata::Claimed { .. } => ("execution_started", "execution"),
            EventMetadata::Completed { success: true, .. } => ("execution_completed", "execution"),
            EventMetadata::Completed { success: false, .. } => ("execution_failed", "execution"),
            EventMetadata::ExecutionLost { .. } => ("execution_lost", "agent"),
            EventMetadata::Expired => ("request_expired", "approval"),
        };

        let audit_event = AuditEvent::simple(
            event_type,
            category,
            &event.actor_id,
            Some(&event.request_id),
        );
        let _ = self.audit.record(&audit_event);

        let webhook_event = WebhookEvent {
            event_type: event_type.to_string(),
            request_id: Some(event.request_id.clone()),
            database: Some(event.database.as_str().to_string()),
            environment: Some(event.environment.as_str().to_string()),
            actor: Some(event.actor_id.clone()),
            detail: None,
        };
        self.notifier.dispatch(webhook_event);
    }
}
