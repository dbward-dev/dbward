use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::Arc;
use tracing::{error, warn};

use crate::Metrics;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebhookConfig {
    pub url: String,
    #[serde(default = "default_events")]
    pub events: Vec<String>,
    #[serde(default = "default_format")]
    pub format: String,
    pub secret: Option<String>,
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()              // 127.0.0.0/8
                || v4.is_private()        // 10/8, 172.16/12, 192.168/16
                || v4.is_link_local()     // 169.254.0.0/16 (AWS metadata)
                || v4.is_unspecified()    // 0.0.0.0
                || v4.is_broadcast()      // 255.255.255.255
                || v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64 // 100.64.0.0/10 (CGNAT)
        }
        IpAddr::V6(v6) => {
            // IPv4-mapped (::ffff:x.x.x.x) or IPv4-compatible (::x.x.x.x)
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_private_ip(IpAddr::V4(v4));
            }
            v6.is_loopback()              // ::1
                || v6.is_unspecified()    // ::
                || {
                    let seg = v6.segments();
                    // fc00::/7 (unique local)
                    (seg[0] & 0xfe00) == 0xfc00
                    // fe80::/10 (link-local)
                    || (seg[0] & 0xffc0) == 0xfe80
                }
        }
    }
}

/// Validate a webhook URL is safe to deliver to (no SSRF).
/// Uses blocking DNS resolution — acceptable for low-frequency webhook delivery.
pub fn validate_webhook_url(url: &str) -> Result<(), String> {
    let parsed = url::Url::parse(url).map_err(|e| format!("invalid URL: {e}"))?;

    match parsed.scheme() {
        "http" | "https" => {}
        s => return Err(format!("unsupported scheme: {s}")),
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| "URL has no host".to_string())?;

    // Resolve DNS and check all IPs
    let port = parsed.port_or_known_default().unwrap_or(443);
    let addr_str = format!("{host}:{port}");
    let addrs: Vec<_> = addr_str
        .to_socket_addrs()
        .map_err(|e| format!("DNS resolution failed for {host}: {e}"))?
        .collect();

    if addrs.is_empty() {
        return Err(format!("no addresses resolved for {host}"));
    }

    for addr in &addrs {
        if is_private_ip(addr.ip()) {
            return Err(format!(
                "webhook URL resolves to private/reserved IP: {}",
                addr.ip()
            ));
        }
    }

    Ok(())
}

fn default_events() -> Vec<String> {
    vec![
        "request_created".into(),
        "request_approved".into(),
        "request_auto_approved".into(),
        "request_rejected".into(),
        "request_cancelled".into(),
        "request_completed".into(),
        "request_failed".into(),
        "break_glass".into(),
        "step_approved".into(),
    ]
}

fn default_format() -> String {
    "generic".into()
}

#[derive(Debug, Clone, Serialize)]
pub struct WebhookEvent {
    pub event: String,
    pub timestamp: String,
    pub request_id: String,
    pub status: String,
    pub requester: String,
    pub actor: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_role: Option<String>,
    pub operation: String,
    pub environment: String,
    pub database: String,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_step: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cli_command: Option<String>,
}

#[derive(Clone)]
pub struct WebhookDispatcher {
    hooks: Vec<WebhookConfig>,
    client: reqwest::Client,
}

impl WebhookDispatcher {
    /// Create dispatcher. TOML-configured webhooks are admin-trusted (no SSRF validation).
    /// Future: API-created webhooks should call validate_webhook_url() before adding.
    pub fn new(hooks: Vec<WebhookConfig>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(
                crate::constants::WEBHOOK_HTTP_TIMEOUT_SECS,
            ))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_default();
        Self { hooks, client }
    }

    pub fn empty() -> Self {
        Self {
            hooks: vec![],
            client: reqwest::Client::new(),
        }
    }

    /// Replace webhook list (used when config is reloaded via API).
    pub fn reload(&mut self, hooks: Vec<WebhookConfig>) {
        self.hooks = hooks;
    }

    /// Fire-and-forget: spawn a task for each matching webhook.
    /// Uses global hooks (legacy) — prefer dispatch_with_policy for DB×env routing.
    pub fn dispatch(&self, event: WebhookEvent) {
        self.dispatch_hooks(&self.hooks, &event, None);
    }

    /// Fire-and-forget using notification policy webhooks.
    pub fn dispatch_with_policy(
        &self,
        hooks: Vec<WebhookConfig>,
        event: WebhookEvent,
        metrics: Arc<Metrics>,
    ) {
        // Merge global hooks + policy hooks
        let mut all = self.hooks.clone();
        all.extend(hooks);
        self.dispatch_hooks(&all, &event, Some(metrics));
    }

    fn dispatch_hooks(
        &self,
        hooks: &[WebhookConfig],
        event: &WebhookEvent,
        metrics: Option<Arc<Metrics>>,
    ) {
        for hook in hooks {
            if !hook.events.iter().any(|e| e == &event.event) {
                continue;
            }
            let hook = hook.clone();
            let event = event.clone();
            let client = self.client.clone();
            let metrics = metrics.clone();
            tokio::spawn(async move {
                let delivered = send_with_retry(&client, &hook, &event).await.is_ok();
                if let Some(metrics) = metrics {
                    metrics.record_webhook_delivery(delivered);
                }
            });
        }
    }
}

async fn send_with_retry(
    client: &reqwest::Client,
    hook: &WebhookConfig,
    event: &WebhookEvent,
) -> Result<(), ()> {
    let (body, content_type) = format_payload(hook, event);

    for attempt in 0..crate::constants::WEBHOOK_MAX_RETRIES {
        if attempt > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(1 << (attempt * 2))).await;
        }

        let mut req = client
            .post(&hook.url)
            .header("content-type", &content_type)
            .header("x-dbward-event", &event.event);

        if let Some(ref secret) = hook.secret {
            use hmac::{Hmac, Mac};
            use sha2::Sha256;
            let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
            mac.update(body.as_bytes());
            let sig = hex::encode(mac.finalize().into_bytes());
            req = req.header("x-dbward-signature", format!("sha256={sig}"));
        }

        match req.body(body.clone()).send().await {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            Ok(resp) => {
                warn!(
                    url = %hook.url,
                    status = %resp.status(),
                    attempt = attempt + 1,
                    "webhook returned non-success status"
                );
            }
            Err(e) => {
                warn!(url = %hook.url, error = %e, attempt = attempt + 1, "webhook failed");
            }
        }
    }
    error!(
        url = %hook.url,
        max_retries = crate::constants::WEBHOOK_MAX_RETRIES,
        "webhook failed after all attempts"
    );
    Err(())
}

fn format_payload(hook: &WebhookConfig, event: &WebhookEvent) -> (String, String) {
    match hook.format.as_str() {
        "slack" => {
            let emoji = match event.event.as_str() {
                "break_glass" => "🚨",
                "request_approved" | "step_approved" => "👍",
                "request_auto_approved" | "request_completed" => "✅",
                "request_rejected" => "❌",
                "request_cancelled" => "🚫",
                "request_failed" => "⚠️",
                _ => "📋",
            };
            let title = match event.event.as_str() {
                "request_created" => "New Request",
                "request_approved" => "Request Approved",
                "request_auto_approved" => "Auto-Approved",
                "step_approved" => "Step Approved",
                "request_rejected" => "Request Rejected",
                "request_cancelled" => "Request Cancelled",
                "request_completed" => "Request Completed",
                "request_failed" => "Request Failed",
                "break_glass" => "Break-Glass Request",
                other => other,
            };
            let detail_short = if event.detail.len() > 200 {
                let end = event
                    .detail
                    .char_indices()
                    .map(|(i, _)| i)
                    .take_while(|&i| i <= 200)
                    .last()
                    .unwrap_or(0);
                format!("{}...", &event.detail[..end])
            } else {
                event.detail.clone()
            };
            let sep = "━━━━━━━━━━━━━━━━━━━━━━";
            let mut text = format!(
                "{emoji} *[dbward] {title}*\n{sep}\n*Requester:* {}\n*Operation:* `{}`\n*Environment:* `{}`\n*Database:* `{}`\n{sep}\n```{}```",
                event.requester, event.operation, event.environment, event.database, detail_short,
            );
            if let Some(ref reason) = event.reason {
                text.push_str(&format!("\n*Reason:* {reason}"));
            }
            if let Some(ref ns) = event.next_step {
                let next_str = if let Some(obj) = ns.as_object() {
                    obj.get("approvers")
                        .and_then(|a| a.as_str())
                        .unwrap_or(&ns.to_string())
                        .to_string()
                } else if let Some(s) = ns.as_str() {
                    s.to_string()
                } else {
                    ns.to_string()
                };
                text.push_str(&format!("\n*Next:* {next_str}"));
            }
            if let Some(ref cmd) = event.cli_command {
                text.push_str(&format!("\n{sep}\n`{cmd}`"));
            }
            let payload = json!({"text": &text});
            (payload.to_string(), "application/json".into())
        }
        _ => {
            let payload = match serde_json::to_string(event) {
                Ok(p) => p,
                Err(e) => {
                    error!(error = %e, "BUG: webhook event serialization failed");
                    format!("{{\"error\":\"serialization failed\"}}")
                }
            };
            (payload, "application/json".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_event(event_name: &str) -> WebhookEvent {
        WebhookEvent {
            event: event_name.into(),
            timestamp: "2026-01-01T00:00:00Z".into(),
            request_id: "req-1".into(),
            status: "pending".into(),
            requester: "alice".into(),
            actor: "alice".into(),
            actor_role: None,
            operation: "execute".into(),
            environment: "production".into(),
            database: "app".into(),
            detail: "SELECT 1".into(),
            reason: None,
            next_step: None,
            cli_command: None,
        }
    }

    fn test_hook(format: &str, events: Vec<&str>) -> WebhookConfig {
        WebhookConfig {
            url: "https://hooks.example.com/test".into(),
            events: events.into_iter().map(Into::into).collect(),
            format: format.into(),
            secret: None,
        }
    }

    #[test]
    fn generic_format_is_json_event() {
        let hook = test_hook("generic", vec!["request_created"]);
        let event = test_event("request_created");
        let (body, ct) = format_payload(&hook, &event);
        assert_eq!(ct, "application/json");
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["event"], "request_created");
        assert_eq!(parsed["requester"], "alice");
    }

    #[test]
    fn slack_format_has_text_field() {
        let hook = test_hook("slack", vec!["request_created"]);
        let event = test_event("request_created");
        let (body, _) = format_payload(&hook, &event);
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        let text = parsed["text"].as_str().unwrap();
        assert!(text.contains("📋"));
        assert!(text.contains("alice"));
        assert!(text.contains("production"));
    }

    #[test]
    fn slack_break_glass_uses_alert_emoji() {
        let hook = test_hook("slack", vec!["break_glass"]);
        let event = test_event("break_glass");
        let (body, _) = format_payload(&hook, &event);
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(parsed["text"].as_str().unwrap().contains("🚨"));
    }

    #[test]
    fn slack_truncates_long_detail() {
        let hook = test_hook("slack", vec!["request_created"]);
        let mut event = test_event("request_created");
        event.detail = "X".repeat(300);
        let (body, _) = format_payload(&hook, &event);
        let text = serde_json::from_str::<serde_json::Value>(&body).unwrap()["text"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(text.contains("..."));
    }

    #[test]
    fn slack_truncates_multibyte_safely() {
        let hook = test_hook("slack", vec!["request_created"]);
        let mut event = test_event("request_created");
        // 100 Japanese chars = 300 bytes (> 200 bytes), triggers truncation
        event.detail = "あ".repeat(100);
        let (body, _) = format_payload(&hook, &event);
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        let text = parsed["text"].as_str().unwrap();
        assert!(text.contains("..."));
    }

    #[test]
    fn dispatch_filters_by_event_name() {
        let hook = test_hook("generic", vec!["request_approved"]);
        let dispatcher = WebhookDispatcher::new(vec![hook]);
        // request_created should not match the hook configured for request_approved
        // We can't easily assert dispatch doesn't fire (it's fire-and-forget),
        // but we can verify the filtering logic directly
        let hook = &dispatcher.hooks[0];
        let event = test_event("request_created");
        assert!(!hook.events.iter().any(|e| e == &event.event));
        let event = test_event("request_approved");
        assert!(hook.events.iter().any(|e| e == &event.event));
    }

    #[test]
    fn default_events_covers_all_lifecycle() {
        let events = default_events();
        assert!(events.contains(&"request_created".to_string()));
        assert!(events.contains(&"request_approved".to_string()));
        assert!(events.contains(&"request_auto_approved".to_string()));
        assert!(events.contains(&"request_rejected".to_string()));
        assert!(events.contains(&"request_cancelled".to_string()));
        assert!(events.contains(&"request_completed".to_string()));
        assert!(events.contains(&"request_failed".to_string()));
        assert!(events.contains(&"break_glass".to_string()));
        assert!(events.contains(&"step_approved".to_string()));
    }

    #[test]
    fn ssrf_blocks_loopback() {
        assert!(validate_webhook_url("http://127.0.0.1/hook").is_err());
        assert!(validate_webhook_url("http://127.0.0.1:8080/hook").is_err());
    }

    #[test]
    fn ssrf_blocks_private_10() {
        assert!(validate_webhook_url("http://10.0.0.1/hook").is_err());
    }

    #[test]
    fn ssrf_blocks_private_172() {
        assert!(validate_webhook_url("http://172.16.0.1/hook").is_err());
    }

    #[test]
    fn ssrf_blocks_private_192() {
        assert!(validate_webhook_url("http://192.168.1.1/hook").is_err());
    }

    #[test]
    fn ssrf_blocks_metadata() {
        assert!(validate_webhook_url("http://169.254.169.254/latest/meta-data/").is_err());
    }

    #[test]
    fn ssrf_blocks_ipv6_loopback() {
        assert!(validate_webhook_url("http://[::1]/hook").is_err());
    }

    #[test]
    fn ssrf_blocks_ipv4_mapped_ipv6() {
        // ::ffff:127.0.0.1 must be blocked
        assert!(validate_webhook_url("http://[::ffff:127.0.0.1]/hook").is_err());
        assert!(validate_webhook_url("http://[::ffff:10.0.0.1]/hook").is_err());
        assert!(validate_webhook_url("http://[::ffff:169.254.169.254]/hook").is_err());
    }

    #[test]
    fn ssrf_rejects_unsupported_scheme() {
        assert!(validate_webhook_url("ftp://example.com/hook").is_err());
        assert!(validate_webhook_url("file:///etc/passwd").is_err());
    }

    #[test]
    fn ssrf_rejects_no_host() {
        assert!(validate_webhook_url("http:///path").is_err());
    }

    #[test]
    fn ssrf_allows_public_ip() {
        // 8.8.8.8 is Google DNS - public IP
        assert!(validate_webhook_url("https://8.8.8.8/hook").is_ok());
    }
}
