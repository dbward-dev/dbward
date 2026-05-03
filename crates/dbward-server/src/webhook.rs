use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebhookConfig {
    pub url: String,
    #[serde(default = "default_events")]
    pub events: Vec<String>,
    #[serde(default = "default_format")]
    pub format: String,
    pub secret: Option<String>,
}

fn default_events() -> Vec<String> {
    vec![
        "request_created".into(),
        "request_approved".into(),
        "request_rejected".into(),
        "request_completed".into(),
        "break_glass".into(),
    ]
}

fn default_format() -> String {
    "generic".into()
}

#[derive(Debug, Clone, Serialize)]
pub struct WebhookEvent {
    pub event: String,
    pub request_id: String,
    pub user: String,
    pub operation: String,
    pub environment: String,
    pub database: String,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone)]
pub struct WebhookDispatcher {
    hooks: Vec<WebhookConfig>,
    client: reqwest::Client,
}

impl WebhookDispatcher {
    pub fn new(hooks: Vec<WebhookConfig>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_default();
        Self { hooks, client }
    }

    pub fn empty() -> Self {
        Self::new(vec![])
    }

    /// Fire-and-forget: spawn a task for each matching webhook.
    /// Uses global hooks (legacy) — prefer dispatch_with_policy for DB×env routing.
    pub fn dispatch(&self, event: WebhookEvent) {
        self.dispatch_hooks(&self.hooks, &event);
    }

    /// Fire-and-forget using notification policy webhooks.
    pub fn dispatch_with_policy(&self, hooks: Vec<WebhookConfig>, event: WebhookEvent) {
        // Merge global hooks + policy hooks
        let mut all = self.hooks.clone();
        all.extend(hooks);
        self.dispatch_hooks(&all, &event);
    }

    fn dispatch_hooks(&self, hooks: &[WebhookConfig], event: &WebhookEvent) {
        for hook in hooks {
            if !hook.events.iter().any(|e| e == &event.event) {
                continue;
            }
            let hook = hook.clone();
            let event = event.clone();
            let client = self.client.clone();
            tokio::spawn(async move {
                let _ = send_with_retry(&client, &hook, &event).await;
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

    for attempt in 0..3u32 {
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
                eprintln!(
                    "webhook {} returned {} (attempt {})",
                    hook.url,
                    resp.status(),
                    attempt + 1
                );
            }
            Err(e) => {
                eprintln!("webhook {} failed: {e} (attempt {})", hook.url, attempt + 1);
            }
        }
    }
    eprintln!("webhook {} failed after 3 attempts", hook.url);
    Err(())
}

fn format_payload(hook: &WebhookConfig, event: &WebhookEvent) -> (String, String) {
    match hook.format.as_str() {
        "slack" => {
            let emoji = if event.event == "break_glass" { "🚨" } else { "📋" };
            let detail_short = if event.detail.len() > 100 {
                format!("{}...", &event.detail[..100])
            } else {
                event.detail.clone()
            };
            let text = format!(
                "{emoji} *[dbward]* `{}` by *{}*\n`{}` on `{}`\n```{}```{}",
                event.event,
                event.user,
                event.operation,
                event.environment,
                detail_short,
                event.reason.as_ref().map(|r| format!("\nReason: {r}")).unwrap_or_default(),
            );
            let payload = json!({"text": &text});
            (payload.to_string(), "application/json".into())
        }
        _ => {
            let payload = serde_json::to_string(event).unwrap();
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
            request_id: "req-1".into(),
            user: "alice".into(),
            operation: "execute".into(),
            environment: "production".into(),
            database: "app".into(),
            detail: "SELECT 1".into(),
            approved_by: None,
            reason: None,
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
        assert_eq!(parsed["user"], "alice");
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
        event.detail = "X".repeat(200);
        let (body, _) = format_payload(&hook, &event);
        let text = serde_json::from_str::<serde_json::Value>(&body).unwrap()["text"].as_str().unwrap().to_string();
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
        assert!(events.contains(&"request_rejected".to_string()));
        assert!(events.contains(&"request_completed".to_string()));
        assert!(events.contains(&"break_glass".to_string()));
    }
}
