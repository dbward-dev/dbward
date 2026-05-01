use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Debug, Clone, Deserialize)]
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
    pub fn dispatch(&self, event: WebhookEvent) {
        for hook in &self.hooks {
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
