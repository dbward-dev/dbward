pub trait Notifier: Send + Sync {
    fn dispatch(&self, event: WebhookEvent);
}

pub struct WebhookEvent {
    pub event_type: String,
    pub request_id: Option<String>,
    pub database: Option<String>,
    pub environment: Option<String>,
    pub actor: Option<String>,
    pub detail: Option<String>,
}
