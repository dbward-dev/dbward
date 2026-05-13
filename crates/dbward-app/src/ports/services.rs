pub trait Notifier: Send + Sync {
    fn dispatch(&self, event: WebhookEvent);
    /// Reload webhook configuration from the repository.
    fn reload(&self) -> Result<(), crate::error::AppError> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct WebhookEvent {
    pub event_type: String,
    pub request_id: Option<String>,
    pub database: Option<String>,
    pub environment: Option<String>,
    pub actor: Option<String>,
    pub detail: Option<String>,
    pub requester: Option<String>,
    pub reason: Option<String>,
    pub redacted_detail: Option<String>,
    pub error_summary: Option<String>,
    pub approval_hint: Option<String>,
    pub operation: Option<String>,
}
