pub mod block_kit;
mod client;
mod notifier;
pub mod user_resolver;

pub use client::SlackHttpClient;
pub use notifier::SlackNotifier;
pub use user_resolver::SlackUserResolver;

use dbward_app::error::AppError;

/// Slack API operations (infra-internal interface).
#[async_trait::async_trait]
pub trait SlackClient: Send + Sync {
    async fn post_message(
        &self,
        channel: &str,
        blocks: &[serde_json::Value],
        text: &str,
    ) -> Result<String, SlackError>;

    async fn post_thread(
        &self,
        channel: &str,
        thread_ts: &str,
        blocks: &[serde_json::Value],
        text: &str,
    ) -> Result<(), SlackError>;

    async fn update_message(
        &self,
        channel: &str,
        ts: &str,
        blocks: &[serde_json::Value],
        text: &str,
    ) -> Result<(), SlackError>;

    async fn open_modal(
        &self,
        trigger_id: &str,
        view: &serde_json::Value,
    ) -> Result<String, SlackError>;

    async fn update_modal(&self, view_id: &str, view: &serde_json::Value)
    -> Result<(), SlackError>;

    async fn post_ephemeral(&self, channel: &str, user: &str, text: &str)
    -> Result<(), SlackError>;

    /// Look up a Slack user ID by email address (requires users:read.email scope).
    async fn lookup_user_by_email(&self, _email: &str) -> Result<Option<String>, SlackError> {
        Ok(None)
    }

    /// POST to a Slack response_url (slash command / interaction callback).
    async fn post_response_url(
        &self,
        _url: &str,
        _text: &str,
        _ephemeral: bool,
    ) -> Result<(), SlackError> {
        Ok(())
    }
}

/// Persists request_id → Slack message mapping.
pub trait SlackMessageRepo: Send + Sync {
    fn save(&self, request_id: &str, channel: &str, message_ts: &str) -> Result<(), AppError>;
    fn get(&self, request_id: &str) -> Result<Option<SlackMessageRef>, AppError>;
}

pub struct SlackMessageRef {
    pub channel: String,
    pub message_ts: String,
}

#[derive(Debug, thiserror::Error)]
pub enum SlackError {
    #[error("slack api error: {0}")]
    Api(String),
    #[error("network error: {0}")]
    Network(String),
}

#[derive(Debug, Clone)]
pub struct SlackConfig {
    pub bot_token: String,
    pub signing_secret: String,
    pub default_channel: String,
    pub channel_overrides: std::collections::HashMap<String, String>,
}

impl SlackConfig {
    pub fn channel_for_env(&self, env: &str) -> &str {
        self.channel_overrides
            .get(env)
            .map(|s| s.as_str())
            .unwrap_or(&self.default_channel)
    }
}
