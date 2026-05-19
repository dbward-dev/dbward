mod block_kit;
mod client;
mod notifier;

pub use client::SlackHttpClient;
pub use notifier::SlackNotifier;

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
    pub user_mappings: Vec<SlackUserMapping>,
}

#[derive(Debug, Clone)]
pub struct SlackUserMapping {
    pub slack_user_id: String,
    pub dbward_subject: String,
}

impl SlackConfig {
    pub fn channel_for_env(&self, env: &str) -> &str {
        self.channel_overrides
            .get(env)
            .map(|s| s.as_str())
            .unwrap_or(&self.default_channel)
    }

    pub fn resolve_subject(&self, slack_user_id: &str) -> Option<&str> {
        self.user_mappings
            .iter()
            .find(|m| m.slack_user_id == slack_user_id)
            .map(|m| m.dbward_subject.as_str())
    }
}
