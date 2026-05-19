use super::{SlackClient, SlackError};

/// HTTP-based Slack API client using reqwest.
pub struct SlackHttpClient {
    http: reqwest::Client,
    bot_token: String,
}

impl SlackHttpClient {
    pub fn new(bot_token: String) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_default();
        Self { http, bot_token }
    }
}

#[async_trait::async_trait]
impl SlackClient for SlackHttpClient {
    async fn post_message(
        &self,
        channel: &str,
        blocks: &[serde_json::Value],
        text: &str,
    ) -> Result<String, SlackError> {
        let body = serde_json::json!({
            "channel": channel,
            "text": text,
            "blocks": blocks,
        });
        let resp = self
            .http
            .post("https://slack.com/api/chat.postMessage")
            .bearer_auth(&self.bot_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| SlackError::Network(e.to_string()))?;

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| SlackError::Network(e.to_string()))?;

        if json["ok"].as_bool() != Some(true) {
            return Err(SlackError::Api(
                json["error"].as_str().unwrap_or("unknown").to_string(),
            ));
        }
        json["ts"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| SlackError::Api("missing ts in response".into()))
    }

    async fn post_thread(
        &self,
        channel: &str,
        thread_ts: &str,
        blocks: &[serde_json::Value],
        text: &str,
    ) -> Result<(), SlackError> {
        let body = serde_json::json!({
            "channel": channel,
            "thread_ts": thread_ts,
            "text": text,
            "blocks": blocks,
        });
        let resp = self
            .http
            .post("https://slack.com/api/chat.postMessage")
            .bearer_auth(&self.bot_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| SlackError::Network(e.to_string()))?;

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| SlackError::Network(e.to_string()))?;

        if json["ok"].as_bool() != Some(true) {
            return Err(SlackError::Api(
                json["error"].as_str().unwrap_or("unknown").to_string(),
            ));
        }
        Ok(())
    }

    async fn update_message(
        &self,
        channel: &str,
        ts: &str,
        blocks: &[serde_json::Value],
        text: &str,
    ) -> Result<(), SlackError> {
        let body = serde_json::json!({
            "channel": channel,
            "ts": ts,
            "text": text,
            "blocks": blocks,
        });
        let resp = self
            .http
            .post("https://slack.com/api/chat.update")
            .bearer_auth(&self.bot_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| SlackError::Network(e.to_string()))?;

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| SlackError::Network(e.to_string()))?;

        if json["ok"].as_bool() != Some(true) {
            return Err(SlackError::Api(
                json["error"].as_str().unwrap_or("unknown").to_string(),
            ));
        }
        Ok(())
    }
}
