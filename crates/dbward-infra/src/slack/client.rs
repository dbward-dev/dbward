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

    async fn open_modal(
        &self,
        trigger_id: &str,
        view: &serde_json::Value,
    ) -> Result<String, SlackError> {
        let body = serde_json::json!({
            "trigger_id": trigger_id,
            "view": view,
        });
        let resp = self
            .http
            .post("https://slack.com/api/views.open")
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
        json["view"]["id"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| SlackError::Api("missing view.id".into()))
    }

    async fn update_modal(
        &self,
        view_id: &str,
        view: &serde_json::Value,
    ) -> Result<(), SlackError> {
        let body = serde_json::json!({
            "view_id": view_id,
            "view": view,
        });
        let resp = self
            .http
            .post("https://slack.com/api/views.update")
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

    async fn post_ephemeral(
        &self,
        channel: &str,
        user: &str,
        text: &str,
    ) -> Result<(), SlackError> {
        let body = serde_json::json!({
            "channel": channel,
            "user": user,
            "text": text,
        });
        let resp = self
            .http
            .post("https://slack.com/api/chat.postEphemeral")
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

    async fn lookup_user_by_email(&self, email: &str) -> Result<Option<String>, SlackError> {
        let resp = self
            .http
            .get("https://slack.com/api/users.lookupByEmail")
            .bearer_auth(&self.bot_token)
            .query(&[("email", email)])
            .send()
            .await
            .map_err(|e| SlackError::Network(e.to_string()))?;

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| SlackError::Network(e.to_string()))?;

        if json["ok"].as_bool() != Some(true) {
            let err = json["error"].as_str().unwrap_or("unknown");
            if err == "users_not_found" {
                return Ok(None);
            }
            return Err(SlackError::Api(err.to_string()));
        }
        Ok(json["user"]["id"].as_str().map(String::from))
    }

    async fn post_response_url(
        &self,
        url: &str,
        text: &str,
        ephemeral: bool,
    ) -> Result<(), SlackError> {
        let response_type = if ephemeral { "ephemeral" } else { "in_channel" };
        let body = serde_json::json!({
            "response_type": response_type,
            "text": text,
        });
        let resp = self
            .http
            .post(url)
            .json(&body)
            .send()
            .await
            .map_err(|e| SlackError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            tracing::debug!(status = %resp.status(), "response_url POST non-2xx");
        }
        Ok(())
    }
}
