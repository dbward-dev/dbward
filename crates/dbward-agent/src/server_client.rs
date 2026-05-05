use dbward_core::Error;
use reqwest::Client;
use serde_json::Value;

#[derive(Clone)]
pub struct AgentClient {
    base_url: String,
    agent_token: String,
    client: Client,
}

impl AgentClient {
    pub fn new(base_url: &str, agent_token: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            agent_token: agent_token.to_string(),
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .connect_timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("failed to build HTTP client"),
        }
    }

    pub async fn poll(
        &self,
        databases: &[String],
        environments: &[String],
        operations: &[String],
    ) -> Result<Vec<Value>, Error> {
        let resp = self
            .client
            .post(format!("{}/api/agent/poll", self.base_url))
            .bearer_auth(&self.agent_token)
            .json(&serde_json::json!({
                "databases": databases,
                "environments": environments,
                "operations": operations,
            }))
            .send()
            .await
            .map_err(|e| Error::Server(format!("poll failed: {e}")))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Error::Server(format!("poll failed ({status}): {body}")));
        }

        let body: Value = resp
            .json()
            .await
            .map_err(|e| Error::Server(format!("poll parse failed: {e}")))?;

        Ok(body["jobs"].as_array().cloned().unwrap_or_default())
    }

    pub async fn claim(&self, request_id: &str, agent_id: &str) -> Result<Value, Error> {
        let resp = self
            .client
            .post(format!(
                "{}/api/agent/jobs/{}/claim",
                self.base_url, request_id
            ))
            .bearer_auth(&self.agent_token)
            .json(&serde_json::json!({"agent_id": agent_id}))
            .send()
            .await
            .map_err(|e| Error::Server(format!("claim failed: {e}")))?;

        let status = resp.status();
        let body: Value = resp
            .json()
            .await
            .map_err(|e| Error::Server(format!("claim parse failed: {e}")))?;

        if !status.is_success() {
            return Err(Error::Server(format!(
                "claim failed ({}): {}",
                status, body
            )));
        }
        Ok(body)
    }

    pub async fn send_result(
        &self,
        execution_id: &str,
        success: bool,
        result: Option<serde_json::Value>,
        error: Option<&str>,
    ) -> Result<(), Error> {
        let resp = self
            .client
            .post(format!(
                "{}/api/agent/jobs/{}/result",
                self.base_url, execution_id
            ))
            .bearer_auth(&self.agent_token)
            .json(&serde_json::json!({
                "success": success,
                "result": result,
                "error": error,
            }))
            .send()
            .await
            .map_err(|e| Error::Server(format!("send result failed: {e}")))?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(Error::Server(format!("send result failed: {text}")));
        }
        Ok(())
    }

    pub async fn heartbeat(&self, execution_id: &str) -> Result<(), Error> {
        let resp = self
            .client
            .post(format!(
                "{}/api/agent/jobs/{}/heartbeat",
                self.base_url, execution_id
            ))
            .bearer_auth(&self.agent_token)
            .send()
            .await
            .map_err(|e| Error::Server(format!("heartbeat failed: {e}")))?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(Error::Server(format!("heartbeat failed: {text}")));
        }
        Ok(())
    }

    pub async fn get_public_key(&self) -> Result<ed25519_dalek::VerifyingKey, Error> {
        let resp = self
            .client
            .get(format!("{}/api/public-key", self.base_url))
            .send()
            .await
            .map_err(|e| Error::Server(format!("get public key failed: {e}")))?;

        let bytes = resp
            .bytes()
            .await
            .map_err(|e| Error::Server(format!("read public key failed: {e}")))?;

        let key_bytes: [u8; 32] = bytes
            .as_ref()
            .try_into()
            .map_err(|_| Error::Server("invalid public key size".into()))?;

        ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| Error::Server(format!("invalid public key: {e}")))
    }
}
