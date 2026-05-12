use std::time::Duration;

use dbward_api_types::agent::{
    ClaimResponse, HeartbeatResponse, PollRequest, PollResponse, ResultBody,
};
use ed25519_dalek::VerifyingKey;
use reqwest::Client;

use crate::AgentError;

pub struct AgentClient {
    http: Client,
    base_url: String,
    agent_token: String,
}

impl AgentClient {
    pub fn new(server_url: &str, agent_token: &str) -> Result<Self, AgentError> {
        let http = Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self {
            http,
            base_url: server_url.trim_end_matches('/').to_string(),
            agent_token: agent_token.to_string(),
        })
    }

    pub async fn fetch_public_key(&self) -> Result<VerifyingKey, AgentError> {
        let resp = self
            .http
            .get(format!("{}/api/public-key", self.base_url))
            .bearer_auth(&self.agent_token)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(AgentError::ServerError {
                status: status.as_u16(),
                body,
            });
        }
        let body: serde_json::Value = resp.json().await
            .map_err(|e| AgentError::TokenVerification(format!("invalid response: {e}")))?;
        let hex_str = body["public_key"].as_str()
            .ok_or_else(|| AgentError::TokenVerification("missing public_key field".into()))?;
        let bytes = hex::decode(hex_str.trim())
            .map_err(|e| AgentError::TokenVerification(format!("invalid public key hex: {e}")))?;
        let key_bytes: [u8; 32] = bytes.try_into().map_err(|_| {
            AgentError::TokenVerification("public key must be 32 bytes".into())
        })?;
        Ok(VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| AgentError::TokenVerification(e.to_string()))?)
    }

    pub async fn poll(&self, req: &PollRequest) -> Result<PollResponse, AgentError> {
        let resp = self
            .http
            .post(format!("{}/api/agent/poll", self.base_url))
            .bearer_auth(&self.agent_token)
            .json(req)
            .send()
            .await?;
        self.parse_response(resp).await
    }

    pub async fn claim(&self, request_id: &str) -> Result<ClaimResponse, AgentError> {
        let resp = self
            .http
            .post(format!("{}/api/agent/jobs/{}/claim", self.base_url, request_id))
            .bearer_auth(&self.agent_token)
            .send()
            .await?;
        let status = resp.status();
        if status.as_u16() == 409 {
            return Err(AgentError::AlreadyClaimed);
        }
        self.parse_response(resp).await
    }

    pub async fn heartbeat(&self, execution_id: &str) -> Result<HeartbeatResponse, AgentError> {
        let resp = self
            .http
            .post(format!(
                "{}/api/agent/jobs/{}/heartbeat",
                self.base_url, execution_id
            ))
            .bearer_auth(&self.agent_token)
            .send()
            .await?;
        self.parse_response(resp).await
    }

    pub async fn submit_result(
        &self,
        execution_id: &str,
        body: &ResultBody,
    ) -> Result<(), AgentError> {
        let resp = self
            .http
            .post(format!(
                "{}/api/agent/jobs/{}/result",
                self.base_url, execution_id
            ))
            .bearer_auth(&self.agent_token)
            .json(body)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(AgentError::ServerError {
                status: status.as_u16(),
                body,
            });
        }
        Ok(())
    }

    async fn parse_response<T: serde::de::DeserializeOwned>(
        &self,
        resp: reqwest::Response,
    ) -> Result<T, AgentError> {
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(AgentError::ServerError {
                status: status.as_u16(),
                body,
            });
        }
        Ok(resp.json().await?)
    }
}
