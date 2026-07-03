use std::time::Duration;

use dbward_api_client::{ApiClient, ApiError};
use dbward_api_types::agent::{
    ClaimResponse, HeartbeatResponse, PollRequest, PollResponse, ResultBody,
};
use ed25519_dalek::VerifyingKey;
use serde_json::Value;

use crate::AgentError;

pub struct AgentClient {
    api: ApiClient,
}

impl AgentClient {
    pub fn new(server_url: &str, agent_token: &str) -> Result<Self, AgentError> {
        let api = ApiClient::new(
            server_url,
            agent_token,
            Duration::from_secs(30),
            Duration::from_secs(10),
        )
        .map_err(|e| AgentError::Http {
            message: e.to_string(),
            retryable: false,
        })?;
        Ok(Self { api })
    }

    pub async fn fetch_public_key(&self) -> Result<VerifyingKey, AgentError> {
        let body: Value = self.api.get("/api/public-key").await.map_err(|e| match e {
            ApiError::Deserialize(msg) => {
                AgentError::TokenVerification(format!("invalid response: {msg}"))
            }
            other => map_err(other),
        })?;
        let hex_str = body["public_key"]
            .as_str()
            .ok_or_else(|| AgentError::TokenVerification("missing public_key field".into()))?;
        let bytes = hex::decode(hex_str.trim())
            .map_err(|e| AgentError::TokenVerification(format!("invalid public key hex: {e}")))?;
        let key_bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| AgentError::TokenVerification("public key must be 32 bytes".into()))?;
        VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| AgentError::TokenVerification(e.to_string()))
    }

    pub async fn poll(&self, req: &PollRequest) -> Result<PollResponse, AgentError> {
        self.api.post("/api/agent/poll", req).await.map_err(map_err)
    }

    pub async fn claim(&self, request_id: &str) -> Result<ClaimResponse, AgentError> {
        let path = format!("/api/agent/jobs/{}/claim", request_id);
        let (status, text) = self
            .api
            .post_empty_with_status(&path)
            .await
            .map_err(map_err)?;
        if status == 409 {
            return Err(AgentError::AlreadyClaimed);
        }
        if status >= 400 {
            return Err(AgentError::ServerError { status, body: text });
        }
        serde_json::from_str(&text).map_err(|e| AgentError::Http {
            message: format!("invalid response: {e}"),
            retryable: false,
        })
    }

    pub async fn heartbeat(&self, execution_id: &str) -> Result<HeartbeatResponse, AgentError> {
        let path = format!("/api/agent/jobs/{}/heartbeat", execution_id);
        self.api.post_empty(&path).await.map_err(map_err)
    }

    pub async fn submit_result(
        &self,
        execution_id: &str,
        body: &ResultBody,
    ) -> Result<(), AgentError> {
        let path = format!("/api/agent/jobs/{}/result", execution_id);
        let _: Value = self.api.post(&path, body).await.map_err(map_err)?;
        Ok(())
    }

    pub async fn dry_run_claim(&self, job_id: &str) -> Result<String, AgentError> {
        let path = format!("/api/agent/dry-run/{}/claim", job_id);
        let (status, text) = self
            .api
            .post_empty_with_status(&path)
            .await
            .map_err(map_err)?;
        if status == 409 {
            return Err(AgentError::AlreadyClaimed);
        }
        if status >= 400 {
            return Err(AgentError::ServerError { status, body: text });
        }
        let body: Value = serde_json::from_str(&text).map_err(|e| AgentError::Http {
            message: format!("invalid response: {e}"),
            retryable: false,
        })?;
        body["claim_token"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| AgentError::ServerError {
                status: 200,
                body: "missing claim_token".into(),
            })
    }

    pub async fn dry_run_result(
        &self,
        job_id: &str,
        claim_token: &str,
        result: Option<&serde_json::Value>,
        error: Option<&str>,
    ) -> Result<(), AgentError> {
        let body = serde_json::json!({
            "claim_token": claim_token,
            "result": result,
            "error": error,
        });
        let path = format!("/api/agent/dry-run/{}/result", job_id);
        let (status, text) = self
            .api
            .post_with_status(&path, &body)
            .await
            .map_err(map_err)?;
        if status >= 400 {
            return Err(AgentError::ServerError { status, body: text });
        }
        Ok(())
    }

    pub async fn submit_preflight_result(
        &self,
        job_id: &str,
        claim_token: &str,
        result: &serde_json::Value,
    ) -> Result<(), AgentError> {
        let body = serde_json::json!({
            "job_id": job_id,
            "claim_token": claim_token,
            "result": result,
        });
        let (status, text) = self
            .api
            .post_with_status("/api/agent/preflight-result", &body)
            .await
            .map_err(map_err)?;
        if status >= 400 {
            return Err(AgentError::ServerError { status, body: text });
        }
        Ok(())
    }

    pub async fn submit_preflight_error(
        &self,
        job_id: &str,
        claim_token: &str,
        error: &str,
    ) -> Result<(), AgentError> {
        let body = serde_json::json!({
            "job_id": job_id,
            "claim_token": claim_token,
            "error": error,
        });
        let (status, text) = self
            .api
            .post_with_status("/api/agent/preflight-result", &body)
            .await
            .map_err(map_err)?;
        if status >= 400 {
            return Err(AgentError::ServerError { status, body: text });
        }
        Ok(())
    }

    pub async fn schema_sync(
        &self,
        database: &str,
        environment: &str,
        dialect: &str,
        status: &str,
        snapshot: Option<&serde_json::Value>,
        error_message: Option<&str>,
    ) -> Result<(), AgentError> {
        let body = serde_json::json!({
            "database": database,
            "environment": environment,
            "dialect": dialect,
            "status": status,
            "snapshot": snapshot,
            "error_message": error_message,
        });
        let (resp_status, text) = self
            .api
            .post_with_status("/api/agent/schema-sync", &body)
            .await
            .map_err(map_err)?;
        if resp_status >= 400 {
            return Err(AgentError::ServerError {
                status: resp_status,
                body: text,
            });
        }
        Ok(())
    }
}

fn map_err(e: ApiError) -> AgentError {
    match e {
        ApiError::Http { status, body } => AgentError::ServerError { status, body },
        ApiError::Network(e) => {
            let retryable = e.is_timeout() || e.is_connect();
            AgentError::Http {
                message: e.to_string(),
                retryable,
            }
        }
        ApiError::Deserialize(msg) => AgentError::Http {
            message: msg,
            retryable: false,
        },
    }
}
