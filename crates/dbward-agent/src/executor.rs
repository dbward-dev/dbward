use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dbward_api_types::agent::{ClaimResponse, Job, ResultBody};
use dbward_driver::{CancelState, DatabaseDriver};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use tracing::{debug, error, info, warn};

use crate::cancel::CancelToken;
use crate::client::AgentClient;
use crate::config::DatabaseEntry;
use crate::AgentError;

pub struct JobExecutor {
    pub client: Arc<AgentClient>,
    pub public_key: VerifyingKey,
    pub pools: Arc<HashMap<(String, String), Arc<dyn DatabaseDriver>>>,
    pub db_entries: Arc<HashMap<(String, String), DatabaseEntry>>,
    pub statement_timeout_secs: u64,
}

impl JobExecutor {
    pub async fn execute_job(&self, job: Job, _draining: Arc<AtomicBool>) -> Result<(), AgentError> {
        let claim = match self.client.claim(&job.id).await {
            Ok(c) => c,
            Err(AgentError::AlreadyClaimed) => {
                debug!(job_id = %job.id, "job already claimed, skipping");
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        info!(request_id = %claim.request_id, op = %claim.operation, "job claimed");

        self.verify_token(&claim)?;

        let pool_key = (claim.database.clone(), claim.environment.clone());
        let driver = self.pools.get(&pool_key).ok_or_else(|| {
            AgentError::Config(format!(
                "no pool for database={} environment={}",
                claim.database, claim.environment
            ))
        })?;

        let timeout_secs = claim.statement_timeout_secs.unwrap_or(self.statement_timeout_secs);
        let is_migration = claim.operation.starts_with("migrate");

        // CancelState shared between driver and heartbeat
        let cancel_state = CancelState::new();

        // CancelToken orchestrates kill logic (agent-side)
        let db_url = self.db_entries.get(&pool_key).map(|e| e.url.clone());
        let cancel_token = CancelToken::new(db_url, is_migration, cancel_state.clone());

        // Heartbeat task uses execution_id
        let execution_id = claim.execution_id.clone();
        let heartbeat_client = self.client.clone();
        let heartbeat_token = cancel_token.clone();
        let heartbeat_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(2));
            interval.tick().await;
            loop {
                interval.tick().await;
                if heartbeat_token.is_cancelled() {
                    break;
                }
                match heartbeat_client.heartbeat(&execution_id).await {
                    Ok(resp) if resp.cancelled => {
                        warn!(execution_id = %execution_id, "cancellation requested by server");
                        heartbeat_token.trigger_cancel().await;
                        break;
                    }
                    Err(e) => {
                        warn!("heartbeat failed: {e}");
                    }
                    _ => {}
                }
            }
        });

        let sql = extract_sql(&claim.detail, &claim.operation);
        let result = run_cancellable(driver, &claim.operation, &sql, timeout_secs, &cancel_state).await;

        heartbeat_handle.abort();

        let body = match result {
            Ok(value) => ResultBody {
                success: true,
                result_data: Some(value),
                error_message: None,
                rows_affected: None,
                truncated: None,
                total_rows: None,
            },
            Err(e) => ResultBody {
                success: false,
                result_data: None,
                error_message: Some(e.to_string()),
                rows_affected: None,
                truncated: None,
                total_rows: None,
            },
        };

        self.submit_with_retry(&claim.execution_id, &body).await;
        Ok(())
    }

    fn verify_token(&self, claim: &ClaimResponse) -> Result<(), AgentError> {
        let token: serde_json::Value = serde_json::from_str(&claim.execution_token)
            .map_err(|e| AgentError::TokenVerification(format!("invalid token JSON: {e}")))?;

        let sig_hex = token.get("signature")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AgentError::TokenVerification("missing signature".into()))?;

        let expires_at = token.get("expires_at")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AgentError::TokenVerification("missing expires_at".into()))?;
        let exp_time = chrono::DateTime::parse_from_rfc3339(expires_at)
            .map_err(|e| AgentError::TokenVerification(format!("invalid expires_at: {e}")))?;
        if chrono::Utc::now() > exp_time {
            return Err(AgentError::TokenVerification("token expired".into()));
        }

        let token_request_id = token.get("request_id").and_then(|v| v.as_str());
        if token_request_id != Some(&claim.request_id) {
            return Err(AgentError::TokenVerification("request_id mismatch".into()));
        }
        let token_op = token.get("operation").and_then(|v| v.as_str());
        if token_op != Some(&claim.operation) {
            return Err(AgentError::TokenVerification("operation mismatch".into()));
        }
        let token_db = token.get("database").and_then(|v| v.as_str());
        if token_db != Some(&claim.database) {
            return Err(AgentError::TokenVerification("database mismatch".into()));
        }
        let token_env = token.get("environment").and_then(|v| v.as_str());
        if token_env != Some(&claim.environment) {
            return Err(AgentError::TokenVerification("environment mismatch".into()));
        }

        let expected_hash = token.get("detail_hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AgentError::TokenVerification("missing detail_hash".into()))?;
        let actual_hash = hex::encode(Sha256::digest(claim.detail.as_bytes()));
        if actual_hash != expected_hash {
            return Err(AgentError::TokenVerification("detail_hash mismatch".into()));
        }

        let requester_role = token.get("requester_role").and_then(|v| v.as_str()).unwrap_or("");
        let requester_subject = token.get("requester_subject_id").and_then(|v| v.as_str()).unwrap_or("");
        let message = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}",
            claim.request_id, claim.operation, claim.environment,
            claim.database, expected_hash, expires_at,
            requester_role, requester_subject,
        );

        let sig_bytes = hex::decode(sig_hex)
            .map_err(|e| AgentError::TokenVerification(format!("invalid signature hex: {e}")))?;
        let signature = Signature::from_slice(&sig_bytes)
            .map_err(|e| AgentError::TokenVerification(format!("invalid signature: {e}")))?;
        self.public_key
            .verify(message.as_bytes(), &signature)
            .map_err(|e| AgentError::TokenVerification(format!("signature invalid: {e}")))?;

        Ok(())
    }

    async fn submit_with_retry(&self, execution_id: &str, body: &ResultBody) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(300);
        let mut delay = Duration::from_secs(1);
        let max_delay = Duration::from_secs(15);

        loop {
            match self.client.submit_result(execution_id, body).await {
                Ok(()) => {
                    info!(execution_id, "result submitted");
                    return;
                }
                Err(e) => {
                    if tokio::time::Instant::now() + delay > deadline {
                        error!(execution_id, "result submission failed after retries: {e}");
                        return;
                    }
                    warn!(execution_id, delay_ms = delay.as_millis(), "submit retry: {e}");
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(max_delay);
                }
            }
        }
    }
}

fn extract_sql(detail: &str, _operation: &str) -> String {
    // detail is the raw SQL string from the server
    detail.to_string()
}

async fn run_cancellable(
    driver: &Arc<dyn DatabaseDriver>,
    operation: &str,
    sql: &str,
    timeout_secs: u64,
    cancel: &CancelState,
) -> Result<String, AgentError> {
    tokio::select! {
        biased;
        result = do_execute(driver, operation, sql, timeout_secs, cancel) => result,
        _ = cancel.wait_for_kill() => {
            Err(AgentError::Driver(dbward_driver::DriverError::Cancelled))
        }
    }
}

async fn do_execute(
    driver: &Arc<dyn DatabaseDriver>,
    operation: &str,
    sql: &str,
    timeout_secs: u64,
    cancel: &CancelState,
) -> Result<String, AgentError> {
    match operation {
        "query" | "execute_select" => {
            let output = driver.query_cancellable(sql, timeout_secs, cancel).await?;
            Ok(serde_json::to_string(&serde_json::json!({
                "rows": output.rows,
                "truncated": output.truncated,
                "truncation_reason": output.truncation_reason,
            })).unwrap())
        }
        _ => {
            let affected = driver.execute_cancellable(sql, timeout_secs, cancel).await?;
            Ok(serde_json::to_string(&serde_json::json!({ "rows_affected": affected })).unwrap())
        }
    }
}
