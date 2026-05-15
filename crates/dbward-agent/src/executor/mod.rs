mod handlers;
mod heartbeat;
pub(crate) mod result;
mod token;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use dbward_api_types::agent::{ClaimResponse, Job, ResultBody};
use dbward_driver::{CancelState, DatabaseDriver, DriverError};
use ed25519_dalek::VerifyingKey;
use tracing::{debug, error, info, warn};

use crate::AgentError;
use crate::cancel::CancelToken;
use crate::client::AgentClient;
use crate::config::DatabaseEntry;

use handlers::Operation;
use heartbeat::HeartbeatTask;
use result::error_body;
use token::ExecutionToken;

pub struct JobExecutor {
    pub client: Arc<AgentClient>,
    pub public_key: VerifyingKey,
    pub pools: Arc<HashMap<(String, String), Arc<dyn DatabaseDriver>>>,
    pub db_entries: Arc<HashMap<(String, String), DatabaseEntry>>,
    pub statement_timeout_secs: u64,
}

impl JobExecutor {
    pub async fn execute_job(
        &self,
        job: Job,
        _draining: Arc<AtomicBool>,
    ) -> Result<(), AgentError> {
        // Stage 1: Claim
        let claim = match self.claim_job(&job.id).await {
            Ok(c) => c,
            Err(AgentError::AlreadyClaimed) => return Ok(()),
            Err(e) => return Err(e),
        };
        info!(request_id = %claim.request_id, op = %claim.operation, "job claimed");

        // Stages 2-4 wrapped: any failure submits error result
        let start = std::time::Instant::now();
        let body: ResultBody = match self.execute_claimed(&claim).await {
            Ok(r) => {
                let mut b: ResultBody = r.into();
                b.duration_ms = Some(start.elapsed().as_millis() as u64);
                b
            }
            Err(ref e) => {
                warn!(request_id = %claim.request_id, "execution failed: {e}");
                let mut b = error_body(e.to_string());
                b.duration_ms = Some(start.elapsed().as_millis() as u64);
                b
            }
        };

        // Stage 5: Submit
        self.submit_with_retry(&claim.execution_id, &body).await;
        Ok(())
    }

    async fn execute_claimed(
        &self,
        claim: &ClaimResponse,
    ) -> Result<result::ExecutionResult, AgentError> {
        // Stage 2: Verify
        let token = ExecutionToken::parse(&claim.execution_token)?;
        token.verify(claim, &self.public_key)?;

        // Stage 3: Resolve
        let driver = self.resolve_driver(claim)?;
        let operation = Operation::resolve(&claim.operation);

        // Stage 4: Execute with heartbeat
        self.execute_with_heartbeat(claim, driver, &operation).await
    }

    async fn claim_job(&self, job_id: &str) -> Result<ClaimResponse, AgentError> {
        match self.client.claim(job_id).await {
            Ok(c) => Ok(c),
            Err(AgentError::AlreadyClaimed) => {
                debug!(job_id = %job_id, "job already claimed, skipping");
                Err(AgentError::AlreadyClaimed)
            }
            Err(e) => Err(e),
        }
    }

    fn resolve_driver(
        &self,
        claim: &ClaimResponse,
    ) -> Result<&Arc<dyn DatabaseDriver>, AgentError> {
        let pool_key = (claim.database.clone(), claim.environment.clone());
        self.pools.get(&pool_key).ok_or_else(|| {
            AgentError::Config(format!(
                "no pool for database={} environment={}",
                claim.database, claim.environment
            ))
        })
    }

    async fn execute_with_heartbeat(
        &self,
        claim: &ClaimResponse,
        driver: &Arc<dyn DatabaseDriver>,
        operation: &Operation,
    ) -> Result<result::ExecutionResult, AgentError> {
        let timeout_secs = claim
            .statement_timeout_secs
            .unwrap_or(self.statement_timeout_secs);
        let is_migration = claim.operation.starts_with("migrate");

        let cancel_state = CancelState::new();
        let pool_key = (claim.database.clone(), claim.environment.clone());
        let db_url = self.db_entries.get(&pool_key).map(|e| e.url.clone());
        let cancel_token = CancelToken::new(db_url, is_migration, cancel_state.clone());

        let _heartbeat = HeartbeatTask::spawn(
            self.client.clone(),
            claim.execution_id.clone(),
            cancel_token,
        );

        let result = tokio::select! {
            biased;
            result = operation.execute(driver, &claim.detail, timeout_secs, &cancel_state) => result,
            _ = cancel_state.wait_for_kill() => {
                Err(AgentError::Driver(DriverError::Cancelled))
            }
        };

        // Prevent heartbeat from triggering cancel on a stale connection PID
        cancel_state.mark_cancelled();
        result
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
                    warn!(
                        execution_id,
                        delay_ms = delay.as_millis(),
                        "submit retry: {e}"
                    );
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(max_delay);
                }
            }
        }
    }
}
