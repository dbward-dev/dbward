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

pub type PoolKey = (String, String);

pub struct PoolEntry {
    pub(crate) driver: Arc<tokio::sync::RwLock<Arc<dyn DatabaseDriver>>>,
    pub(crate) config: DatabaseEntry,
}

pub type PoolRegistry = HashMap<PoolKey, PoolEntry>;

pub struct JobExecutor {
    pub client: Arc<AgentClient>,
    pub public_key: VerifyingKey,
    pub pools: Arc<PoolRegistry>,
    pub statement_timeout_secs: u64,
    pub health_tx: tokio::sync::mpsc::UnboundedSender<PoolHealthEvent>,
}

/// Signals pool health from executor to runner.
#[derive(Debug)]
pub enum PoolHealthEvent {
    ConnectivityError {
        database: String,
        environment: String,
    },
    Success {
        database: String,
        environment: String,
    },
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

        // Stage 6: Schema re-sync after successful migration
        if body.success && matches!(claim.operation.as_str(), "migrate_up" | "migrate_down") {
            let pool_key = (claim.database.clone(), claim.environment.clone());
            if let Some(entry) = self.pools.get(&pool_key) {
                let driver = entry.driver.read().await;
                let (dialect, status, snapshot, error_message) = match driver.collect_schema().await
                {
                    Ok(snap) => {
                        let json = serde_json::to_value(&snap).ok();
                        (driver.dialect(), "ready", json, None)
                    }
                    Err(e) => (driver.dialect(), "failed", None, Some(e.to_string())),
                };
                let _ = self
                    .client
                    .schema_sync(
                        &claim.database,
                        &claim.environment,
                        dialect,
                        status,
                        snapshot.as_ref(),
                        error_message.as_deref(),
                    )
                    .await;
                info!(
                    database = %claim.database,
                    environment = %claim.environment,
                    "schema re-sync after migration"
                );
            }
        }

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
        let driver = self.resolve_driver(claim).await?;
        let operation = Operation::resolve(&claim.operation)?;

        // Stage 4: Execute with heartbeat
        let result = self
            .execute_with_heartbeat(claim, &driver, &operation)
            .await;

        // Report health
        let pool_key_db = claim.database.clone();
        let pool_key_env = claim.environment.clone();
        let is_connectivity = match &result {
            Err(AgentError::Driver(e)) => e.is_connectivity_error(),
            Err(AgentError::Migration(dbward_migrate::MigrateError::Driver(e))) => {
                e.is_connectivity_error()
            }
            _ => false,
        };
        match (&result, is_connectivity) {
            (Ok(_), _) => {
                let _ = self.health_tx.send(PoolHealthEvent::Success {
                    database: pool_key_db,
                    environment: pool_key_env,
                });
            }
            (Err(_), true) => {
                let _ = self.health_tx.send(PoolHealthEvent::ConnectivityError {
                    database: pool_key_db,
                    environment: pool_key_env,
                });
            }
            _ => {}
        }

        result
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

    async fn resolve_driver(
        &self,
        claim: &ClaimResponse,
    ) -> Result<Arc<dyn DatabaseDriver>, AgentError> {
        let pool_key = (claim.database.clone(), claim.environment.clone());
        let entry = self.pools.get(&pool_key).ok_or_else(|| {
            AgentError::Config(format!(
                "no pool for database={} environment={}",
                claim.database, claim.environment
            ))
        })?;
        let driver = entry.driver.read().await.clone();
        Ok(driver)
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
        let max_rows = claim.max_rows.map(|v| v as usize);
        let is_migration = matches!(
            operation,
            Operation::MigrateUp | Operation::MigrateDown | Operation::MigrateStatus
        );

        let cancel_state = CancelState::new();
        let cancel_token =
            CancelToken::new(Some(driver.clone()), is_migration, cancel_state.clone());

        let _heartbeat = HeartbeatTask::spawn(
            self.client.clone(),
            claim.execution_id.clone(),
            cancel_token,
        );

        let result = tokio::select! {
            biased;
            result = operation.execute(driver, &claim.detail, timeout_secs, &cancel_state, max_rows) => result,
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
                Err(ref e) if !Self::is_retryable(e) => {
                    error!(execution_id, error = %e, "result submission failed (non-retryable)");
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

    fn is_retryable(err: &AgentError) -> bool {
        match err {
            AgentError::ServerError { status, .. } => *status >= 500 || *status == 429,
            AgentError::Http(e) => e.is_timeout() || e.is_connect(),
            _ => false,
        }
    }
}
