use std::sync::Arc;

use dbward_api_types::agent::PreflightJobPayload;
use tracing::warn;

use crate::client::AgentClient;
use crate::executor::PoolRegistry;

/// Handle preflight EXPLAIN jobs received from poll (already claimed by server).
/// Fire-and-forget: errors are logged, not propagated.
pub(crate) async fn handle_preflight_jobs(
    jobs: Vec<PreflightJobPayload>,
    pools: &Arc<PoolRegistry>,
    client: &Arc<AgentClient>,
) {
    for job in jobs {
        let client = client.clone();
        let pools = pools.clone();
        tokio::spawn(async move {
            let key = (job.database.clone(), job.environment.clone());
            let Some(entry) = pools.get(&key) else {
                // No pool for this scope — submit error
                let claim_token = job.claim_token.as_deref().unwrap_or("");
                if let Err(e) = client
                    .submit_preflight_error(&job.id, claim_token, "no pool available for scope")
                    .await
                {
                    warn!(job_id = %job.id, %e, "preflight error submit failed");
                }
                return;
            };

            let claim_token = job.claim_token.as_deref().unwrap_or("");
            let driver = entry.driver.read().await;
            match driver.explain(&job.sql, 5).await {
                Ok(plan) => {
                    if let Err(e) = client
                        .submit_preflight_result(&job.id, claim_token, &plan)
                        .await
                    {
                        warn!(job_id = %job.id, %e, "preflight result submit failed");
                    }
                }
                Err(e) => {
                    if let Err(submit_err) = client
                        .submit_preflight_error(&job.id, claim_token, &e.to_string())
                        .await
                    {
                        warn!(job_id = %job.id, %submit_err, "preflight error submit failed");
                    }
                }
            }
        });
    }
}
