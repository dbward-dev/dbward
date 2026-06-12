use std::sync::Arc;
use std::time::{Duration, Instant};

use dbward_api_types::agent::{ActiveJob, AgentStatusReport, PollRequest};
use tracing::{error, info};

use crate::AgentError;
use crate::client::AgentClient;

use super::JobTracker;

/// Drain phase: wait for in-flight jobs, send final status.
#[allow(clippy::too_many_arguments)]
pub(super) async fn drain(
    client: &Arc<AgentClient>,
    tracker: &Arc<JobTracker>,
    databases: &[String],
    environments: &[String],
    operations: &[String],
    max_concurrent: u32,
    timeout: Duration,
    start_time: Instant,
) -> Result<(), AgentError> {
    info!("draining, waiting for in-flight jobs");
    let deadline = tokio::time::Instant::now() + timeout;
    while tracker.snapshot().0 > 0 {
        if tokio::time::Instant::now() >= deadline {
            error!("drain timeout exceeded");
            return Err(AgentError::DrainTimeout);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let req = build_poll_request(
        databases,
        environments,
        operations,
        0,
        max_concurrent,
        true,
        start_time.elapsed().as_secs(),
        0,
        vec![],
    );
    if let Err(e) = client.poll(&req).await {
        tracing::debug!(error = %e, "shutdown poll notify failed");
    }

    info!("agent shutdown complete");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build_poll_request(
    databases: &[String],
    environments: &[String],
    operations: &[String],
    limit: u32,
    max_concurrent: u32,
    draining: bool,
    uptime_secs: u64,
    in_flight: u32,
    active_jobs: Vec<ActiveJob>,
) -> PollRequest {
    PollRequest {
        agent_id: None,
        capabilities: dbward_api_types::agent::PollCapabilities {
            databases: databases.to_vec(),
            environments: environments.to_vec(),
            operations: operations.to_vec(),
        },
        limit,
        status: Some(AgentStatusReport {
            in_flight,
            max_concurrent,
            draining,
            uptime_secs,
            active_jobs,
        }),
        agent_version: Some(env!("CARGO_PKG_VERSION").to_string()),
    }
}
