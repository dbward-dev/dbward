use std::sync::Arc;
use std::time::{Duration, Instant};

use dbward_api_types::agent::{
    ActiveJob, AgentStatusReport, PollCapabilities, PollRequest, PollScope,
};
use tracing::{error, info};

use crate::AgentError;
use crate::client::AgentClient;

use super::JobTracker;

/// Drain phase: wait for in-flight jobs, send final status.
#[allow(clippy::too_many_arguments)]
pub(super) async fn drain(
    client: &Arc<AgentClient>,
    tracker: &Arc<JobTracker>,
    scopes: &[(String, String)],
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
        scopes,
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
    scopes: &[(String, String)],
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
        capabilities: PollCapabilities {
            scopes: scopes
                .iter()
                .map(|(db, env)| PollScope {
                    database: db.clone(),
                    environment: env.clone(),
                })
                .collect(),
            operations: operations.to_vec(),
        },
        limit,
        status: Some(AgentStatusReport {
            in_flight,
            in_flight_preflight: 0,
            max_concurrent,
            draining,
            uptime_secs,
            active_jobs,
        }),
        agent_version: Some(env!("CARGO_PKG_VERSION").to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_poll_request_uses_scopes_format() {
        let scopes = vec![
            ("app".to_string(), "production".to_string()),
            ("app".to_string(), "staging".to_string()),
            ("analytics".to_string(), "production".to_string()),
        ];
        let operations = vec!["execute_select".to_string(), "migrate_up".to_string()];

        let req = build_poll_request(&scopes, &operations, 5, 4, false, 100, 1, vec![]);

        // Verify scopes are set correctly
        assert_eq!(req.capabilities.scopes.len(), 3);
        assert_eq!(req.capabilities.scopes[0].database, "app");
        assert_eq!(req.capabilities.scopes[0].environment, "production");
        assert_eq!(req.capabilities.scopes[1].database, "app");
        assert_eq!(req.capabilities.scopes[1].environment, "staging");
        assert_eq!(req.capabilities.scopes[2].database, "analytics");
        assert_eq!(req.capabilities.scopes[2].environment, "production");

        // Verify operations
        assert_eq!(
            req.capabilities.operations,
            vec!["execute_select", "migrate_up"]
        );

        // Verify other fields
        assert_eq!(req.limit, 5);
        assert!(req.status.is_some());
        let status = req.status.unwrap();
        assert_eq!(status.in_flight, 1);
        assert_eq!(status.max_concurrent, 4);
        assert!(!status.draining);
    }

    #[test]
    fn build_poll_request_serializes_to_expected_json() {
        let scopes = vec![("db1".to_string(), "dev".to_string())];
        let req = build_poll_request(&scopes, &[], 1, 2, true, 60, 0, vec![]);

        let json = serde_json::to_value(&req).unwrap();
        let caps = &json["capabilities"];

        // Must have scopes key with array of objects
        assert!(caps["scopes"].is_array());
        assert_eq!(caps["scopes"][0]["database"], "db1");
        assert_eq!(caps["scopes"][0]["environment"], "dev");

        // Must NOT have old databases/environments keys
        assert!(caps.get("databases").is_none());
        assert!(caps.get("environments").is_none());

        // Draining should be true in status
        assert_eq!(json["status"]["draining"], true);
    }
}
