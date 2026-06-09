use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use tracing::{error, info, warn};

use crate::AgentError;
use crate::client::AgentClient;
use crate::executor::{JobExecutor, PoolRegistry};
use crate::probes::ProbeGuard;

use super::{JobGuard, JobTracker, drain::build_poll_request};

/// Poll loop: dispatch jobs, manage degraded mode, handle health events.
/// Returns when draining signal is received.
#[allow(clippy::too_many_arguments)]
pub(super) async fn poll_loop(
    client: &Arc<AgentClient>,
    executor: &Arc<JobExecutor>,
    pools: &Arc<PoolRegistry>,
    tracker: &Arc<JobTracker>,
    draining: &Arc<AtomicBool>,
    probes: &ProbeGuard,
    databases: &[String],
    environments: &[String],
    operations: &[String],
    max_concurrent: u32,
    poll_interval: Duration,
    mut health_rx: tokio::sync::mpsc::UnboundedReceiver<crate::executor::PoolHealthEvent>,
    start_time: Instant,
) -> Result<(), AgentError> {
    let mut consecutive_failures: u32 = 0;
    let mut is_ready = true;
    let mut pool_failure_counts: HashMap<(String, String), u32> = HashMap::new();
    let mut degraded = false;

    loop {
        // Drain health events from executor
        while let Ok(event) = health_rx.try_recv() {
            use crate::executor::PoolHealthEvent;
            match event {
                PoolHealthEvent::ConnectivityError {
                    database,
                    environment,
                } => {
                    let key = (database.clone(), environment.clone());
                    let count = pool_failure_counts.entry(key).or_insert(0);
                    *count += 1;
                    if *count >= 2 && !degraded {
                        degraded = true;
                        is_ready = false;
                        probes.remove_readiness();
                        warn!(
                            phase = "degraded",
                            database,
                            environment,
                            "entering degraded mode: database connectivity lost"
                        );
                    }
                }
                PoolHealthEvent::Success {
                    database,
                    environment,
                } => {
                    pool_failure_counts.remove(&(database, environment));
                }
            }
        }

        // Degraded: attempt reconnect
        if degraded {
            let mut all_healthy = true;
            for ((db_name, env_name), entry) in pools.iter() {
                let key = (db_name.clone(), env_name.clone());
                if pool_failure_counts.get(&key).copied().unwrap_or(0) < 2 {
                    continue;
                }
                match tokio::time::timeout(
                    Duration::from_secs(5),
                    dbward_driver::connect(&entry.config.url, None),
                )
                .await
                {
                    Ok(Ok(new_driver)) => {
                        *entry.driver.write().await = new_driver;
                        pool_failure_counts.remove(&key);
                        info!(
                            phase = "degraded",
                            database = db_name,
                            environment = env_name,
                            "database reconnected"
                        );
                    }
                    Ok(Err(e))
                        if matches!(e, dbward_driver::DriverError::AuthenticationFailed(_)) =>
                    {
                        error!(phase = "degraded", database = db_name, environment = env_name,
                            %e, "authentication failed during reconnect, exiting");
                        return Err(AgentError::Driver(e));
                    }
                    _ => {
                        all_healthy = false;
                    }
                }
            }
            if all_healthy || pool_failure_counts.values().all(|c| *c < 2) {
                degraded = false;
                if consecutive_failures == 0 {
                    is_ready = true;
                    probes.restore_readiness();
                    info!(
                        phase = "ready",
                        "all databases recovered, readiness restored"
                    );
                }
            }
        }

        if draining.load(Ordering::Acquire) {
            // Notify server we're draining, then exit loop
            let (in_flight, active_jobs) = tracker.snapshot();
            let req = build_poll_request(
                databases,
                environments,
                operations,
                0,
                max_concurrent,
                true,
                start_time.elapsed().as_secs(),
                in_flight,
                active_jobs,
            );
            let _ = client.poll(&req).await;
            probes.remove_readiness();
            break;
        }

        let (in_flight, active_jobs) = tracker.snapshot();
        let available = if is_ready && !degraded {
            max_concurrent.saturating_sub(in_flight)
        } else {
            0
        };

        let req = build_poll_request(
            databases,
            environments,
            operations,
            available,
            max_concurrent,
            draining.load(Ordering::Relaxed),
            start_time.elapsed().as_secs(),
            in_flight,
            active_jobs,
        );

        match client.poll(&req).await {
            Ok(resp) => {
                if resp.upgrade_required {
                    let min = resp.min_agent_version.as_deref().unwrap_or("unknown");
                    warn!("Server requires agent upgrade (min_version: {min})");
                    if is_ready {
                        probes.remove_readiness();
                        is_ready = false;
                    }
                } else if let Some(ref sv) = resp.server_version {
                    let av = env!("CARGO_PKG_VERSION");
                    if sv != av {
                        info!("Server version: {sv}, agent version: {av}");
                    }
                }
                if !is_ready && !resp.upgrade_required {
                    info!(
                        phase = "ready",
                        consecutive_failures, "poll recovered, readiness restored"
                    );
                    probes.restore_readiness();
                    is_ready = true;
                }
                consecutive_failures = 0;
                for job in resp.jobs {
                    let request_id = job.id.clone();
                    let operation = job.operation.clone();
                    tracker.insert(request_id.clone(), operation);
                    let guard = JobGuard {
                        tracker: tracker.clone(),
                        request_id,
                    };
                    let exec = executor.clone();
                    let drain_flag = draining.clone();
                    tokio::spawn(async move {
                        let _guard = guard;
                        if let Err(e) = exec.execute_job(job, drain_flag).await {
                            error!("job execution failed: {e}");
                        }
                    });
                }
                // Process dry-run EXPLAIN jobs (fire-and-forget, not tracked)
                for dry_job in resp.dry_run_jobs {
                    let client_dr = client.clone();
                    let pools_dr = pools.clone();
                    tokio::spawn(async move {
                        let key = (dry_job.database.clone(), dry_job.environment.clone());
                        let Some(entry) = pools_dr.get(&key) else {
                            return;
                        };
                        let claim_token = match client_dr.dry_run_claim(&dry_job.id).await {
                            Ok(t) => t,
                            Err(AgentError::AlreadyClaimed) => return,
                            Err(AgentError::ServerError {
                                status: 404 | 501, ..
                            }) => return,
                            Err(e) => {
                                warn!(job_id = %dry_job.id, %e, "dry-run claim failed");
                                return;
                            }
                        };
                        let driver = entry.driver.read().await;
                        let (result, error) = match driver.explain(&dry_job.sql, 5).await {
                            Ok(plan) => (Some(plan), None),
                            Err(e) => (None, Some(e.to_string())),
                        };
                        if let Err(e) = client_dr
                            .dry_run_result(
                                &dry_job.id,
                                &claim_token,
                                result.as_ref(),
                                error.as_deref(),
                            )
                            .await
                        {
                            warn!(job_id = %dry_job.id, %e, "dry-run result submit failed");
                        }
                    });
                }
            }
            Err(e) => {
                consecutive_failures += 1;
                if consecutive_failures <= 3 {
                    warn!(consecutive_failures, "poll failed: {e}");
                } else if consecutive_failures == 6 {
                    warn!(
                        consecutive_failures,
                        "poll failures exceeded threshold, removing readiness"
                    );
                    probes.remove_readiness();
                    is_ready = false;
                }
            }
        }

        tokio::time::sleep(poll_interval).await;
    }
    Ok(())
}
