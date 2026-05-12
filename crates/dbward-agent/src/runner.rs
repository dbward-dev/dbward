use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dbward_api_types::agent::{AgentStatusReport, PollRequest};
use dbward_driver::DatabaseDriver;
use tracing::{error, info, warn};

use crate::client::AgentClient;
use crate::config::{AgentConfig, DatabaseEntry};
use crate::executor::JobExecutor;
use crate::probes::ProbeGuard;
use crate::AgentError;

struct InFlightGuard {
    counter: Arc<AtomicU32>,
}

impl InFlightGuard {
    fn acquire(counter: &Arc<AtomicU32>) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        Self {
            counter: counter.clone(),
        }
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Relaxed);
    }
}

pub async fn run(config: AgentConfig) -> Result<(), AgentError> {
    let agent_id = config.agent_id();
    let max_concurrent = config.max_concurrent_tasks();
    let poll_interval = Duration::from_millis(config.poll_interval_ms());
    let drain_timeout = Duration::from_secs(config.drain_timeout_secs());
    let statement_timeout = config.statement_timeout_secs();
    let operations = config.operations();

    info!(agent_id, "starting agent");

    let client = Arc::new(AgentClient::new(&config.server.url, &config.server.agent_token)?);

    // Fail-fast: fetch public key
    let public_key = client.fetch_public_key().await?;
    info!("public key fetched");

    // Connect to all databases
    let mut pools: HashMap<(String, String), Arc<dyn DatabaseDriver>> = HashMap::new();
    let mut db_entries: HashMap<(String, String), DatabaseEntry> = HashMap::new();
    for (db_name, envs) in &config.databases {
        for (env_name, entry) in envs {
            let driver = dbward_driver::connect(&entry.url, None)
                .await
                .map_err(|e| {
                    AgentError::Config(format!(
                        "database '{}' environment '{}': {}",
                        db_name, env_name, e
                    ))
                })?;
            pools.insert((db_name.clone(), env_name.clone()), driver);
            db_entries.insert((db_name.clone(), env_name.clone()), entry.clone());
            info!(database = db_name, environment = env_name, "connected");
        }
    }
    let pools = Arc::new(pools);
    let db_entries = Arc::new(db_entries);

    // Build capabilities for poll
    let databases: Vec<String> = config.databases.keys().cloned().collect();
    let environments: Vec<String> = config
        .databases
        .values()
        .flat_map(|envs| envs.keys().cloned())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    // Initial poll to validate token
    let init_req = PollRequest {
        databases: databases.clone(),
        environments: environments.clone(),
        operations: operations.clone(),
        limit: 0,
        status: None,
    };
    client.poll(&init_req).await?;
    info!("initial poll successful, token valid");

    // Probes
    let probes = ProbeGuard::create("/tmp/dbward-agent-alive", "/tmp/dbward-agent-ready")?;

    // Signal handling
    let draining = Arc::new(AtomicBool::new(false));
    let draining_signal = draining.clone();
    tokio::spawn(async move {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
        let sigint = tokio::signal::ctrl_c();
        tokio::select! {
            _ = sigterm.recv() => {}
            _ = sigint => {}
        }
        info!("shutdown signal received, draining");
        draining_signal.store(true, Ordering::Release);
    });

    let in_flight = Arc::new(AtomicU32::new(0));
    let start_time = std::time::Instant::now();
    let mut consecutive_failures: u32 = 0;

    let executor = Arc::new(JobExecutor {
        client: client.clone(),
        public_key,
        pools,
        db_entries,
        statement_timeout_secs: statement_timeout,
    });

    // Poll loop
    loop {
        if draining.load(Ordering::Acquire) {
            // Medium Fix 1: remove readiness immediately on drain
            probes.remove_readiness();
            break;
        }

        let current_in_flight = in_flight.load(Ordering::Relaxed);
        let available = max_concurrent.saturating_sub(current_in_flight);

        if available > 0 {
            let req = PollRequest {
                databases: databases.clone(),
                environments: environments.clone(),
                operations: operations.clone(),
                limit: available,
                status: Some(AgentStatusReport {
                    in_flight: current_in_flight,
                    max_concurrent: max_concurrent,
                    draining: false,
                    uptime_secs: start_time.elapsed().as_secs(),
                    active_jobs: vec![],
                }),
            };

            match client.poll(&req).await {
                Ok(resp) => {
                    if consecutive_failures >= 6 {
                        // High Fix 3: restore readiness after recovery
                        probes.restore_readiness();
                    }
                    consecutive_failures = 0;
                    for job in resp.jobs {
                        let guard = InFlightGuard::acquire(&in_flight);
                        let exec = executor.clone();
                        let drain_flag = draining.clone();
                        tokio::spawn(async move {
                            let _guard = guard;
                            if let Err(e) = exec.execute_job(job, drain_flag).await {
                                error!("job execution failed: {e}");
                            }
                        });
                    }
                }
                Err(e) => {
                    consecutive_failures += 1;
                    warn!(consecutive_failures, "poll failed: {e}");
                    if consecutive_failures >= 6 {
                        probes.remove_readiness();
                    }
                }
            }
        }

        tokio::time::sleep(poll_interval).await;
    }

    // Drain phase
    info!("draining, waiting for in-flight jobs");
    let drain_deadline = tokio::time::Instant::now() + drain_timeout;
    while in_flight.load(Ordering::Relaxed) > 0 {
        if tokio::time::Instant::now() >= drain_deadline {
            error!("drain timeout exceeded");
            drop(probes);
            return Err(AgentError::DrainTimeout);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    drop(probes);
    info!("agent shutdown complete");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_flight_guard() {
        let counter = Arc::new(AtomicU32::new(0));
        {
            let _g1 = InFlightGuard::acquire(&counter);
            assert_eq!(counter.load(Ordering::Relaxed), 1);
            {
                let _g2 = InFlightGuard::acquire(&counter);
                assert_eq!(counter.load(Ordering::Relaxed), 2);
            }
            assert_eq!(counter.load(Ordering::Relaxed), 1);
        }
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }
}
