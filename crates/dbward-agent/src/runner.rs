use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use dbward_api_types::agent::{ActiveJob, AgentStatusReport, PollRequest};
use dbward_driver::DatabaseDriver;
use tracing::{error, info, warn};

use crate::AgentError;
use crate::client::AgentClient;
use crate::config::{AgentConfig, DatabaseEntry};
use crate::executor::JobExecutor;
use crate::probes::ProbeGuard;

/// Tracks in-flight jobs for observability. Single lock for consistent snapshots.
struct JobTracker {
    jobs: std::sync::Mutex<BTreeMap<String, (String, Instant)>>,
}

impl JobTracker {
    fn new() -> Self {
        Self {
            jobs: std::sync::Mutex::new(BTreeMap::new()),
        }
    }

    fn insert(&self, request_id: String, operation: String) {
        self.jobs
            .lock()
            .unwrap()
            .insert(request_id, (operation, Instant::now()));
    }

    fn remove(&self, request_id: &str) {
        self.jobs.lock().unwrap().remove(request_id);
    }

    fn snapshot(&self) -> (u32, Vec<ActiveJob>) {
        let jobs = self.jobs.lock().unwrap();
        let in_flight = jobs.len() as u32;
        let active_jobs = jobs
            .iter()
            .map(|(id, (op, start))| ActiveJob {
                request_id: id.clone(),
                operation: op.clone(),
                elapsed_secs: start.elapsed().as_secs(),
            })
            .collect();
        (in_flight, active_jobs)
    }
}

/// Guard that removes a job from the tracker on drop.
struct JobGuard {
    tracker: Arc<JobTracker>,
    request_id: String,
}

impl Drop for JobGuard {
    fn drop(&mut self) {
        self.tracker.remove(&self.request_id);
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

    let client = Arc::new(AgentClient::new(
        &config.server.url,
        &config.server.agent_token,
    )?);

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

    // Initial poll to validate token (send status from the start)
    let init_req = PollRequest {
        agent_id: None,
        capabilities: dbward_api_types::agent::PollCapabilities {
            databases: databases.clone(),
            environments: environments.clone(),
            operations: operations.clone(),
        },
        limit: 0,
        status: Some(AgentStatusReport {
            in_flight: 0,
            max_concurrent,
            draining: false,
            uptime_secs: 0,
            active_jobs: vec![],
        }),
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

    let tracker = Arc::new(JobTracker::new());
    let start_time = Instant::now();
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
            // Send final drain status before exiting poll loop
            let (current_in_flight, active_jobs) = tracker.snapshot();
            let drain_req = PollRequest {
                agent_id: None,
                capabilities: dbward_api_types::agent::PollCapabilities {
                    databases: databases.clone(),
                    environments: environments.clone(),
                    operations: operations.clone(),
                },
                limit: 0,
                status: Some(AgentStatusReport {
                    in_flight: current_in_flight,
                    max_concurrent,
                    draining: true,
                    uptime_secs: start_time.elapsed().as_secs(),
                    active_jobs,
                }),
            };
            let _ = client.poll(&drain_req).await;
            probes.remove_readiness();
            break;
        }

        let (current_in_flight, active_jobs) = tracker.snapshot();
        let available = max_concurrent.saturating_sub(current_in_flight);

        let req = PollRequest {
            agent_id: None,
            capabilities: dbward_api_types::agent::PollCapabilities {
                databases: databases.clone(),
                environments: environments.clone(),
                operations: operations.clone(),
            },
            limit: available,
            status: Some(AgentStatusReport {
                in_flight: current_in_flight,
                max_concurrent,
                draining: draining.load(Ordering::Relaxed),
                uptime_secs: start_time.elapsed().as_secs(),
                active_jobs,
            }),
        };

        match client.poll(&req).await {
            Ok(resp) => {
                if consecutive_failures >= 6 {
                    probes.restore_readiness();
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
            }
            Err(e) => {
                consecutive_failures += 1;
                warn!(consecutive_failures, "poll failed: {e}");
                if consecutive_failures >= 6 {
                    probes.remove_readiness();
                }
            }
        }

        tokio::time::sleep(poll_interval).await;
    }

    // Drain phase
    info!("draining, waiting for in-flight jobs");
    let drain_deadline = tokio::time::Instant::now() + drain_timeout;
    while tracker.snapshot().0 > 0 {
        if tokio::time::Instant::now() >= drain_deadline {
            error!("drain timeout exceeded");
            drop(probes);
            return Err(AgentError::DrainTimeout);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Final poll to clear stale state on server
    let final_req = PollRequest {
        agent_id: None,
        capabilities: dbward_api_types::agent::PollCapabilities {
            databases: databases.clone(),
            environments: environments.clone(),
            operations: operations.clone(),
        },
        limit: 0,
        status: Some(AgentStatusReport {
            in_flight: 0,
            max_concurrent,
            draining: true,
            uptime_secs: start_time.elapsed().as_secs(),
            active_jobs: vec![],
        }),
    };
    let _ = client.poll(&final_req).await;

    drop(probes);
    info!("agent shutdown complete");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_tracker_insert_remove() {
        let tracker = JobTracker::new();
        tracker.insert("req-1".into(), "execute_query".into());
        tracker.insert("req-2".into(), "migrate_up".into());

        let (count, jobs) = tracker.snapshot();
        assert_eq!(count, 2);
        assert_eq!(jobs[0].request_id, "req-1");
        assert_eq!(jobs[1].request_id, "req-2");

        tracker.remove("req-1");
        let (count, jobs) = tracker.snapshot();
        assert_eq!(count, 1);
        assert_eq!(jobs[0].request_id, "req-2");
    }

    #[test]
    fn job_guard_removes_on_drop() {
        let tracker = Arc::new(JobTracker::new());
        tracker.insert("req-1".into(), "execute_query".into());
        {
            let _guard = JobGuard {
                tracker: tracker.clone(),
                request_id: "req-1".into(),
            };
            assert_eq!(tracker.snapshot().0, 1);
        }
        assert_eq!(tracker.snapshot().0, 0);
    }
}
