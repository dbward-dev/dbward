mod drain;
mod poll;
mod startup;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use dbward_api_types::agent::ActiveJob;
use tracing::{info, warn};

use crate::AgentError;
use crate::client::AgentClient;
use crate::config::AgentConfig;
use crate::executor::JobExecutor;
use crate::probes::ProbeGuard;

/// Tracks in-flight jobs for observability. Single lock for consistent snapshots.
pub(super) struct JobTracker {
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
pub(super) struct JobGuard {
    tracker: Arc<JobTracker>,
    request_id: String,
}

impl Drop for JobGuard {
    fn drop(&mut self) {
        self.tracker.remove(&self.request_id);
    }
}

/// Classifies an error as hard (should exit) or transient (should retry).
pub(super) fn is_hard_error(err: &AgentError) -> bool {
    match err {
        AgentError::ServerError { status, .. } => {
            // 4xx = client error (config problem), except 429 (rate limit)
            *status != 429 && (400..500).contains(status)
        }
        AgentError::Config(_) => true,
        AgentError::TokenVerification(_) => true,
        AgentError::UnsupportedOperation(_) => true,
        AgentError::Driver(driver_err) => matches!(
            driver_err,
            dbward_driver::DriverError::UnsupportedScheme(_)
                | dbward_driver::DriverError::AuthenticationFailed(_)
        ),
        _ => false,
    }
}

/// Retry log state to avoid log flooding.
pub(super) struct RetryLogger {
    start: Instant,
    attempt: u32,
    last_summary: Instant,
}

impl RetryLogger {
    pub(super) fn new() -> Self {
        let now = Instant::now();
        Self {
            start: now,
            attempt: 0,
            last_summary: now,
        }
    }

    pub(super) fn log_failure(
        &mut self,
        target: &str,
        error: &dyn std::fmt::Display,
        next_ms: u64,
    ) {
        self.attempt += 1;
        if self.attempt <= 3 {
            warn!(
                phase = "startup",
                target,
                attempt = self.attempt,
                next_retry_ms = next_ms,
                %error,
                "startup blocked, retrying"
            );
        } else if self.last_summary.elapsed() >= Duration::from_secs(30) {
            let elapsed = self.start.elapsed().as_secs();
            warn!(
                phase = "startup",
                target,
                attempts = self.attempt,
                elapsed_secs = elapsed,
                %error,
                "still waiting for dependency"
            );
            self.last_summary = Instant::now();
        }
    }

    pub(super) fn log_recovered(&self, target: &str) {
        if self.attempt > 0 {
            let elapsed = self.start.elapsed().as_secs();
            info!(
                phase = "startup",
                target,
                attempts = self.attempt,
                downtime_secs = elapsed,
                "dependency recovered"
            );
        }
    }
}

/// Sleep that can be interrupted by shutdown signal.
pub(super) async fn interruptible_sleep(ms: u64, draining: &AtomicBool) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
    loop {
        if draining.load(Ordering::Acquire) {
            return true; // interrupted
        }
        let remaining = deadline - tokio::time::Instant::now();
        if remaining.is_zero() {
            return false; // completed
        }
        tokio::time::sleep(remaining.min(Duration::from_millis(500))).await;
    }
}

pub async fn run(config: AgentConfig) -> Result<(), AgentError> {
    let agent_id = config.agent_id();
    let max_concurrent = config.max_concurrent_tasks();
    let poll_interval = Duration::from_millis(config.poll_interval_ms());
    let drain_timeout = Duration::from_secs(config.drain_timeout_secs());
    let statement_timeout = config.statement_timeout_secs();
    let operations = config.operations();
    if config.operations.is_none() {
        tracing::warn!(
            "agent.operations not configured; all standard operations including migrations are enabled. \
             Note: migrate_repair requires explicit configuration. \
             Set [agent].operations explicitly for production use."
        );
    }
    let startup_initial = config.startup_retry_initial_ms();
    let startup_max = config.startup_retry_max_ms();
    let startup_deadline = config.startup_max_wait_secs();

    info!(agent_id, "starting agent");

    let start_time = Instant::now();
    let probes = ProbeGuard::create_liveness("/tmp/dbward-agent-alive", "/tmp/dbward-agent-ready")?;

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

    let client = Arc::new(AgentClient::new(
        &config.server.url,
        &config.server.agent_token,
    )?);

    // --- Startup ---
    let (public_key, pools) = match startup::startup_with_retry(
        &config,
        &client,
        &draining,
        startup_initial,
        startup_max,
        startup_deadline,
        &operations,
        max_concurrent,
    )
    .await?
    {
        Some(result) => result,
        None => return Ok(()), // shutdown during startup
    };

    // --- Ready ---
    probes.set_ready();
    info!(phase = "ready", "agent initialized and accepting work");

    // --- Background schema sync (non-blocking) ---
    startup::spawn_schema_sync(&config, &client, &pools);

    let scopes: Vec<(String, String)> = config
        .databases
        .iter()
        .flat_map(|(db_name, envs)| {
            envs.keys()
                .map(move |env_name| (db_name.clone(), env_name.clone()))
        })
        .collect();

    let tracker = Arc::new(JobTracker::new());
    let (health_tx, health_rx) =
        tokio::sync::mpsc::unbounded_channel::<crate::executor::PoolHealthEvent>();

    let executor = Arc::new(JobExecutor {
        client: client.clone(),
        public_key,
        pools: pools.clone(),
        statement_timeout_secs: statement_timeout,
        health_tx,
    });

    // --- Poll Loop ---
    poll::poll_loop(
        &client,
        &executor,
        &pools,
        &tracker,
        &draining,
        &probes,
        &scopes,
        &operations,
        max_concurrent,
        poll_interval,
        health_rx,
        start_time,
    )
    .await?;

    // --- Drain ---
    drain::drain(
        &client,
        &tracker,
        &scopes,
        &operations,
        max_concurrent,
        drain_timeout,
        start_time,
    )
    .await
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

    #[test]
    fn is_hard_error_classification() {
        assert!(is_hard_error(&AgentError::ServerError {
            status: 401,
            body: "unauthorized".into()
        }));
        assert!(is_hard_error(&AgentError::ServerError {
            status: 403,
            body: "forbidden".into()
        }));
        assert!(is_hard_error(&AgentError::ServerError {
            status: 404,
            body: "not found".into()
        }));
        assert!(is_hard_error(&AgentError::ServerError {
            status: 400,
            body: "bad request".into()
        }));
        assert!(is_hard_error(&AgentError::Config("bad".into())));
        assert!(is_hard_error(&AgentError::TokenVerification("bad".into())));
        assert!(is_hard_error(&AgentError::Driver(
            dbward_driver::DriverError::UnsupportedScheme("sqlite://".into())
        )));
        assert!(is_hard_error(&AgentError::Driver(
            dbward_driver::DriverError::AuthenticationFailed("password failed".into())
        )));
        assert!(is_hard_error(&AgentError::UnsupportedOperation(
            "future_op".into()
        )));

        // Transient
        assert!(!is_hard_error(&AgentError::ServerError {
            status: 500,
            body: "internal".into()
        }));
        assert!(!is_hard_error(&AgentError::ServerError {
            status: 503,
            body: "unavailable".into()
        }));
        assert!(!is_hard_error(&AgentError::ServerError {
            status: 429,
            body: "rate limited".into()
        }));
        assert!(!is_hard_error(&AgentError::Driver(
            dbward_driver::DriverError::ConnectionFailed("connection refused".into())
        )));
    }

    #[test]
    fn scopes_from_config_produces_correct_pairs() {
        use std::collections::HashMap;

        // Simulate config.databases structure: HashMap<db, HashMap<env, _>>
        let mut databases: HashMap<String, HashMap<String, ()>> = HashMap::new();
        databases
            .entry("app".into())
            .or_default()
            .insert("production".into(), ());
        databases
            .entry("app".into())
            .or_default()
            .insert("staging".into(), ());
        databases
            .entry("analytics".into())
            .or_default()
            .insert("production".into(), ());

        // Same logic as runner/mod.rs
        let scopes: Vec<(String, String)> = databases
            .iter()
            .flat_map(|(db_name, envs)| {
                envs.keys()
                    .map(move |env_name| (db_name.clone(), env_name.clone()))
            })
            .collect();

        // Should produce exactly 3 pairs, no extras
        assert_eq!(scopes.len(), 3);
        assert!(scopes.contains(&("app".into(), "production".into())));
        assert!(scopes.contains(&("app".into(), "staging".into())));
        assert!(scopes.contains(&("analytics".into(), "production".into())));
        // Should NOT contain cross-product phantom
        assert!(!scopes.contains(&("analytics".into(), "staging".into())));
    }
}
