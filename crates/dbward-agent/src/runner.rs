use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use dbward_api_types::agent::{ActiveJob, AgentStatusReport, PollRequest};
use tracing::{error, info, warn};

use crate::AgentError;
use crate::client::AgentClient;
use crate::config::{AgentConfig, DatabaseEntry};
use crate::executor::{JobExecutor, PoolMap};
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

/// Classifies an error as hard (should exit) or transient (should retry).
fn is_hard_error(err: &AgentError) -> bool {
    match err {
        AgentError::ServerError { status, .. } => {
            // 4xx = client error (config problem), except 429 (rate limit)
            *status != 429 && (400..500).contains(status)
        }
        AgentError::Config(_) => true,
        AgentError::TokenVerification(_) => true,
        AgentError::Driver(driver_err) => matches!(
            driver_err,
            dbward_driver::DriverError::UnsupportedScheme(_)
                | dbward_driver::DriverError::AuthenticationFailed(_)
        ),
        _ => false,
    }
}

/// Retry log state to avoid log flooding.
struct RetryLogger {
    start: Instant,
    attempt: u32,
    last_summary: Instant,
}

impl RetryLogger {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            start: now,
            attempt: 0,
            last_summary: now,
        }
    }

    fn log_failure(&mut self, target: &str, error: &dyn std::fmt::Display, next_ms: u64) {
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

    fn log_recovered(&self, target: &str) {
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
async fn interruptible_sleep(ms: u64, draining: &AtomicBool) -> bool {
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
    let startup_initial = config.startup_retry_initial_ms();
    let startup_max = config.startup_retry_max_ms();
    let startup_deadline = config.startup_max_wait_secs();

    info!(agent_id, "starting agent");

    // Liveness probe immediately — process is alive
    let probes = ProbeGuard::create_liveness("/tmp/dbward-agent-alive", "/tmp/dbward-agent-ready")?;

    // Install signal handler BEFORE startup retries
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

    let startup_start = Instant::now();

    // --- Startup Phase: fetch public key ---
    let public_key = {
        let mut backoff_ms = startup_initial;
        let mut logger = RetryLogger::new();
        loop {
            if draining.load(Ordering::Acquire) {
                info!("shutdown during startup, exiting");
                return Ok(());
            }
            if startup_deadline > 0
                && startup_start.elapsed() > Duration::from_secs(startup_deadline)
            {
                error!(phase = "startup", "startup timeout exceeded, exiting");
                return Err(AgentError::Config("startup timeout exceeded".into()));
            }
            match client.fetch_public_key().await {
                Ok(key) => {
                    logger.log_recovered("server");
                    info!("public key fetched");
                    break key;
                }
                Err(e) if is_hard_error(&e) => {
                    error!(phase = "startup", %e, "hard error, exiting");
                    return Err(e);
                }
                Err(e) => {
                    logger.log_failure("server", &e, backoff_ms);
                    if interruptible_sleep(backoff_ms, &draining).await {
                        info!("shutdown during startup, exiting");
                        return Ok(());
                    }
                    backoff_ms = (backoff_ms * 2).min(startup_max);
                }
            }
        }
    };

    // --- Startup Phase: connect databases ---
    let mut pools: PoolMap = HashMap::new();
    let mut db_entries: HashMap<(String, String), DatabaseEntry> = HashMap::new();
    for (db_name, envs) in &config.databases {
        for (env_name, entry) in envs {
            let mut backoff_ms = startup_initial;
            let mut logger = RetryLogger::new();
            let driver = loop {
                if draining.load(Ordering::Acquire) {
                    info!("shutdown during startup, exiting");
                    return Ok(());
                }
                if startup_deadline > 0
                    && startup_start.elapsed() > Duration::from_secs(startup_deadline)
                {
                    error!(phase = "startup", "startup timeout exceeded, exiting");
                    return Err(AgentError::Config("startup timeout exceeded".into()));
                }
                match dbward_driver::connect(&entry.url, None).await {
                    Ok(d) => {
                        logger.log_recovered(&format!("database:{db_name}/{env_name}"));
                        info!(database = db_name, environment = env_name, "connected");
                        break d;
                    }
                    Err(e) => {
                        let agent_err = AgentError::Driver(e);
                        if is_hard_error(&agent_err) {
                            error!(
                                phase = "startup",
                                database = db_name,
                                environment = env_name,
                                %agent_err,
                                "hard error connecting database, exiting"
                            );
                            return Err(agent_err);
                        }
                        logger.log_failure(
                            &format!("database:{db_name}/{env_name}"),
                            &agent_err,
                            backoff_ms,
                        );
                        if interruptible_sleep(backoff_ms, &draining).await {
                            info!("shutdown during startup, exiting");
                            return Ok(());
                        }
                        backoff_ms = (backoff_ms * 2).min(startup_max);
                    }
                }
            };
            pools.insert(
                (db_name.clone(), env_name.clone()),
                Arc::new(tokio::sync::RwLock::new(driver)),
            );
            db_entries.insert((db_name.clone(), env_name.clone()), entry.clone());
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

    // --- Startup Phase: initial poll to validate token ---
    {
        let mut backoff_ms = startup_initial;
        let mut logger = RetryLogger::new();
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
        loop {
            if draining.load(Ordering::Acquire) {
                info!("shutdown during startup, exiting");
                return Ok(());
            }
            if startup_deadline > 0
                && startup_start.elapsed() > Duration::from_secs(startup_deadline)
            {
                error!(phase = "startup", "startup timeout exceeded, exiting");
                return Err(AgentError::Config("startup timeout exceeded".into()));
            }
            match client.poll(&init_req).await {
                Ok(_) => {
                    logger.log_recovered("initial_poll");
                    info!("initial poll successful, token valid");
                    break;
                }
                Err(e) if is_hard_error(&e) => {
                    error!(phase = "startup", %e, "hard error during initial poll, exiting");
                    return Err(e);
                }
                Err(e) => {
                    logger.log_failure("initial_poll", &e, backoff_ms);
                    if interruptible_sleep(backoff_ms, &draining).await {
                        info!("shutdown during startup, exiting");
                        return Ok(());
                    }
                    backoff_ms = (backoff_ms * 2).min(startup_max);
                }
            }
        }
    }

    // --- Ready ---
    probes.set_ready();
    info!(phase = "ready", "agent initialized and accepting work");

    let tracker = Arc::new(JobTracker::new());
    let start_time = Instant::now();
    let mut consecutive_failures: u32 = 0;
    let mut is_ready = true;

    // Health channel for degraded mode
    let (health_tx, mut health_rx) =
        tokio::sync::mpsc::unbounded_channel::<crate::executor::PoolHealthEvent>();
    let mut pool_failure_counts: HashMap<(String, String), u32> = HashMap::new();
    let mut degraded = false;

    let executor = Arc::new(JobExecutor {
        client: client.clone(),
        public_key,
        pools: pools.clone(),
        db_entries: db_entries.clone(),
        statement_timeout_secs: statement_timeout,
        health_tx,
    });

    // Poll loop
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
                    let key = (database, environment);
                    pool_failure_counts.remove(&key);
                }
            }
        }

        // Degraded: attempt reconnect probe
        if degraded {
            let mut all_healthy = true;
            for ((db_name, env_name), entry) in db_entries.iter() {
                let key = (db_name.clone(), env_name.clone());
                if pool_failure_counts.get(&key).copied().unwrap_or(0) < 2 {
                    continue;
                }
                match tokio::time::timeout(
                    Duration::from_secs(5),
                    dbward_driver::connect(&entry.url, None),
                )
                .await
                {
                    Ok(Ok(new_driver)) => {
                        // Swap pool
                        if let Some(lock) = pools.get(&key) {
                            *lock.write().await = new_driver;
                        }
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
                        error!(
                            phase = "degraded",
                            database = db_name,
                            environment = env_name,
                            %e,
                            "authentication failed during reconnect, exiting"
                        );
                        return Err(AgentError::Driver(e));
                    }
                    _ => {
                        all_healthy = false;
                    }
                }
            }
            if all_healthy || pool_failure_counts.values().all(|c| *c < 2) {
                degraded = false;
                // Only restore readiness if poll is also healthy
                if consecutive_failures == 0 {
                    is_ready = true;
                    probes.restore_readiness();
                    info!(
                        phase = "ready",
                        "all databases recovered, readiness restored"
                    );
                } else {
                    info!(
                        phase = "degraded",
                        "databases recovered, waiting for server poll to stabilize"
                    );
                }
            }
        }

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
        // When not ready (poll failures or degraded), request no new jobs
        let available = if is_ready && !degraded {
            max_concurrent.saturating_sub(current_in_flight)
        } else {
            0
        };

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
                if !is_ready {
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
                // After threshold, log summary every 30s handled by poll interval
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
}
