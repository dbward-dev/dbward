use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use dbward_api_types::agent::{ActiveJob, AgentStatusReport, PollRequest};
use tracing::{error, info, warn};

use crate::AgentError;
use crate::client::AgentClient;
use crate::config::AgentConfig;
use crate::executor::{JobExecutor, PoolEntry, PoolRegistry};
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
    let (public_key, pools) = match startup_with_retry(
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
    // TODO(v0.1.3-phase2): re-run schema sync after migration execution completes
    {
        let client_bg = client.clone();
        let pools_bg = pools.clone();
        tokio::spawn(async move {
            for ((db_name, env_name), entry) in pools_bg.iter() {
                let driver = entry.driver.read().await;
                let (dialect, status, snapshot, error_message) = match driver.collect_schema().await
                {
                    Ok(snap) => {
                        let json = serde_json::to_value(&snap).ok();
                        (driver.dialect(), "ready", json, None)
                    }
                    Err(e) => (driver.dialect(), "failed", None, Some(e.to_string())),
                };
                match client_bg
                    .schema_sync(
                        db_name,
                        env_name,
                        dialect,
                        status,
                        snapshot.as_ref(),
                        error_message.as_deref(),
                    )
                    .await
                {
                    Ok(_) => {
                        info!(
                            database = db_name,
                            environment = env_name,
                            "schema sync completed"
                        );
                    }
                    Err(AgentError::ServerError {
                        status: 404 | 501, ..
                    }) => {
                        info!(
                            database = db_name,
                            "schema-sync not supported by server (upgrade to v0.1.3+)"
                        );
                    }
                    Err(e) => {
                        warn!(database = db_name, environment = env_name, %e, "schema sync failed");
                    }
                }
            }
        });
    }

    let databases: Vec<String> = config.databases.keys().cloned().collect();
    let environments: Vec<String> = config
        .databases
        .values()
        .flat_map(|envs| envs.keys().cloned())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
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
    poll_loop(
        &client,
        &executor,
        &pools,
        &tracker,
        &draining,
        &probes,
        &databases,
        &environments,
        &operations,
        max_concurrent,
        poll_interval,
        health_rx,
        start_time,
    )
    .await?;

    // --- Drain ---
    drain(
        &client,
        &tracker,
        &databases,
        &environments,
        &operations,
        max_concurrent,
        drain_timeout,
        start_time,
    )
    .await
}

/// Startup phase: fetch public key, connect databases, validate token.
/// Returns None if shutdown was requested during startup.
#[allow(clippy::too_many_arguments)]
async fn startup_with_retry(
    config: &AgentConfig,
    client: &Arc<AgentClient>,
    draining: &Arc<AtomicBool>,
    initial_ms: u64,
    max_ms: u64,
    deadline_secs: u64,
    operations: &[String],
    max_concurrent: u32,
) -> Result<Option<(ed25519_dalek::VerifyingKey, Arc<PoolRegistry>)>, AgentError> {
    let start = Instant::now();

    // Fetch public key
    let public_key = {
        let mut backoff_ms = initial_ms;
        let mut logger = RetryLogger::new();
        loop {
            if draining.load(Ordering::Acquire) {
                info!("shutdown during startup, exiting");
                return Ok(None);
            }
            if deadline_secs > 0 && start.elapsed() > Duration::from_secs(deadline_secs) {
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
                    if interruptible_sleep(backoff_ms, draining).await {
                        info!("shutdown during startup, exiting");
                        return Ok(None);
                    }
                    backoff_ms = (backoff_ms * 2).min(max_ms);
                }
            }
        }
    };

    // Connect databases
    let mut registry: PoolRegistry = HashMap::new();
    for (db_name, envs) in &config.databases {
        for (env_name, entry) in envs {
            let mut backoff_ms = initial_ms;
            let mut logger = RetryLogger::new();
            let driver = loop {
                if draining.load(Ordering::Acquire) {
                    info!("shutdown during startup, exiting");
                    return Ok(None);
                }
                if deadline_secs > 0 && start.elapsed() > Duration::from_secs(deadline_secs) {
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
                                phase = "startup", database = db_name, environment = env_name,
                                %agent_err, "hard error connecting database, exiting"
                            );
                            return Err(agent_err);
                        }
                        logger.log_failure(
                            &format!("database:{db_name}/{env_name}"),
                            &agent_err,
                            backoff_ms,
                        );
                        if interruptible_sleep(backoff_ms, draining).await {
                            info!("shutdown during startup, exiting");
                            return Ok(None);
                        }
                        backoff_ms = (backoff_ms * 2).min(max_ms);
                    }
                }
            };
            registry.insert(
                (db_name.clone(), env_name.clone()),
                PoolEntry {
                    driver: Arc::new(tokio::sync::RwLock::new(driver)),
                    config: entry.clone(),
                },
            );
        }
    }
    let pools = Arc::new(registry);

    // Initial poll to validate token
    let databases: Vec<String> = config.databases.keys().cloned().collect();
    let environments: Vec<String> = config
        .databases
        .values()
        .flat_map(|envs| envs.keys().cloned())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    {
        let mut backoff_ms = initial_ms;
        let mut logger = RetryLogger::new();
        let init_req = PollRequest {
            agent_id: None,
            capabilities: dbward_api_types::agent::PollCapabilities {
                databases: databases.clone(),
                environments: environments.clone(),
                operations: operations.to_vec(),
            },
            limit: 0,
            status: Some(AgentStatusReport {
                in_flight: 0,
                max_concurrent,
                draining: false,
                uptime_secs: 0,
                active_jobs: vec![],
            }),
            agent_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        };
        loop {
            if draining.load(Ordering::Acquire) {
                info!("shutdown during startup, exiting");
                return Ok(None);
            }
            if deadline_secs > 0 && start.elapsed() > Duration::from_secs(deadline_secs) {
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
                    if interruptible_sleep(backoff_ms, draining).await {
                        info!("shutdown during startup, exiting");
                        return Ok(None);
                    }
                    backoff_ms = (backoff_ms * 2).min(max_ms);
                }
            }
        }
    }

    Ok(Some((public_key, pools)))
}
/// Poll loop: dispatch jobs, manage degraded mode, handle health events.
/// Returns when draining signal is received.
#[allow(clippy::too_many_arguments)]
async fn poll_loop(
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

/// Drain phase: wait for in-flight jobs, send final status.
#[allow(clippy::too_many_arguments)]
async fn drain(
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
    let _ = client.poll(&req).await;

    info!("agent shutdown complete");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_poll_request(
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
}
