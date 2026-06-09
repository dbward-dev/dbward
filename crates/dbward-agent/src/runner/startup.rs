use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use dbward_api_types::agent::{AgentStatusReport, PollRequest};
use tracing::{error, info, warn};

use crate::AgentError;
use crate::client::AgentClient;
use crate::config::AgentConfig;
use crate::executor::{PoolEntry, PoolRegistry};

use super::{RetryLogger, interruptible_sleep, is_hard_error};

async fn run_schema_sync_once(pools: Arc<PoolRegistry>, client: Arc<AgentClient>) {
    for ((db_name, env_name), entry) in pools.iter() {
        let driver = entry.driver.read().await;
        let (dialect, status, snapshot, error_message) = match driver.collect_schema().await {
            Ok(snap) => {
                let json = serde_json::to_value(&snap).ok();
                (driver.dialect(), "ready", json, None)
            }
            Err(e) => (driver.dialect(), "failed", None, Some(e.to_string())),
        };
        match client
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
}

/// Startup phase: fetch public key, connect databases, validate token.
/// Returns None if shutdown was requested during startup.
#[allow(clippy::too_many_arguments)]
pub(super) async fn startup_with_retry(
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

/// Spawn background schema sync tasks based on config.
pub(super) fn spawn_schema_sync(
    config: &AgentConfig,
    client: &Arc<AgentClient>,
    pools: &Arc<PoolRegistry>,
) {
    if config.schema_sync.enabled && config.schema_sync.sync_on_startup {
        let client_bg = client.clone();
        let pools_bg = pools.clone();
        tokio::spawn(run_schema_sync_once(pools_bg, client_bg));
    }
    if config.schema_sync.enabled && config.schema_sync.interval_secs > 0 {
        let client_bg = client.clone();
        let pools_bg = pools.clone();
        let interval = std::time::Duration::from_secs(config.schema_sync.interval_secs);
        tokio::spawn(async move {
            tokio::time::sleep(interval).await;
            loop {
                run_schema_sync_once(pools_bg.clone(), client_bg.clone()).await;
                tokio::time::sleep(interval).await;
            }
        });
    }
}
