use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dbward_core::{AgentConfig, Engine, Error};
use dbward_migrate::Migrator;
use tokio::sync::Semaphore;
use tracing::{error, info, warn, Instrument};

use crate::server_client::AgentClient;

const ALIVE_PROBE_PATH: &str = "/tmp/dbward-agent-alive";
const READY_PROBE_PATH: &str = "/tmp/dbward-agent-ready";

/// Guard that decrements in_flight on drop (panic-safe).
struct InFlightGuard(Arc<AtomicUsize>);
impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Run the agent poll loop. Blocks until interrupted.
pub async fn run(config: AgentConfig) -> Result<(), Error> {
    let client = AgentClient::new(&config.server.url, &config.server.agent_token);
    let poll_interval = Duration::from_millis(config.poll_interval_ms);
    let draining = Arc::new(AtomicBool::new(false));
    let in_flight = Arc::new(AtomicUsize::new(0));
    let max_concurrent = config.max_concurrent_tasks.max(1) as usize;
    let semaphore = Arc::new(Semaphore::new(max_concurrent));

    // Fetch server's public key for token verification
    let public_key = client.get_public_key().await?;

    // Verify DB connectivity for all configured databases
    for (name, db_config) in &config.databases {
        info!(database = %name, "verifying database connection");
        let driver = dbward_core::driver::connect_with_timeout(
            &db_config.url,
            Some(config.statement_timeout_secs.unwrap_or(30)),
        )
            .await
            .map_err(|e| {
                Error::Config(format!(
                    "failed to connect to database '{name}': {e}. Check url in agent config."
                ))
            })?;
        drop(driver);
    }

    // Verify server connectivity and agent token validity
    let cap = &config.capabilities;
    client
        .poll(&cap.databases, &cap.environments, &cap.operations, 1)
        .await
        .map_err(|e| Error::Config(format!("server connection check failed: {e}")))?;

    write_probe(ALIVE_PROBE_PATH)?;
    write_probe(READY_PROBE_PATH)?;
    let _probe_guard = ProbeGuard;

    info!(
        agent_id = %config.agent_id,
        server = %config.server.url,
        max_concurrent = max_concurrent,
        "agent started, polling"
    );

    install_shutdown_task(draining.clone());
    let mut drain_started_at = None;

    let consecutive_failures = AtomicUsize::new(0);
    let ready_removed = AtomicBool::new(false);

    loop {
        if draining.load(Ordering::SeqCst) {
            if drain_started_at.is_none() {
                drain_started_at = Some(tokio::time::Instant::now());
                if let Err(err) = remove_probe(READY_PROBE_PATH) {
                    warn!(%err, "failed to remove readiness probe");
                }
                info!("agent draining");
            }
            if should_exit_drain(&draining, &in_flight) {
                info!("agent shut down");
                return Ok(());
            }
            if drain_timed_out(drain_started_at, config.drain_timeout_secs) {
                return Err(Error::Server(format!(
                    "drain timed out after {}s",
                    config.drain_timeout_secs
                )));
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        }

        poll_once(
            &config,
            &client,
            &public_key,
            &in_flight,
            &semaphore,
            &consecutive_failures,
            &ready_removed,
        )
        .await;
        tokio::time::sleep(poll_interval).await;
    }
}

const MAX_CONSECUTIVE_POLL_FAILURES: usize = 6;

async fn poll_once(
    config: &AgentConfig,
    client: &AgentClient,
    public_key: &ed25519_dalek::VerifyingKey,
    in_flight: &Arc<AtomicUsize>,
    semaphore: &Arc<Semaphore>,
    consecutive_failures: &AtomicUsize,
    ready_removed: &AtomicBool,
) {
    // Only request as many jobs as we have capacity for
    let available = semaphore.available_permits() as u32;
    if available == 0 {
        return;
    }

    let jobs = match client
        .poll(
            &config.capabilities.databases,
            &config.capabilities.environments,
            &config.capabilities.operations,
            available,
        )
        .await
    {
        Ok(j) => {
            let prev = consecutive_failures.swap(0, Ordering::SeqCst);
            if prev >= MAX_CONSECUTIVE_POLL_FAILURES && ready_removed.swap(false, Ordering::SeqCst)
            {
                if let Err(e) = write_probe(READY_PROBE_PATH) {
                    warn!(%e, "failed to restore readiness probe");
                } else {
                    info!("readiness probe restored after recovery");
                }
            }
            j
        }
        Err(e) => {
            let count = consecutive_failures.fetch_add(1, Ordering::SeqCst) + 1;
            warn!(count, max = MAX_CONSECUTIVE_POLL_FAILURES, %e, "poll failed");
            if count >= MAX_CONSECUTIVE_POLL_FAILURES
                && !ready_removed.swap(true, Ordering::SeqCst)
            {
                if let Err(re) = remove_probe(READY_PROBE_PATH) {
                    warn!(%re, "failed to remove readiness probe");
                } else {
                    warn!(count, "readiness probe removed after consecutive poll failures");
                }
            }
            return;
        }
    };

    for job in jobs {
        let request_id = match job["id"].as_str() {
            Some(id) => id.to_string(),
            None => {
                warn!("skipping job with missing id field");
                continue;
            }
        };

        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => break, // no more capacity
        };

        let config = config.clone();
        let client = client.clone();
        let public_key = *public_key;
        let in_flight = in_flight.clone();

        in_flight.fetch_add(1, Ordering::SeqCst);
        let span = tracing::info_span!("job", request_id = %request_id);
        tokio::spawn(
            async move {
                let _guard = InFlightGuard(in_flight);

                if let Err(e) =
                    execute_job(&config, &client, &public_key, &request_id, &job).await
                {
                    error!(request_id = %request_id, %e, "job failed");
                }

                drop(permit);
            }
            .instrument(span),
        );
    }
}

async fn execute_job(
    config: &AgentConfig,
    client: &AgentClient,
    public_key: &ed25519_dalek::VerifyingKey,
    request_id: &str,
    _job: &serde_json::Value,
) -> Result<(), Error> {
    // Claim
    let claim = client.claim(request_id, &config.agent_id).await?;
    let exec_id = claim["execution_id"]
        .as_str()
        .ok_or_else(|| Error::Server("missing execution_id in claim".into()))?;
    let operation = claim["operation"].as_str().unwrap_or("");
    let environment = claim["environment"].as_str().unwrap_or("");
    let database = claim["database"].as_str().unwrap_or("");
    let detail = claim["detail"].as_str().unwrap_or("");

    info!(request_id, operation, database, "claimed job");

    // Verify token
    let token: dbward_core::token::ExecutionToken =
        serde_json::from_value(claim["execution_token"].clone())
            .map_err(|e| Error::Server(format!("invalid execution_token: {e}")))?;

    // Resolve DB and execute
    let resolved = config.resolve_database(database)?;
    let expected_detail = match operation {
        "migrate_up" | "migrate_down" => dbward_migrate::canonicalize_migration_approval_detail(
            &resolved.migrations_dir,
            detail,
        )?,
        _ => detail.to_string(),
    };

    dbward_core::token::verify_token(
        &token,
        public_key,
        operation,
        environment,
        database,
        &expected_detail,
    )?;

    let env = match environment {
        "production" => dbward_core::Environment::Production,
        "staging" => dbward_core::Environment::Staging,
        "development" => dbward_core::Environment::Development,
        other => dbward_core::Environment::Custom(other.to_string()),
    };

    // Cancel detection via heartbeat response
    let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let cancelled_clone = cancelled.clone();

    // Heartbeat + cancel check task
    let hb_client = client.clone();
    let hb_exec_id = exec_id.to_string();
    let cancel_check_interval = std::time::Duration::from_secs(2);
    let hb_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(cancel_check_interval);
        interval.tick().await; // skip immediate first tick
        loop {
            interval.tick().await;
            match hb_client.heartbeat(&hb_exec_id).await {
                Ok(true) => {
                    cancelled_clone.store(true, std::sync::atomic::Ordering::SeqCst);
                    break;
                }
                Ok(false) => {}
                Err(e) => {
                    warn!(%e, "heartbeat failed");
                }
            }
        }
    });

    let (result_value, success) = match execute_operation(&resolved, env, operation, detail).await {
        Ok(text) => {
            let val: serde_json::Value =
                serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text));
            (Some(val), true)
        }
        Err(e) => {
            let msg = e.to_string();
            error!(request_id, error = %msg, "job execution failed");
            hb_handle.abort();
            send_result_with_retry(client, exec_id, false, None, Some(&msg)).await;
            return Ok(());
        }
    };

    hb_handle.abort();

    if cancelled.load(std::sync::atomic::Ordering::SeqCst) {
        warn!(request_id, "job was cancelled during execution");
        send_result_with_retry(client, exec_id, false, None, Some("cancelled by user")).await;
        return Ok(());
    }

    info!(request_id, "job execution completed");
    send_result_with_retry(client, exec_id, success, result_value, None).await;
    Ok(())
}

async fn send_result_with_retry(
    client: &crate::server_client::AgentClient,
    exec_id: &str,
    success: bool,
    result: Option<serde_json::Value>,
    error: Option<&str>,
) {
    let mut backoff = std::time::Duration::from_secs(1);
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(300); // 5 min

    loop {
        match client
            .send_result(exec_id, success, result.clone(), error)
            .await
        {
            Ok(_) => return,
            Err(e) => {
                if tokio::time::Instant::now() + backoff > deadline {
                    error!(%e, "result submit failed after retries");
                    return;
                }
                warn!(%e, ?backoff, "result submit failed, retrying");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(std::time::Duration::from_secs(15));
            }
        }
    }
}

fn install_shutdown_task(draining: std::sync::Arc<AtomicBool>) {
    tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        draining.store(true, Ordering::SeqCst);
        if let Err(err) = remove_probe(READY_PROBE_PATH) {
            warn!(%err, "failed to remove readiness probe");
        }
    });
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        let ctrl_c = tokio::signal::ctrl_c();
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    _ = ctrl_c => {}
                    _ = sigterm.recv() => {}
                }
            }
            Err(err) => {
                error!(%err, "failed to register SIGTERM handler");
                if let Err(ctrl_c_err) = ctrl_c.await {
                    error!(%ctrl_c_err, "failed while waiting for Ctrl-C");
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        if let Err(err) = tokio::signal::ctrl_c().await {
            error!(%err, "failed while waiting for Ctrl-C");
        }
    }
}

fn should_exit_drain(draining: &AtomicBool, in_flight: &AtomicUsize) -> bool {
    draining.load(Ordering::SeqCst) && in_flight.load(Ordering::SeqCst) == 0
}

fn drain_timed_out(started_at: Option<tokio::time::Instant>, drain_timeout_secs: u64) -> bool {
    started_at.is_some_and(|started| started.elapsed() >= Duration::from_secs(drain_timeout_secs))
}

fn write_probe(path: &str) -> Result<(), Error> {
    std::fs::write(path, b"ok").map_err(Error::Io)
}

fn remove_probe(path: &str) -> Result<(), Error> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(Error::Io(err)),
    }
}

struct ProbeGuard;

impl Drop for ProbeGuard {
    fn drop(&mut self) {
        if let Err(err) = remove_probe(ALIVE_PROBE_PATH) {
            warn!(%err, "failed to remove liveness probe");
        }
        if let Err(err) = remove_probe(READY_PROBE_PATH) {
            warn!(%err, "failed to remove readiness probe");
        }
    }
}

async fn execute_operation(
    resolved: &dbward_core::ResolvedDatabaseConfig,
    env: dbward_core::Environment,
    operation: &str,
    detail: &str,
) -> Result<String, Error> {
    match operation {
        "execute_query" => {
            let mut engine = Engine::new(resolved, env).await?;
            let result = engine.execute_query("agent", "developer", detail).await?;
            let mut output = if result.rows.is_empty() {
                serde_json::json!({"rows_affected": result.rows_affected, "truncated": false})
            } else {
                serde_json::json!({
                    "rows": result.rows,
                    "row_count": result.rows.len(),
                    "truncated": result.truncated,
                    "truncation_reason": result.truncation_reason,
                })
            };
            if result.truncated {
                // Keep truncated/truncation_reason already set above
            }
            serde_json::to_string_pretty(&output).map_err(|e| Error::Server(e.to_string()))
        }
        "migrate_up" => {
            let engine = Engine::new(resolved, env).await?;
            let migrator = Migrator::new(engine.driver().clone(), resolved.migrations_dir.clone());
            let parsed = dbward_migrate::MigrationApprovalDetail::parse(detail)?;
            let count = Some(parsed.count);
            let count = if count == Some(0) { None } else { count };
            let r = migrator.up(count).await?;
            if r.applied.is_empty() {
                Ok("No pending migrations.".into())
            } else {
                Ok(format!(
                    "Applied {} migration(s):\n{}",
                    r.applied.len(),
                    r.applied.join("\n")
                ))
            }
        }
        "migrate_down" => {
            let engine = Engine::new(resolved, env).await?;
            let migrator = Migrator::new(engine.driver().clone(), resolved.migrations_dir.clone());
            let count = Some(dbward_migrate::MigrationApprovalDetail::parse(detail)?.count);
            let r = migrator.down(count).await?;
            if r.rolled_back.is_empty() {
                Ok("Nothing to rollback.".into())
            } else {
                Ok(format!("Rolled back:\n{}", r.rolled_back.join("\n")))
            }
        }
        "migrate_status" => {
            let engine = Engine::new(resolved, env).await?;
            let migrator = Migrator::new(engine.driver().clone(), resolved.migrations_dir.clone());
            let statuses = migrator.status().await?;
            if statuses.is_empty() {
                Ok("No migration files found.".into())
            } else {
                Ok(statuses
                    .iter()
                    .map(|s| {
                        let mark = if s.applied { "[x]" } else { "[ ]" };
                        format!("{mark} {}_{}", s.version, s.name)
                    })
                    .collect::<Vec<_>>()
                    .join("\n"))
            }
        }
        _ => Err(Error::Server(format!("unsupported operation: {operation}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dbward_core::token::{ExecutionToken, hash_detail, token_message, verify_token};
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn drain_requires_flag_and_zero_inflight() {
        let draining = AtomicBool::new(false);
        let in_flight = AtomicUsize::new(0);
        assert!(!should_exit_drain(&draining, &in_flight));

        draining.store(true, Ordering::SeqCst);
        in_flight.store(1, Ordering::SeqCst);
        assert!(!should_exit_drain(&draining, &in_flight));

        in_flight.store(0, Ordering::SeqCst);
        assert!(should_exit_drain(&draining, &in_flight));
    }

    #[test]
    fn probe_file_helpers_round_trip() {
        let path = format!("/tmp/dbward-agent-test-{}", std::process::id());
        remove_probe(&path).unwrap();
        write_probe(&path).unwrap();
        assert!(std::path::Path::new(&path).exists());
        remove_probe(&path).unwrap();
        assert!(!std::path::Path::new(&path).exists());
    }

    #[test]
    fn migrate_token_rejected_when_migration_files_change() {
        let dir = std::env::temp_dir().join(format!(
            "dbward-agent-migrate-detail-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("20260501120000_create_users.sql");
        std::fs::write(&path, "-- migrate:up\nSELECT 1;\n").unwrap();

        let approved_detail = dbward_migrate::build_migration_approval_detail(&dir, 0).unwrap();
        let detail_hash = hash_detail(&approved_detail);
        let expires_at = "2999-01-01T00:00:00+00:00".to_string();
        let message = token_message(
            "req-1",
            "migrate_up",
            "production",
            "default",
            &detail_hash,
            &expires_at,
        );
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let signature = signing_key.sign(message.as_bytes());
        let token = ExecutionToken {
            request_id: "req-1".into(),
            operation: "migrate_up".into(),
            environment: "production".into(),
            database: "default".into(),
            detail_hash,
            issued_at: "2026-01-01T00:00:00+00:00".into(),
            expires_at,
            signature: hex::encode(signature.to_bytes()),
        };

        std::fs::write(&path, "-- migrate:up\nSELECT 2;\n").unwrap();
        let current_detail =
            dbward_migrate::canonicalize_migration_approval_detail(&dir, &approved_detail).unwrap();
        let err = verify_token(
            &token,
            &signing_key.verifying_key(),
            "migrate_up",
            "production",
            "default",
            &current_detail,
        )
        .unwrap_err();

        assert!(err.to_string().contains("detail_hash mismatch"));
        std::fs::remove_dir_all(dir).ok();
    }
}
