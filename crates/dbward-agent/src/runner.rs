use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use dbward_core::{AgentConfig, Engine, Error};
use dbward_migrate::Migrator;

use crate::server_client::AgentClient;

const ALIVE_PROBE_PATH: &str = "/tmp/dbward-agent-alive";
const READY_PROBE_PATH: &str = "/tmp/dbward-agent-ready";

/// Run the agent poll loop. Blocks until interrupted.
pub async fn run(config: AgentConfig) -> Result<(), Error> {
    let client = AgentClient::new(&config.server.url, &config.server.agent_token);
    let poll_interval = Duration::from_millis(config.poll_interval_ms);
    let draining = std::sync::Arc::new(AtomicBool::new(false));
    let in_flight = std::sync::Arc::new(AtomicUsize::new(0));

    // Fetch server's public key for token verification
    let public_key = client.get_public_key().await?;
    write_probe(ALIVE_PROBE_PATH)?;
    write_probe(READY_PROBE_PATH)?;
    let _probe_guard = ProbeGuard;
    eprintln!(
        "agent {} started, polling {}",
        config.agent_id, config.server.url
    );

    install_shutdown_task(draining.clone());
    let mut drain_started_at = None;

    loop {
        if draining.load(Ordering::SeqCst) {
            if drain_started_at.is_none() {
                drain_started_at = Some(tokio::time::Instant::now());
                if let Err(err) = remove_probe(READY_PROBE_PATH) {
                    eprintln!("failed to remove readiness probe: {err}");
                }
                eprintln!("agent draining");
            }
            if should_exit_drain(&draining, &in_flight) {
                eprintln!("agent shut down");
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

        poll_once(&config, &client, &public_key, &in_flight).await;
        tokio::time::sleep(poll_interval).await;
    }
}

async fn poll_once(
    config: &AgentConfig,
    client: &AgentClient,
    public_key: &ed25519_dalek::VerifyingKey,
    in_flight: &AtomicUsize,
) {
    let jobs = match client
        .poll(
            &config.capabilities.databases,
            &config.capabilities.environments,
            &config.capabilities.operations,
        )
        .await
    {
        Ok(j) => j,
        Err(e) => {
            eprintln!("poll failed: {e}");
            return;
        }
    };

    for job in jobs {
        let request_id = match job["id"].as_str() {
            Some(id) => id.to_string(),
            None => continue,
        };

        in_flight.fetch_add(1, Ordering::SeqCst);
        if let Err(e) = execute_job(config, client, public_key, &request_id, &job).await {
            eprintln!("job {request_id} failed: {e}");
        }
        in_flight.fetch_sub(1, Ordering::SeqCst);
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

    eprintln!("claimed job {request_id} ({operation} on {database})");

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

    // Heartbeat task: extend lease while executing
    let heartbeat_interval = std::time::Duration::from_secs(config.lease_duration_secs / 3);
    let hb_client = client.clone();
    let hb_exec_id = exec_id.to_string();
    let hb_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(heartbeat_interval);
        interval.tick().await; // skip immediate first tick
        loop {
            interval.tick().await;
            if let Err(e) = hb_client.heartbeat(&hb_exec_id).await {
                eprintln!("heartbeat failed: {e}");
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
            eprintln!("job {request_id} execution failed: {msg}");
            hb_handle.abort();
            send_result_with_retry(client, exec_id, false, None, Some(&msg)).await;
            return Ok(());
        }
    };

    hb_handle.abort();
    eprintln!("job {request_id} execution completed");
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
                    eprintln!("result submit failed after retries: {e}");
                    return;
                }
                eprintln!("result submit failed, retrying in {backoff:?}: {e}");
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
            eprintln!("failed to remove readiness probe: {err}");
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
                eprintln!("failed to register SIGTERM handler: {err}");
                if let Err(ctrl_c_err) = ctrl_c.await {
                    eprintln!("failed while waiting for Ctrl-C: {ctrl_c_err}");
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        if let Err(err) = tokio::signal::ctrl_c().await {
            eprintln!("failed while waiting for Ctrl-C: {err}");
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
            eprintln!("failed to remove liveness probe: {err}");
        }
        if let Err(err) = remove_probe(READY_PROBE_PATH) {
            eprintln!("failed to remove readiness probe: {err}");
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
                serde_json::json!({"rows_affected": result.rows_affected})
            } else {
                serde_json::json!({"rows": result.rows, "row_count": result.rows.len()})
            };
            if result.truncated {
                output["truncated"] = serde_json::json!(true);
                output["truncation_reason"] = serde_json::json!(result.truncation_reason);
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
