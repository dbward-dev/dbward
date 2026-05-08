pub(crate) mod api_error;
pub mod auth;
pub(crate) mod authz;
pub(crate) mod constants;
pub mod db;
pub mod license;
pub mod limits;
pub mod metrics;
pub mod oidc;
pub mod result_storage;
pub mod routes;
pub mod server_config;
pub(crate) mod services;
mod state;
pub mod token;
pub mod update_checker;
pub mod webhook;

pub use metrics::Metrics;
pub use state::{AppState, RequestNotifier, ResultChannels};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const API_VERSION: u32 = 1;

use std::net::SocketAddr;
use tracing::{error, info};

/// Initialize structured logging. Call once before `start()`.
/// Set `RUST_LOG` for level filter (default: info).
/// Set `DBWARD_LOG_FORMAT=json` for JSON output (default: compact human-readable).
pub fn init_logging(config: &server_config::LoggingConfig) -> Option<tracing_appender::non_blocking::WorkerGuard> {
    use tracing_subscriber::{fmt, EnvFilter};

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let json = std::env::var("DBWARD_LOG_FORMAT")
        .map(|v| v == "json")
        .unwrap_or(false);

    match config.output.as_str() {
        "file" => {
            let path = config.file_path.as_deref().unwrap_or("/var/log/dbward/server.log");
            let dir = std::path::Path::new(path).parent().unwrap_or(std::path::Path::new("."));
            let file_name = std::path::Path::new(path)
                .file_name()
                .and_then(|f| f.to_str())
                .unwrap_or("server.log");

            if let Err(e) = std::fs::create_dir_all(dir) {
                eprintln!("FATAL: cannot create log directory {}: {e}. Falling back to stderr.", dir.display());
                if json {
                    fmt()
                        .json()
                        .with_env_filter(filter)
                        .with_target(true)
                        .with_writer(std::io::stderr)
                        .init();
                } else {
                    fmt()
                        .compact()
                        .with_env_filter(filter)
                        .with_target(false)
                        .with_writer(std::io::stderr)
                        .init();
                }
                return None;
            }

            let appender = match config.rotation.as_str() {
                "hourly" => tracing_appender::rolling::hourly(dir, file_name),
                "never" => tracing_appender::rolling::never(dir, file_name),
                _ => tracing_appender::rolling::daily(dir, file_name),
            };
            let (writer, guard) = tracing_appender::non_blocking(appender);
            if json {
                fmt()
                    .json()
                    .with_env_filter(filter)
                    .with_target(true)
                    .with_writer(writer)
                    .init();
            } else {
                fmt()
                    .compact()
                    .with_env_filter(filter)
                    .with_target(false)
                    .with_writer(writer)
                    .init();
            }
            Some(guard)
        }
        _ => {
            if json {
                fmt()
                    .json()
                    .with_env_filter(filter)
                    .with_target(true)
                    .with_writer(std::io::stderr)
                    .init();
            } else {
                fmt()
                    .compact()
                    .with_env_filter(filter)
                    .with_target(false)
                    .with_writer(std::io::stderr)
                    .init();
            }
            None
        }
    }
}

pub async fn start(addr: SocketAddr, state: AppState) -> Result<(), dbward_core::Error> {
    authz::warmup().await.map_err(|(_, message)| {
        dbward_core::Error::Server(format!("authorization init failed: {message}"))
    })?;

    // Background task: reclaim expired agent leases every 60s
    let sqlite = state.sqlite.clone();
    let metrics = state.metrics.clone();
    let webhooks = state.webhooks.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(
            constants::LEASE_RECLAIM_INTERVAL_SECS,
        ));
        loop {
            interval.tick().await;
            let conn = sqlite.lock().await;
            match db::maintenance::reclaim_expired_leases(&conn) {
                Ok(reclaimed) if !reclaimed.is_empty() => {
                    let n = reclaimed.len();
                    metrics.record_agent_lease_expirations(n as u64);
                    info!(count = n, "reclaimed expired leases");
                    drop(conn);
                    let mut conn = sqlite.lock().await;
                    for req in &reclaimed {
                        let _ = db::audit_event_repo::insert_audit_event(
                            &mut conn,
                            &db::audit_event_repo::AuditEvent {
                                event_type: "execution_lost",
                                event_category: "agent",
                                outcome: "failure",
                                actor_id: "system",
                                actor_type: "system",
                                resource_type: Some("request"),
                                resource_id: Some(&req.id),
                                peer_ip: None,
                                client_ip: None,
                                client_ip_source: None,
                                request_id: Some(&req.id),
                                operation: Some(&req.operation),
                                environment: Some(&req.environment),
                                database_name: Some(&req.database),
                                detail_fingerprint: None,
                                detail_raw: None,
                                reason: Some("agent lease expired"),
                                metadata_json: "{}",
                            },
                        );
                        webhooks.read().unwrap().dispatch(webhook::WebhookEvent {
                            event: "request.execution_lost".into(),
                            timestamp: chrono::Utc::now().to_rfc3339(),
                            request_id: req.id.clone(),
                            status: "execution_lost".into(),
                            requester: req.requester.clone(),
                            actor: "system".into(),
                            actor_role: None,
                            operation: req.operation.clone(),
                            environment: req.environment.clone(),
                            database: req.database.clone(),
                            detail: req.detail.clone(),
                            reason: Some("agent lease expired".into()),
                            next_step: None,
                            cli_command: Some(format!("dbward request resume {}", req.id)),
                        });
                    }
                }
                Ok(_) => {}
                Err(err) => error!(error = %err, "failed to reclaim expired leases"),
            }
        }
    });

    // Background task: purge old requests and audit logs every hour
    let sqlite2 = state.sqlite.clone();
    let retention = state.retention.clone();
    let purge_result_store = state.result_store.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(
            constants::RECORD_PURGE_INTERVAL_SECS,
        ));
        loop {
            interval.tick().await;
            {
                let conn = sqlite2.lock().await;
                match db::maintenance::purge_old_records(
                    &conn,
                    retention.request_ttl_days,
                    retention.audit_ttl_days,
                ) {
                    Ok((r, a)) if r > 0 || a > 0 => {
                        info!(requests = r, audit_logs = a, "purged old records");
                    }
                    Ok(_) => {}
                    Err(err) => error!(error = %err, "failed to purge old records"),
                }
            }

            // Purge expired result storage (release mutex during I/O)
            if let Some(ref store) = purge_result_store {
                let expired = {
                    let conn = sqlite2.lock().await;
                    match db::maintenance::collect_expired_results(&conn) {
                        Ok(v) => v,
                        Err(e) => {
                            error!(error = %e, "failed to collect expired results");
                            vec![]
                        }
                    }
                };
                if !expired.is_empty() {
                    for (request_id, _) in &expired {
                        let _ = store.delete(request_id).await;
                    }
                    let conn = sqlite2.lock().await;
                    for (request_id, _) in &expired {
                        let _ =
                            db::maintenance::delete_expired_result_records(&conn, request_id);
                    }
                    info!(count = expired.len(), "purged expired results");
                }
            }

            // WAL checkpoint + revoked token cleanup
            {
                let conn = sqlite2.lock().await;
                let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)");
                if let Ok(n) = db::maintenance::purge_revoked_tokens(&conn, 90) {
                    if n > 0 {
                        info!(count = n, "purged old revoked tokens");
                    }
                }
            }
        }
    });

    // Background task: check for updates
    update_checker::spawn_update_checker(
        state.update_check_enabled,
        state.update_available.clone(),
    );

    let app = routes::router(state.clone());

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(dbward_core::Error::Io)?;

    info!(addr = %addr, "dbward server listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(state))
        .await
        .map_err(|e| dbward_core::Error::Server(e.to_string()))?;

    info!("dbward server shut down");
    Ok(())
}

async fn shutdown_signal(state: AppState) {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    _ = ctrl_c => info!("received SIGINT, draining..."),
                    _ = sigterm.recv() => info!("received SIGTERM, draining..."),
                }
            }
            Err(err) => {
                error!(error = %err, "failed to register SIGTERM handler");
                if let Err(ctrl_c_err) = ctrl_c.await {
                    error!(error = %ctrl_c_err, "failed while waiting for Ctrl-C");
                } else {
                    info!("received SIGINT, draining...");
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        match ctrl_c.await {
            Ok(()) => info!("received SIGINT, draining..."),
            Err(err) => error!(error = %err, "failed while waiting for Ctrl-C"),
        }
    }

    // Phase 1: Drain — notify waiting clients, reject new requests
    state
        .draining
        .store(true, std::sync::atomic::Ordering::SeqCst);
    state.request_notifier.notify_all().await;
    state.result_channels.notify_all().await;

    // Give time for agent result submits to arrive
    tokio::time::sleep(std::time::Duration::from_secs(
        constants::SHUTDOWN_DRAIN_SECS,
    ))
    .await;
    info!("drain complete, shutting down listener...");
}
