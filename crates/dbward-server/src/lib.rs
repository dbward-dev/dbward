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
pub mod webhook;

pub use metrics::Metrics;
pub use state::{AppState, RequestNotifier, ResultChannels};

use std::net::SocketAddr;

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
                    eprintln!("reclaimed {n} expired lease(s)");
                    for req in &reclaimed {
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
                Err(err) => eprintln!("failed to reclaim expired leases: {err}"),
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
                        eprintln!("purged {r} old request(s), {a} old audit log(s)");
                    }
                    Ok(_) => {}
                    Err(err) => eprintln!("failed to purge old records: {err}"),
                }
            }

            // Purge expired result storage (release mutex during I/O)
            if let Some(ref store) = purge_result_store {
                let expired = {
                    let conn = sqlite2.lock().await;
                    match db::maintenance::collect_expired_results(&conn) {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!("failed to collect expired results: {e}");
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
                    eprintln!("purged {} expired result(s)", expired.len());
                }
            }
        }
    });

    let app = routes::router(state.clone());

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(dbward_core::Error::Io)?;

    eprintln!("dbward server listening on {addr}");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(state))
        .await
        .map_err(|e| dbward_core::Error::Server(e.to_string()))?;

    eprintln!("dbward server shut down");
    Ok(())
}

async fn shutdown_signal(state: AppState) {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    _ = ctrl_c => eprintln!("\nReceived SIGINT, draining..."),
                    _ = sigterm.recv() => eprintln!("\nReceived SIGTERM, draining..."),
                }
            }
            Err(err) => {
                eprintln!("failed to register SIGTERM handler: {err}");
                if let Err(ctrl_c_err) = ctrl_c.await {
                    eprintln!("failed while waiting for Ctrl-C: {ctrl_c_err}");
                } else {
                    eprintln!("\nReceived SIGINT, draining...");
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        match ctrl_c.await {
            Ok(()) => eprintln!("\nReceived SIGINT, draining..."),
            Err(err) => eprintln!("failed while waiting for Ctrl-C: {err}"),
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
    eprintln!("Drain complete, shutting down listener...");
}
