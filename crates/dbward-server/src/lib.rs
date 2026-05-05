pub mod api_error;
pub mod auth;
pub mod authz;
pub mod db;
pub mod oidc;
pub mod policy;
pub mod result_storage;
pub mod routes;
pub mod server_config;
pub mod services;
mod state;
pub mod token;
pub mod webhook;

pub use state::{AppState, RequestNotifier, ResultChannels};

use std::net::SocketAddr;

pub async fn start(addr: SocketAddr, state: AppState) -> Result<(), dbward_core::Error> {
    // Background task: reclaim expired agent leases every 60s
    let sqlite = state.sqlite.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let conn = sqlite.lock().await;
            if let Ok(n) = db::maintenance::reclaim_expired_leases(&conn)
                && n > 0
            {
                eprintln!("reclaimed {n} expired lease(s)");
            }
        }
    });

    // Background task: purge old requests and audit logs every hour
    let sqlite2 = state.sqlite.clone();
    let retention = state.retention.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            let conn = sqlite2.lock().await;
            if let Ok((r, a)) = db::maintenance::purge_old_records(
                &conn,
                retention.request_ttl_days,
                retention.audit_ttl_days,
            ) && (r > 0 || a > 0)
            {
                eprintln!("purged {r} old request(s), {a} old audit log(s)");
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
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to register SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => eprintln!("\nReceived SIGINT, draining..."),
            _ = sigterm.recv() => eprintln!("\nReceived SIGTERM, draining..."),
        }
    }
    #[cfg(not(unix))]
    {
        ctrl_c.await.ok();
        eprintln!("\nReceived SIGINT, draining...");
    }

    // Phase 1: Drain — notify waiting clients, reject new requests
    state
        .draining
        .store(true, std::sync::atomic::Ordering::SeqCst);
    state.request_notifier.notify_all().await;
    state.result_channels.notify_all().await;

    // Give time for agent result submits to arrive
    tokio::time::sleep(std::time::Duration::from_secs(20)).await;
    eprintln!("Drain complete, shutting down listener...");
}
