pub mod background;
pub mod middleware;
pub mod routes;
pub mod state;

use std::sync::atomic::Ordering;

use axum::Router;
use state::AppState;
use tokio::time::Duration;

pub fn build_app(state: AppState) -> Router {
    routes::build_router(state)
}

pub async fn start(addr: std::net::SocketAddr, state: AppState) -> Result<(), Box<dyn std::error::Error>> {
    let draining = state.draining.clone();
    let result_channel = state.result_channel.clone();

    // Startup recovery: warn about in-flight requests
    let dispatched = state.request_repo.count_by_status("dispatched").unwrap_or(0);
    let running = state.request_repo.count_by_status("running").unwrap_or(0);
    if dispatched > 0 || running > 0 {
        tracing::warn!(dispatched, running, "in-flight requests detected on startup");
    }

    // Spawn background tasks
    let bg_handle = background::spawn_background_tasks(state.clone(), draining.clone());

    let app = build_app(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "server started");

    let shutdown_fut = async move {
        wait_for_signal().await;
        tracing::info!("shutdown signal received, entering drain mode");
        draining.store(true, Ordering::SeqCst);
        result_channel.notify_all().await;
        tracing::info!("draining for 20 seconds...");
        tokio::time::sleep(Duration::from_secs(20)).await;
    };

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_fut)
        .await?;

    bg_handle.abort();
    tracing::info!("server stopped");
    Ok(())
}

async fn wait_for_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
        tokio::select! {
            _ = ctrl_c => {},
            _ = sigterm.recv() => {},
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.ok();
    }
}
