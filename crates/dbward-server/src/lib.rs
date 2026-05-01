pub mod auth;
pub mod db;
mod routes;
mod state;

pub use state::AppState;

use std::net::SocketAddr;

pub async fn start(addr: SocketAddr, state: AppState) -> Result<(), dbward_core::Error> {
    let app = routes::router(state);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(dbward_core::Error::Io)?;

    eprintln!("dbward server listening on {addr}");

    axum::serve(listener, app)
        .await
        .map_err(|e| dbward_core::Error::Config(e.to_string()))?;

    Ok(())
}
