mod runner;
mod server_client;

pub use runner::run;

/// Initialize structured logging for the agent.
/// Set `RUST_LOG` for level filter (default: info).
/// Set `DBWARD_LOG_FORMAT=json` for JSON output (default: compact human-readable).
pub fn init_logging() {
    use tracing_subscriber::{fmt, EnvFilter};

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let json = std::env::var("DBWARD_LOG_FORMAT")
        .map(|v| v == "json")
        .unwrap_or(false);

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
}
