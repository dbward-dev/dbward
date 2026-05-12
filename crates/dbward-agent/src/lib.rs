mod cancel;
mod client;
pub mod config;
mod error;
mod executor;
mod probes;
mod runner;

pub use config::AgentConfig;
pub use error::AgentError;
pub use runner::run;

use tracing_subscriber::{EnvFilter, fmt, prelude::*};

pub fn init_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let json = std::env::var("DBWARD_LOG_FORMAT")
        .map(|v| v == "json")
        .unwrap_or(false);

    if json {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().json())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().compact())
            .init();
    }
}
