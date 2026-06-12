use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "dbward-agent", about = "dbward database execution agent")]
struct Args {
    /// Path to agent config file
    #[arg(long, default_value = "dbward-agent.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    dbward_agent::init_logging();

    let config = match dbward_agent::config::load_from_file(&args.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error loading config: {e}");
            std::process::exit(1);
        }
    };

    // TLS transport security check (env > config priority)
    let allow_insecure = if let Ok(v) = std::env::var("DBWARD_ALLOW_INSECURE") {
        v == "true" || v == "1"
    } else {
        config.server.allow_insecure.unwrap_or(false)
    };

    if let Err(e) = dbward_config::transport::check_transport_security(
        &config.server.url,
        allow_insecure,
        false,
    ) {
        eprintln!("fatal: {e}");
        std::process::exit(1);
    }
    if allow_insecure && !dbward_config::transport::is_local_or_internal(&config.server.url) {
        tracing::warn!(
            url = %config.server.url,
            "insecure HTTP transport explicitly allowed"
        );
    }

    if let Err(e) = dbward_agent::run(config).await {
        eprintln!("Agent error: {e}");
        std::process::exit(1);
    }
}
