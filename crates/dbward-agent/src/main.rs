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

    if let Err(e) = dbward_agent::run(config).await {
        eprintln!("Agent error: {e}");
        std::process::exit(1);
    }
}
