mod cli;
mod config_loader;
mod mcp;
mod server_client;

use std::process;

use clap::Parser;

use cli::Cli;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(e) = cli::run(cli).await {
        eprintln!("error: {e}");
        process::exit(1);
    }
}
