use std::process;

use clap::Parser;

use dbward::cli::{self, Cli};

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(e) = cli::run(cli).await {
        eprintln!("{e}");
        process::exit(1);
    }
}
