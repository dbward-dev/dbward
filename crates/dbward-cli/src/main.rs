use clap::Parser;

#[tokio::main]
async fn main() {
    let cli = dbward::commands::Cli::parse();
    if let Err(e) = dbward::commands::run(cli).await {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
