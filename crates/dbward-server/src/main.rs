use clap::Parser;

#[derive(Parser)]
#[command(name = "dbward-server", about = "dbward HTTP server")]
struct Args {
    /// Listen address
    #[arg(long, default_value = "127.0.0.1:3000")]
    listen: String,

    /// SQLite database path
    #[arg(long, default_value = "dbward.db")]
    data: String,

    /// Server config file path
    #[arg(long, default_value = "dbward-server.toml")]
    config: String,

    /// Dev bootstrap mode: output tokens as JSON to stdout then start
    #[arg(long, hide = true)]
    dev_bootstrap: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    if let Err(e) = dbward_server::run_from_args(
        &args.listen,
        &args.data,
        &args.config,
        args.dev_bootstrap,
    ).await {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
