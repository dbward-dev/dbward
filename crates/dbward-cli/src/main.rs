use clap::Parser;

#[tokio::main]
async fn main() {
    let cli = dbward::commands::Cli::parse();
    if cli.allow_insecure {
        // SAFETY: called before spawning any threads (single-threaded at this point)
        unsafe { std::env::set_var("DBWARD_ALLOW_INSECURE", "true") };
    }
    if let Err(e) = dbward::commands::run(cli).await {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
