use clap::Parser;

#[derive(Parser)]
#[command(name = "dbward-server", about = "dbward HTTP server", version)]
struct Cli {
    /// Listen address
    #[arg(long, default_value = "127.0.0.1:3000")]
    listen: String,

    /// Server config file path
    #[arg(long, default_value = "dbward-server.toml")]
    config: String,

    /// Force re-creation of bootstrap tokens (revokes existing)
    #[arg(long)]
    force_bootstrap: bool,

    /// License key (Pro/Enterprise)
    #[arg(long, env = "DBWARD_LICENSE_KEY")]
    license_key: Option<String>,

    /// Path to license key file
    #[arg(long, env = "DBWARD_LICENSE_FILE")]
    license_file: Option<String>,

    /// Disable online license validation (offline mode)
    #[arg(long, env = "DBWARD_LICENSE_OFFLINE")]
    license_offline: bool,

    /// License validation API URL
    #[arg(
        long,
        env = "DBWARD_LICENSE_URL",
        default_value = "https://license.dbward.dev/v1/validate"
    )]
    license_url: String,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result = dbward_server::run_from_args(
        &cli.listen,
        &cli.config,
        cli.force_bootstrap,
        cli.license_key.as_deref(),
        cli.license_file.as_deref(),
        cli.license_offline,
        &cli.license_url,
    )
    .await;

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn serve_mode_parses() {
        let cli = Cli::try_parse_from([
            "dbward-server",
            "--listen",
            "0.0.0.0:3000",
            "--config",
            "/config/server.toml",
        ])
        .unwrap();
        assert_eq!(cli.listen, "0.0.0.0:3000");
        assert!(!cli.force_bootstrap);
    }

    #[test]
    fn force_bootstrap_parses() {
        let cli = Cli::try_parse_from([
            "dbward-server",
            "--config",
            "/config/server.toml",
            "--force-bootstrap",
        ])
        .unwrap();
        assert!(cli.force_bootstrap);
    }
}
