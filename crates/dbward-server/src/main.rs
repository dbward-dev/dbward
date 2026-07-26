use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "dbward-server",
    about = "dbward HTTP server",
    version,
    disable_version_flag = true
)]
struct Cli {
    /// Print version
    #[arg(short = 'v', long = "version", action = clap::ArgAction::Version)]
    version: (),

    #[command(subcommand)]
    command: Option<Command>,

    /// Listen address
    #[arg(long, default_value = "127.0.0.1:3000")]
    listen: String,

    /// Server config file path
    #[arg(long, default_value = "dbward-server.toml")]
    config: String,

    /// Force re-creation of bootstrap tokens (revokes existing)
    #[arg(long)]
    force_bootstrap: bool,

    /// License key (Team/Enterprise)
    #[arg(long, env = "DBWARD_LICENSE_KEY")]
    license_key: Option<String>,

    /// Path to license key file
    #[arg(long, env = "DBWARD_LICENSE_FILE")]
    license_file: Option<String>,

    /// Disable online license validation (offline mode).
    /// Also enabled by env DBWARD_LICENSE_OFFLINE=true.
    #[arg(long)]
    license_offline: bool,

    /// License validation API URL
    #[arg(
        long,
        env = "DBWARD_LICENSE_URL",
        default_value = "https://license.dbward.dev/v1/validate"
    )]
    license_url: String,
}

#[derive(Subcommand)]
enum Command {
    /// Send SIGHUP to a running server to reload configuration
    Reload {
        /// PID of the server process (reads from state_dir/server.pid if omitted)
        #[arg(long)]
        pid: Option<u32>,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Handle subcommands first
    if let Some(Command::Reload { pid }) = cli.command {
        if let Err(e) = run_reload(pid, &cli.config) {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
        return;
    }

    let result = dbward_server::run_from_args(
        &cli.listen,
        &cli.config,
        cli.force_bootstrap,
        cli.license_key.as_deref(),
        cli.license_file.as_deref(),
        cli.license_offline
            || std::env::var("DBWARD_LICENSE_OFFLINE").unwrap_or_default() == "true",
        &cli.license_url,
    )
    .await;

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

#[cfg(unix)]
fn run_reload(pid_arg: Option<u32>, config: &str) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Read;

    let pid = if let Some(p) = pid_arg {
        p
    } else {
        let cfg = dbward_config::server::ServerConfig::load(std::path::Path::new(config))?;
        let config_dir = std::path::Path::new(config)
            .parent()
            .unwrap_or(std::path::Path::new("."));
        let state_dir = if std::path::Path::new(&cfg.state_dir).is_absolute() {
            std::path::PathBuf::from(&cfg.state_dir)
        } else {
            config_dir.join(&cfg.state_dir)
        };
        let pid_path = state_dir.join("server.pid");
        let mut content = String::new();
        std::fs::File::open(&pid_path)
            .and_then(|mut f| f.read_to_string(&mut content))
            .map_err(|_| format!("cannot read PID file at {}. Use --pid to specify manually.", pid_path.display()))?;
        content.trim().parse::<u32>().map_err(|_| "invalid PID in pid file")?
    };

    let ret = unsafe { libc::kill(pid as libc::pid_t, libc::SIGHUP) };
    if ret == 0 {
        eprintln!("✅ Sent SIGHUP to server (PID {pid})");
        Ok(())
    } else {
        Err(format!("failed to send SIGHUP to PID {pid}: {}", std::io::Error::last_os_error()).into())
    }
}

#[cfg(not(unix))]
fn run_reload(_pid_arg: Option<u32>, _config: &str) -> Result<(), Box<dyn std::error::Error>> {
    Err("server reload via SIGHUP is only supported on Unix".into())
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
