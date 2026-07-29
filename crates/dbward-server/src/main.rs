use clap::{Parser, Subcommand};
use std::path::PathBuf;

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
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the server
    Start {
        /// Server config file path
        #[arg(long, default_value = "dbward-server.toml")]
        config: String,
        /// Listen address
        #[arg(long, default_value = "127.0.0.1:3000")]
        listen: String,
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
    },
    /// Validate server configuration
    Validate {
        /// Path to server config file
        #[arg(long, default_value = "dbward-server.toml")]
        config: PathBuf,
        /// Also check external connectivity (OIDC issuer, Slack API)
        #[arg(long)]
        preflight: bool,
    },
    /// Send SIGHUP to a running server to reload configuration
    Reload {
        /// Path to server config file (used to locate state_dir/server.pid)
        #[arg(long, default_value = "dbward-server.toml")]
        config: String,
        /// PID of the server process (overrides PID file lookup)
        #[arg(long)]
        pid: Option<u32>,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Start {
            config,
            listen,
            force_bootstrap,
            license_key,
            license_file,
            license_offline,
            license_url,
        } => {
            let result = dbward_server::run_from_args(
                &listen,
                &config,
                force_bootstrap,
                license_key.as_deref(),
                license_file.as_deref(),
                license_offline
                    || std::env::var("DBWARD_LICENSE_OFFLINE").unwrap_or_default() == "true",
                &license_url,
            )
            .await;

            if let Err(e) = result {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Command::Validate { config, preflight } => {
            run_validate(&config, preflight).await;
        }
        Command::Reload { config, pid } => {
            if let Err(e) = run_reload(pid, &config) {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
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
            .map_err(|_| {
                format!(
                    "cannot read PID file at {}. Use --pid to specify manually.",
                    pid_path.display()
                )
            })?;
        content
            .trim()
            .parse::<u32>()
            .map_err(|_| "invalid PID in pid file")?
    };

    let ret = unsafe { libc::kill(pid as libc::pid_t, libc::SIGHUP) };
    if ret == 0 {
        eprintln!("✅ Sent SIGHUP to server (PID {pid})");
        Ok(())
    } else {
        Err(format!(
            "failed to send SIGHUP to PID {pid}: {}",
            std::io::Error::last_os_error()
        )
        .into())
    }
}

#[cfg(not(unix))]
fn run_reload(_pid_arg: Option<u32>, _config: &str) -> Result<(), Box<dyn std::error::Error>> {
    Err("server reload via SIGHUP is only supported on Unix".into())
}

/// Validate server configuration.
///
/// Runs static diagnostics (env vars, parse, semantic validation).
/// With --preflight, also checks external connectivity (OIDC, Slack).
async fn run_validate(config_path: &std::path::Path, preflight: bool) {
    use dbward_app::config_diagnostics::diagnose_server_config;
    use dbward_config::validation::ValidationSeverity;

    // Read config file
    let raw_content = match std::fs::read_to_string(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[ERROR] failed to read config: {e}");
            std::process::exit(1);
        }
    };

    // Run full diagnostics (config-level + domain-level)
    let result = diagnose_server_config(&raw_content, &config_path.display().to_string());

    // Display issues
    let mut error_count = 0;
    let mut warning_count = 0;
    for issue in &result.issues {
        let prefix = match issue.severity {
            ValidationSeverity::Error => {
                error_count += 1;
                "[ERROR]"
            }
            ValidationSeverity::Warning => {
                warning_count += 1;
                "[WARN]"
            }
        };
        eprintln!("{} {}: {}", prefix, issue.id, issue.message);
        if let Some(hint) = &issue.hint {
            eprintln!("        hint: {hint}");
        }
    }

    // Exit if static errors
    if error_count > 0 {
        eprintln!("\nConfig invalid ({error_count} error(s), {warning_count} warning(s)).");
        if preflight {
            eprintln!("Preflight checks skipped.");
        }
        std::process::exit(1);
    }

    let mut has_preflight_error = false;

    // Runtime Preflight (--preflight only)
    if preflight {
        // Note: has_errors() == false implies config.is_some()
        let cfg = result
            .config
            .as_ref()
            .expect("BUG: no errors but config is None");

        eprintln!("\n--- Preflight Checks ---");

        // OIDC issuer check
        if let Some(ref oidc) = cfg.auth.oidc {
            match check_oidc_issuer(&oidc.issuer_url).await {
                Ok(()) => eprintln!("[PASS] oidc_issuer: reachable"),
                Err(e) => {
                    eprintln!("[FAIL] oidc_issuer: {e}");
                    has_preflight_error = true;
                }
            }
        }

        // Slack check
        if let Some(ref slack) = cfg.slack {
            match check_slack(slack).await {
                Ok(msg) => eprintln!("[PASS] slack: {msg}"),
                Err(e) => {
                    eprintln!("[FAIL] slack: {e}");
                    has_preflight_error = true;
                }
            }
        }
    }

    // Final message and exit code
    if has_preflight_error {
        eprintln!("\nConfig valid, but preflight checks failed.");
        std::process::exit(1);
    } else if error_count == 0 && warning_count == 0 {
        if preflight {
            eprintln!("\nConfig valid, all preflight checks passed.");
        } else {
            eprintln!("Config valid.");
        }
    } else {
        eprintln!("\nConfig valid with {warning_count} warning(s).");
    }
    std::process::exit(0);
}

/// Check OIDC issuer connectivity.
async fn check_oidc_issuer(issuer_url: &str) -> Result<(), String> {
    let well_known = format!(
        "{}/.well-known/openid-configuration",
        issuer_url.trim_end_matches('/')
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("failed to create HTTP client: {e}"))?;

    let resp = client
        .get(&well_known)
        .send()
        .await
        .map_err(|e| format!("connection failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("HTTP {} from {}", resp.status(), well_known));
    }

    // Verify it's valid JSON with expected fields
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("invalid JSON response: {e}"))?;

    if body.get("issuer").is_none() {
        return Err("response missing 'issuer' field".to_string());
    }

    Ok(())
}

/// Check Slack connectivity (auth.test API).
async fn check_slack(slack: &dbward_config::server::SlackConfig) -> Result<String, String> {
    // Validate token format first
    if !slack.bot_token.starts_with("xoxb-") || slack.bot_token.len() < 10 {
        return Err("invalid bot_token format (expected xoxb-...)".to_string());
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("failed to create HTTP client: {e}"))?;

    let resp = client
        .post("https://slack.com/api/auth.test")
        .bearer_auth(&slack.bot_token)
        .send()
        .await
        .map_err(|e| format!("connection failed: {e}"))?;

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("invalid response: {e}"))?;

    if body["ok"].as_bool() != Some(true) {
        let error = body["error"].as_str().unwrap_or("unknown");
        return Err(format!("Slack API error: {error}"));
    }

    let team = body["team"].as_str().unwrap_or("?");
    let bot = body["user"].as_str().unwrap_or("?");
    Ok(format!("team={team}, bot={bot}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn serve_mode_parses() {
        let cli = Cli::try_parse_from([
            "dbward-server",
            "start",
            "--listen",
            "0.0.0.0:3000",
            "--config",
            "/config/server.toml",
        ])
        .unwrap();
        match cli.command {
            Command::Start { listen, force_bootstrap, .. } => {
                assert_eq!(listen, "0.0.0.0:3000");
                assert!(!force_bootstrap);
            }
            _ => panic!("expected Start"),
        }
    }

    #[test]
    fn force_bootstrap_parses() {
        let cli = Cli::try_parse_from([
            "dbward-server",
            "start",
            "--config",
            "/config/server.toml",
            "--force-bootstrap",
        ])
        .unwrap();
        match cli.command {
            Command::Start { force_bootstrap, .. } => {
                assert!(force_bootstrap);
            }
            _ => panic!("expected Start"),
        }
    }
}
