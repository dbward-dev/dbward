use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "dbward-agent",
    about = "dbward database execution agent",
    version,
    disable_version_flag = true
)]
struct Args {
    /// Print version
    #[arg(short = 'v', long = "version", action = clap::ArgAction::Version)]
    version: (),

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the agent
    Start {
        /// Path to agent config file
        #[arg(long, default_value = "dbward-agent.toml")]
        config: PathBuf,
    },
    /// Validate agent configuration
    Validate {
        /// Path to agent config file
        #[arg(long, default_value = "dbward-agent.toml")]
        config: PathBuf,
        /// Also check external connectivity (server reachable, token valid)
        #[arg(long)]
        preflight: bool,
    },
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    match args.command {
        Command::Start { config } => {
            run_start(&config).await;
        }
        Command::Validate { config, preflight } => {
            run_validate(&config, preflight).await;
        }
    }
}

async fn run_start(config_path: &std::path::Path) {
    dbward_agent::init_logging();

    let config = match dbward_agent::config::load_from_file(config_path) {
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

/// Validate agent configuration.
///
/// Runs static diagnostics (env vars, parse, semantic validation).
/// With --preflight, also checks external connectivity (server, token).
async fn run_validate(config_path: &std::path::Path, preflight: bool) {
    use dbward_config::validation::ValidationSeverity;

    // Read config file
    let raw_content = match std::fs::read_to_string(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[ERROR] failed to read config: {e}");
            std::process::exit(1);
        }
    };

    // Run static diagnostics
    let result = dbward_config::AgentConfig::diagnose_static(
        &raw_content,
        &config_path.display().to_string(),
    );

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
    if result.has_errors() {
        eprintln!("\nConfig invalid ({error_count} error(s), {warning_count} warning(s)).");
        if preflight {
            eprintln!("Preflight checks skipped.");
        }
        std::process::exit(1);
    }

    let mut has_preflight_error = false;

    // Runtime Preflight (--preflight only)
    if preflight {
        let cfg = result
            .config
            .as_ref()
            .expect("BUG: no errors but config is None");

        let timeout = std::time::Duration::from_secs(10);

        eprintln!("\n--- Preflight Checks ---");

        // Server health check
        match check_server_health(&cfg.server.url, timeout).await {
            Ok(version) => eprintln!("[PASS] server_reachable: v{version}"),
            Err(e) => {
                eprintln!("[FAIL] server_reachable: {e}");
                has_preflight_error = true;
            }
        }

        // Agent token check
        match check_agent_token(&cfg.server.url, &cfg.server.agent_token, timeout).await {
            Ok(()) => eprintln!("[PASS] agent_token_valid"),
            Err(e) => {
                eprintln!("[FAIL] agent_token_valid: {e}");
                has_preflight_error = true;
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

/// Check server health by calling /health endpoint.
async fn check_server_health(
    server_url: &str,
    timeout: std::time::Duration,
) -> Result<String, String> {
    let health_url = format!("{}/health", server_url.trim_end_matches('/'));

    let client = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| format!("failed to create HTTP client: {e}"))?;

    let resp = client.get(&health_url).send().await.map_err(|e| {
        if e.is_timeout() {
            "connection timed out".to_string()
        } else if e.is_connect() {
            "connection refused".to_string()
        } else {
            e.to_string()
        }
    })?;

    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("invalid response: {e}"))?;

    let version = body["version"].as_str().unwrap_or("unknown").to_string();

    Ok(version)
}

/// Check agent token validity by calling /api/public-key endpoint.
async fn check_agent_token(
    server_url: &str,
    token: &str,
    timeout: std::time::Duration,
) -> Result<(), String> {
    let url = format!("{}/api/public-key", server_url.trim_end_matches('/'));

    let client = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| format!("failed to create HTTP client: {e}"))?;

    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if resp.status().is_success() {
        Ok(())
    } else if resp.status().as_u16() == 401 {
        Err("unauthorized (invalid token)".to_string())
    } else {
        Err(format!("HTTP {}", resp.status()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn start_mode_parses() {
        let args =
            Args::try_parse_from(["dbward-agent", "start", "--config", "/config/agent.toml"])
                .unwrap();
        match args.command {
            Command::Start { config } => {
                assert_eq!(config, std::path::PathBuf::from("/config/agent.toml"));
            }
            _ => panic!("expected Start"),
        }
    }

    #[test]
    fn validate_mode_parses() {
        let args =
            Args::try_parse_from(["dbward-agent", "validate", "--config", "/config/agent.toml"])
                .unwrap();
        match args.command {
            Command::Validate {
                config,
                preflight: false,
            } => {
                assert_eq!(config, std::path::PathBuf::from("/config/agent.toml"));
            }
            _ => panic!("expected Validate"),
        }
    }

    #[test]
    fn bare_invocation_fails() {
        // After removing backward compatibility, bare invocation must fail
        let result = Args::try_parse_from(["dbward-agent"]);
        assert!(
            result.is_err(),
            "bare invocation should require a subcommand"
        );
    }
}
