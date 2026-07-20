use std::path::PathBuf;
use std::process::Command as ProcessCommand;

use clap::Subcommand;
use serde::Serialize;

use crate::output::CliError;
use crate::output::{CliResponse, RenderPlan};

#[derive(Subcommand)]
pub enum ServerAction {
    Start {
        #[arg(long, default_value = "127.0.0.1:3000")]
        listen: String,
        #[arg(long, default_value = "dbward-server.toml")]
        config: String,
    },
    /// Send SIGHUP to a running server to reload config
    Reload {
        /// PID of the server process (reads from state_dir/server.pid if omitted)
        #[arg(long)]
        pid: Option<u32>,
        /// Path to the server config (to find state_dir/server.pid)
        #[arg(long = "server-config", default_value = "dbward-server.toml")]
        server_config: String,
    },
}

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct ServerReloadOutput {
    pub pid: u32,
    pub signal: String,
}

// ---------------------------------------------------------------------------
// Command implementation
// ---------------------------------------------------------------------------

pub async fn run_server_command(
    action: &ServerAction,
) -> Result<CliResponse<ServerReloadOutput>, CliError> {
    match action {
        ServerAction::Start { listen, config } => run_server_start(listen, config).await,
        ServerAction::Reload { pid, server_config } => run_server_reload(*pid, server_config),
    }
}

async fn run_server_start(
    listen: &str,
    config: &str,
) -> Result<CliResponse<ServerReloadOutput>, CliError> {
    let binary = find_server_binary()?;
    let status = ProcessCommand::new(&binary)
        .arg("--listen")
        .arg(listen)
        .arg("--config")
        .arg(config)
        .status()
        .map_err(|e| CliError::Internal(format!("failed to start server: {e}")))?;
    if !status.success() {
        return Err(CliError::Internal(format!("server exited with {status}")));
    }
    // Server start is a long-running process; this only returns if it exits cleanly
    let render = RenderPlan::status("Server exited.");
    Ok(CliResponse::empty(render))
}

fn find_server_binary() -> Result<PathBuf, CliError> {
    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe.with_file_name("dbward-server");
        if sibling.exists() {
            return Ok(sibling);
        }
    }
    which_binary("dbward-server")
}

fn run_server_reload(
    pid_arg: Option<u32>,
    config: &str,
) -> Result<CliResponse<ServerReloadOutput>, CliError> {
    #[cfg(unix)]
    {
        use std::io::Read;

        let pid = if let Some(p) = pid_arg {
            p
        } else {
            // Try to read from state_dir/server.pid
            let cfg = dbward_config::server::ServerConfig::load(std::path::Path::new(config))
                .map_err(|e| CliError::Config(e.to_string()))?;
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
                    CliError::Internal(format!(
                        "cannot read PID file at {}. Use --pid to specify manually.",
                        pid_path.display()
                    ))
                })?;
            content
                .trim()
                .parse::<u32>()
                .map_err(|_| CliError::Internal("invalid PID in pid file".into()))?
        };

        // Send SIGHUP
        let ret = unsafe { libc::kill(pid as libc::pid_t, libc::SIGHUP) };
        if ret == 0 {
            let output = ServerReloadOutput {
                pid,
                signal: "SIGHUP".into(),
            };
            let render = RenderPlan::status(format!("✅ Sent SIGHUP to server (PID {pid})"));
            Ok(CliResponse::ok(output, render))
        } else {
            Err(CliError::Internal(format!(
                "failed to send SIGHUP to PID {pid}: {}",
                std::io::Error::last_os_error()
            )))
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (pid_arg, config);
        Err(CliError::Internal(
            "server reload via SIGHUP is only supported on Unix".into(),
        ))
    }
}

fn which_binary(name: &str) -> Result<PathBuf, CliError> {
    let path_var = std::env::var("PATH").unwrap_or_default();
    for dir in path_var.split(':') {
        let candidate = PathBuf::from(dir).join(name);
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(CliError::Internal(format!(
        "'{name}' not found. Install it or place it next to the dbward binary."
    )))
}
