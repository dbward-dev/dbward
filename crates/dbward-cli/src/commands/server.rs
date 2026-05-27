use std::path::PathBuf;
use std::process::Command as ProcessCommand;

use clap::Subcommand;

use crate::error::CliError;

#[derive(Subcommand)]
pub enum ServerAction {
    Start {
        #[arg(long, default_value = "127.0.0.1:3000")]
        listen: String,
        #[arg(long, default_value = "dbward-server.toml")]
        config: String,
    },
}

pub async fn run_server_command(action: &ServerAction) -> Result<(), CliError> {
    match action {
        ServerAction::Start { listen, config } => run_server_start(listen, config).await,
    }
}

async fn run_server_start(listen: &str, config: &str) -> Result<(), CliError> {
    let binary = find_server_binary()?;
    let status = ProcessCommand::new(&binary)
        .arg("--listen")
        .arg(listen)
        .arg("--config")
        .arg(config)
        .status()
        .map_err(|e| CliError::Server(format!("failed to start server: {e}")))?;
    if !status.success() {
        return Err(CliError::Server(format!("server exited with {status}")));
    }
    Ok(())
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

fn which_binary(name: &str) -> Result<PathBuf, CliError> {
    let path_var = std::env::var("PATH").unwrap_or_default();
    for dir in path_var.split(':') {
        let candidate = PathBuf::from(dir).join(name);
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(CliError::Server(format!(
        "'{name}' not found. Install it or place it next to the dbward binary."
    )))
}
