use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

use crate::output::CliError;

pub async fn run_agent(config_path: &Path) -> Result<(), CliError> {
    let binary = find_agent_binary()?;
    let status = ProcessCommand::new(&binary)
        .arg("--config")
        .arg(config_path)
        .status()
        .map_err(|e| CliError::Internal(format!("failed to start agent: {e}")))?;
    if !status.success() {
        return Err(CliError::Internal(format!("agent exited with {status}")));
    }
    Ok(())
}

fn find_agent_binary() -> Result<PathBuf, CliError> {
    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe.with_file_name("dbward-agent");
        if sibling.exists() {
            return Ok(sibling);
        }
    }
    let path_var = std::env::var("PATH").unwrap_or_default();
    for dir in path_var.split(':') {
        let candidate = PathBuf::from(dir).join("dbward-agent");
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(CliError::Internal(
        "'dbward-agent' not found. Install it or place it next to the dbward binary.".into(),
    ))
}
