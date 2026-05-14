use std::path::PathBuf;
use std::process::Command as ProcessCommand;

use clap::Subcommand;

use crate::error::CliError;

#[derive(Subcommand)]
pub enum ServerAction {
    Start {
        #[arg(long, default_value = "127.0.0.1:3000")]
        listen: String,
        #[arg(long, default_value = "dbward.db")]
        data: String,
        #[arg(long, default_value = "dbward-server.toml")]
        config: String,
    },
    Token {
        #[command(subcommand)]
        action: TokenAction,
    },
}

#[derive(Subcommand)]
pub enum TokenAction {
    Create {
        #[arg(long)]
        user: String,
        #[arg(long, value_parser = parse_role)]
        role: String,
        #[arg(long)]
        agent: bool,
        #[arg(long, value_delimiter = ',')]
        groups: Vec<String>,
        #[arg(long, default_value = "dbward.db")]
        data: String,
    },
    Revoke {
        #[arg(long)]
        id: String,
        #[arg(long, default_value = "dbward.db")]
        data: String,
    },
}

fn parse_role(s: &str) -> Result<String, String> {
    if s.is_empty() {
        Err("role cannot be empty".into())
    } else {
        Ok(s.to_string())
    }
}

pub async fn run_server_command(action: &ServerAction) -> Result<(), CliError> {
    match action {
        ServerAction::Start {
            listen,
            data,
            config,
        } => run_server_start(listen, data, config).await,
        ServerAction::Token { action } => run_token_command(action).await,
    }
}

async fn run_server_start(listen: &str, data: &str, config: &str) -> Result<(), CliError> {
    let binary = find_server_binary()?;
    let status = ProcessCommand::new(&binary)
        .arg("--listen")
        .arg(listen)
        .arg("--data")
        .arg(data)
        .arg("--config")
        .arg(config)
        .status()
        .map_err(|e| CliError::Server(format!("failed to start server: {e}")))?;
    if !status.success() {
        return Err(CliError::Server(format!("server exited with {status}")));
    }
    Ok(())
}

async fn run_token_command(action: &TokenAction) -> Result<(), CliError> {
    let binary = find_server_binary()?;
    let status = match action {
        TokenAction::Create {
            user,
            role,
            agent,
            groups,
            data,
        } => {
            let mut cmd = ProcessCommand::new(&binary);
            cmd.arg("--data")
                .arg(data)
                .arg("token")
                .arg("create")
                .arg("--user")
                .arg(user)
                .arg("--role")
                .arg(role);
            if *agent {
                cmd.arg("--agent");
            }
            if !groups.is_empty() {
                cmd.arg("--groups").arg(groups.join(","));
            }
            cmd.status()
        }
        TokenAction::Revoke { id, data } => ProcessCommand::new(&binary)
            .arg("--data")
            .arg(data)
            .arg("token")
            .arg("revoke")
            .arg("--id")
            .arg(id)
            .status(),
    };
    let status =
        status.map_err(|e| CliError::Server(format!("failed to run server binary: {e}")))?;
    if !status.success() {
        return Err(CliError::Server(format!(
            "server command exited with {status}"
        )));
    }
    Ok(())
}

fn find_server_binary() -> Result<PathBuf, CliError> {
    // Look for dbward-server next to current binary first
    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe.with_file_name("dbward-server");
        if sibling.exists() {
            return Ok(sibling);
        }
    }
    // Fall back to PATH
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_role_valid() {
        assert_eq!(parse_role("admin").unwrap(), "admin");
        assert_eq!(parse_role("developer").unwrap(), "developer");
    }

    #[test]
    fn parse_role_invalid() {
        assert!(parse_role("").is_err());
    }
}
