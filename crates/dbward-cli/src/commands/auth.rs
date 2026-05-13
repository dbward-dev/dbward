use std::io::{self, BufRead, Write};

use super::Cli;
use crate::error::CliError;

pub fn run_init(cli: &Cli, non_interactive: bool, force: bool) -> Result<(), CliError> {
    let config_path = &cli.config;
    if config_path.exists() && !force {
        return Err(CliError::Config(format!(
            "{} already exists. Use --force to overwrite.",
            config_path.display()
        )));
    }

    let prompt = |msg: &str, default: &str| -> String {
        if non_interactive {
            return default.to_string();
        }
        eprint!("{msg} [{default}]: ");
        io::stderr().flush().ok();
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line).ok();
        let trimmed = line.trim();
        if trimmed.is_empty() {
            default.to_string()
        } else {
            trimmed.to_string()
        }
    };

    let server_url = prompt("Server URL", "http://localhost:3000");
    let db_name = prompt("Database name", "app");

    let toml_content = format!(
        r#"default_database = "{db_name}"

[server]
url = "{server_url}"
# token = "dbw_..."  # Or use [server.oidc] for OIDC

[databases.{db_name}]
"#
    );

    std::fs::write(config_path, toml_content.trim_end())?;
    eprintln!("Created {}", config_path.display());
    Ok(())
}
