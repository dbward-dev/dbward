use std::io::{self, BufRead, Write};
use std::path::Path;

use super::Cli;
use crate::error::CliError;

pub fn run_init(
    cli: &Cli,
    non_interactive: bool,
    force: bool,
    preset: Option<&str>,
    output_dir: &Path,
    dry_run: bool,
) -> Result<(), CliError> {
    match preset {
        Some("small-team") => run_preset_small_team(non_interactive, force, output_dir, dry_run),
        Some(other) => Err(CliError::Config(format!(
            "unknown preset '{other}'. Available: small-team"
        ))),
        None => run_basic_init(cli, non_interactive, force),
    }
}

// ---------------------------------------------------------------------------
// Basic init (existing behavior)
// ---------------------------------------------------------------------------

fn run_basic_init(cli: &Cli, non_interactive: bool, force: bool) -> Result<(), CliError> {
    let config_path = &cli.config;
    if config_path.exists() && !force {
        return Err(CliError::Config(format!(
            "{} already exists. Use --force to overwrite.",
            config_path.display()
        )));
    }

    let (server_url, db_name) = prompt_inputs(non_interactive)?;

    let content = format!(
        r#"default_database = "{db_name}"

[server]
url = "{server_url}"
# token = "dbw_..."  # Or use [server.oidc] for OIDC

[databases.{db_name}]
"#
    );

    std::fs::write(config_path, content.trim_end())?;
    eprintln!("Created {}", config_path.display());
    Ok(())
}

// ---------------------------------------------------------------------------
// Preset: small-team
// ---------------------------------------------------------------------------

fn run_preset_small_team(
    non_interactive: bool,
    force: bool,
    output_dir: &Path,
    dry_run: bool,
) -> Result<(), CliError> {
    let (server_url, db_name) = prompt_inputs(non_interactive)?;
    validate_db_name(&db_name)?;
    validate_server_url(&server_url)?;

    let files = generate_small_team(&server_url, &db_name);

    if dry_run {
        for (name, content) in &files {
            println!("# --- {name} ---");
            println!("{content}");
        }
        return Ok(());
    }

    // Ensure output dir exists before conflict check
    std::fs::create_dir_all(output_dir)?;

    // Check conflicts before writing anything
    if !force {
        for (name, _) in &files {
            let path = output_dir.join(name);
            if path.exists() {
                return Err(CliError::Config(format!(
                    "{} already exists. Use --force to overwrite.",
                    path.display()
                )));
            }
        }
    }

    // Atomic write: tmpdir on same filesystem + rename
    let tmp_dir = tempfile::tempdir_in(output_dir)
        .map_err(|e| CliError::Other(format!("failed to create temp dir: {e}")))?;
    for (name, content) in &files {
        let tmp_path = tmp_dir.path().join(name);
        std::fs::write(&tmp_path, content)?;
    }
    for (name, _) in &files {
        let src = tmp_dir.path().join(name);
        let dst = output_dir.join(name);
        std::fs::rename(&src, &dst)
            .map_err(|e| CliError::Other(format!("failed to write {}: {e}", dst.display())))?;
    }

    eprintln!("Created ({}):", output_dir.display());
    for (name, _) in &files {
        eprintln!("  {name}");
    }
    Ok(())
}

fn generate_small_team(server_url: &str, db_name: &str) -> Vec<(&'static str, String)> {
    vec![
        ("dbward.toml", gen_cli_toml(server_url, db_name)),
        ("server.toml", gen_server_toml(db_name)),
        ("agent.toml", gen_agent_toml(server_url, db_name)),
    ]
}

fn gen_cli_toml(server_url: &str, db_name: &str) -> String {
    format!(
        r#"default_database = "{db_name}"
migrations_dir = "migrations"

[server]
url = "{server_url}"
# token = "dbw_..."  # Set after running: dbward-server with --dev-bootstrap

[databases.{db_name}]
"#
    )
}

fn gen_server_toml(db_name: &str) -> String {
    format!(
        r#"# dbward server configuration — small-team preset

[[databases]]
name = "{db_name}"
environments = ["development", "staging", "production"]

# Development: no approval required
[[workflows]]
database = "*"
environment = "development"
steps = []

# Staging: 1 approval from admin
[[workflows]]
database = "*"
environment = "staging"

[[workflows.steps]]
type = "approval"

[[workflows.steps.approvers]]
role = "admin"
min = 1

# Production: admin approval + reason required
[[workflows]]
database = "*"
environment = "production"
require_reason = true

[[workflows.steps]]
type = "approval"

[[workflows.steps.approvers]]
role = "admin"
min = 1

# Execution policies
[[execution_policies]]
database = "*"
environment = "production"
statement_timeout_secs = 30
max_statement_timeout_secs = 300

# SQL review rules
[sql_review]
no_where_delete = "block"
no_where_update = "block"
drop_table = "warn"

# Auto-approve by environment
[[auto_approve]]
database = "*"
environment = "development"
risk = "high"

[[auto_approve]]
database = "*"
environment = "staging"
risk = "low"

[[auto_approve]]
database = "*"
environment = "production"
risk = "none"
"#
    )
}

fn gen_agent_toml(server_url: &str, db_name: &str) -> String {
    format!(
        r#"# dbward agent configuration — small-team preset

[server]
url = "{server_url}"
agent_token = "${{DBWARD_AGENT_TOKEN}}"

[databases.{db_name}.development]
url = "${{DATABASE_URL_DEV:-postgres://localhost:5432/{db_name}_dev}}"

[databases.{db_name}.staging]
url = "${{DATABASE_URL_STAGING}}"

[databases.{db_name}.production]
url = "${{DATABASE_URL_PRODUCTION}}"
"#
    )
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn prompt_inputs(non_interactive: bool) -> Result<(String, String), CliError> {
    let server_url = prompt("Server URL", "http://localhost:3000", non_interactive);
    let db_name = prompt("Database name", "app", non_interactive);
    Ok((server_url, db_name))
}

fn prompt(msg: &str, default: &str, non_interactive: bool) -> String {
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
}

fn validate_db_name(name: &str) -> Result<(), CliError> {
    if name.is_empty() {
        return Err(CliError::Config("database name cannot be empty".into()));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(CliError::Config(format!(
            "database name '{name}' contains invalid characters (allowed: a-z, A-Z, 0-9, _, -)"
        )));
    }
    Ok(())
}

fn validate_server_url(url: &str) -> Result<(), CliError> {
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err(CliError::Config(format!(
            "server URL must start with http:// or https://, got: {url}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_cli_toml_is_valid() {
        let content = gen_cli_toml("http://localhost:3000", "myapp");
        toml::from_str::<toml::Value>(&content).expect("invalid TOML");
    }

    #[test]
    fn generated_server_toml_is_valid() {
        let content = gen_server_toml("myapp");
        toml::from_str::<toml::Value>(&content).expect("invalid TOML");
    }

    #[test]
    fn generated_agent_toml_is_valid() {
        let content = gen_agent_toml("http://localhost:3000", "myapp");
        toml::from_str::<toml::Value>(&content).expect("invalid TOML");
    }

    #[test]
    fn validate_db_name_accepts_valid() {
        assert!(validate_db_name("app").is_ok());
        assert!(validate_db_name("my-app").is_ok());
        assert!(validate_db_name("my_app_2").is_ok());
    }

    #[test]
    fn validate_db_name_rejects_invalid() {
        assert!(validate_db_name("").is_err());
        assert!(validate_db_name("my app").is_err());
        assert!(validate_db_name("my.app").is_err());
        assert!(validate_db_name("app/db").is_err());
    }

    #[test]
    fn small_team_generates_three_files() {
        let files = generate_small_team("http://localhost:3000", "testdb");
        assert_eq!(files.len(), 3);
        assert_eq!(files[0].0, "dbward.toml");
        assert_eq!(files[1].0, "server.toml");
        assert_eq!(files[2].0, "agent.toml");
    }

    #[test]
    fn validate_server_url_accepts_valid() {
        assert!(validate_server_url("http://localhost:3000").is_ok());
        assert!(validate_server_url("https://dbward.example.com").is_ok());
    }

    #[test]
    fn validate_server_url_rejects_invalid() {
        assert!(validate_server_url("localhost:3000").is_err());
        assert!(validate_server_url("ftp://host").is_err());
    }

    #[test]
    fn preset_writes_files_to_output_dir() {
        let dir = tempfile::tempdir().unwrap();
        run_preset_small_team(true, false, dir.path(), false).unwrap();
        assert!(dir.path().join("dbward.toml").exists());
        assert!(dir.path().join("server.toml").exists());
        assert!(dir.path().join("agent.toml").exists());
    }

    #[test]
    fn preset_conflict_without_force() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("server.toml"), "existing").unwrap();
        let err = run_preset_small_team(true, false, dir.path(), false).unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }
}
