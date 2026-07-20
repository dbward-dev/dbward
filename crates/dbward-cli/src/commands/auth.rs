use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::Cli;
use crate::error::CliError;
use crate::output::{CliResponse, OutputMode, RenderPlan, StderrLine, StdoutRender};

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct InitOutput {
    pub files_created: Vec<String>,
    pub preset: Option<String>,
}

// ---------------------------------------------------------------------------
// Command implementation
// ---------------------------------------------------------------------------

pub fn run_init(
    cli: &Cli,
    non_interactive: bool,
    force: bool,
    preset: Option<&str>,
    output_dir: &Path,
    dry_run: bool,
    mode: OutputMode,
) -> Result<CliResponse<InitOutput>, CliError> {
    // Interactive prompts are not possible in json/quiet mode
    if !non_interactive && mode != OutputMode::Human {
        return Err(CliError::Config(
            "init requires --non-interactive in json/quiet mode".into(),
        ));
    }

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

fn run_basic_init(
    cli: &Cli,
    non_interactive: bool,
    force: bool,
) -> Result<CliResponse<InitOutput>, CliError> {
    // Standalone mode: write single file (backward compat)
    if let Some(ref config_path) = cli.config {
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

        let output = InitOutput {
            files_created: vec![config_path.display().to_string()],
            preset: None,
        };
        let render = RenderPlan::status(format!("Created {}", config_path.display()));
        return Ok(CliResponse::ok(output, render));
    }

    // Auto-detect mode: global + project
    let (server_url, db_name) = prompt_inputs(non_interactive)?;
    let mut files_created = Vec::new();

    // 1. Global config
    let global_dir = crate::config::global_config_dir();
    let global_path = global_dir.join("config.toml");
    let mut stderr = Vec::new();
    if global_path.exists() && !force {
        stderr.push(StderrLine::Status(format!(
            "ℹ Using existing server config: {}",
            global_path.display()
        )));
    } else {
        std::fs::create_dir_all(&global_dir)?;
        let global_content = format!(
            r#"[server]
url = "{server_url}"
# token = "dbw_..."  # Or use [server.oidc] for OIDC
"#
        );
        std::fs::write(&global_path, global_content.trim_end())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&global_dir, std::fs::Permissions::from_mode(0o700));
            let _ = std::fs::set_permissions(&global_path, std::fs::Permissions::from_mode(0o600));
        }
        files_created.push(global_path.display().to_string());
        stderr.push(StderrLine::Status(format!("✓ Created {}", global_path.display())));
    }

    // 2. Project config
    let project_path = PathBuf::from("dbward.toml");
    if project_path.exists() && !force {
        return Err(CliError::Config(format!(
            "{} already exists. Use --force to overwrite.",
            project_path.display()
        )));
    }
    let project_content = format!(
        r#"default_database = "{db_name}"
migrations_dir = "migrations"

[databases.{db_name}]
"#
    );
    std::fs::write(&project_path, project_content.trim_end())?;
    files_created.push(project_path.display().to_string());
    stderr.push(StderrLine::Status(format!("✓ Created {}", project_path.display())));

    let output = InitOutput {
        files_created,
        preset: None,
    };
    let render = RenderPlan {
        stdout: StdoutRender::None,
        stderr,
    };
    Ok(CliResponse::ok(output, render))
}

// ---------------------------------------------------------------------------
// Preset: small-team
// ---------------------------------------------------------------------------

fn run_preset_small_team(
    non_interactive: bool,
    force: bool,
    output_dir: &Path,
    dry_run: bool,
) -> Result<CliResponse<InitOutput>, CliError> {
    let (server_url, db_name) = prompt_inputs(non_interactive)?;
    validate_db_name(&db_name)?;
    validate_server_url(&server_url)?;

    let files = generate_small_team(&server_url, &db_name);

    if dry_run {
        let mut stdout_lines = Vec::new();
        for (name, content) in &files {
            stdout_lines.push(format!("# --- {name} ---"));
            stdout_lines.push(content.clone());
        }
        let output = InitOutput {
            files_created: files.iter().map(|(n, _)| n.to_string()).collect(),
            preset: Some("small-team".into()),
        };
        let render = RenderPlan {
            stdout: StdoutRender::Raw { value: stdout_lines.join("\n") },
            stderr: vec![],
        };
        return Ok(CliResponse::ok(output, render));
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

    let output = InitOutput {
        files_created: files.iter().map(|(n, _)| n.to_string()).collect(),
        preset: Some("small-team".into()),
    };
    let render = RenderPlan {
        stdout: StdoutRender::None,
        stderr: vec![
            StderrLine::Status("✓ Created dbward.toml, server.toml, agent.toml".into()),
            StderrLine::Status(String::new()),
            StderrLine::Status("━━ Required ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".into()),
            StderrLine::Status("  agent.toml:  Set DATABASE_URL_* env vars for target databases".into()),
            StderrLine::Status("  dbward.toml: API token will be generated in step 1 below".into()),
            StderrLine::Status(String::new()),
            StderrLine::Status("━━ Next steps ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".into()),
            StderrLine::Status("  1. dbward-server --config server.toml".into()),
            StderrLine::Status("     → First run auto-creates tokens in /data/".into()),
            StderrLine::Status("  2. Set CLI token in dbward.toml: token = \"$(cat /data/admin-token)\"".into()),
            StderrLine::Status("  3. DBWARD_AGENT_TOKEN=$(cat /data/agent-token) dbward-agent --config agent.toml".into()),
            StderrLine::Status("  4. dbward doctor        # verify connectivity + config".into()),
            StderrLine::Status("  5. dbward execute \"SELECT 1\"".into()),
            StderrLine::Status(String::new()),
            StderrLine::Status("━━ Optional tuning ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".into()),
            StderrLine::Status("  server.toml: team roles, approval rules, auto-approve thresholds".into()),
            StderrLine::Status(String::new()),
            StderrLine::Hint("Docs: https://github.com/dbward-dev/dbward/blob/main/docs/getting-started.md".into()),
        ],
    };
    Ok(CliResponse::ok(output, render))
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
# token = "dbw_..."  # Set from: cat /data/admin-token (after first server start)

[databases.{db_name}]
"#
    )
}

fn gen_server_toml(db_name: &str) -> String {
    format!(
        r#"# dbward server configuration — small-team preset
state_dir = "/data"

[[databases]]
name = "{db_name}"
environments = ["development", "staging", "production"]

# Development: auto-approve all
[[workflows]]
database = "*"
environment = "development"

[workflows.auto_approve]
mode = "always"

# Staging: risk-based auto-approve + 1 approval from admin
[[workflows]]
database = "*"
environment = "staging"

[workflows.auto_approve]
mode = "risk_based"
risk = "low"

[[workflows.steps]]
type = "approval"

[[workflows.steps.approvers]]
role = "admin"
min = 1

# Production: admin approval + reason required (no auto-approve)
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

# SQL review rules (scoped per database×environment)
[[sql_review]]
database = "*"
environment = "*"
no_where_delete = "block"
no_where_update = "block"
drop_table = "warn"

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
        let resp = run_preset_small_team(true, false, dir.path(), false).unwrap();
        assert!(dir.path().join("dbward.toml").exists());
        assert!(dir.path().join("server.toml").exists());
        assert!(dir.path().join("agent.toml").exists());
        assert!(resp.data.is_some());
    }

    #[test]
    fn preset_conflict_without_force() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("server.toml"), "existing").unwrap();
        let result = run_preset_small_team(true, false, dir.path(), false);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.to_string().contains("already exists"));
    }
}
