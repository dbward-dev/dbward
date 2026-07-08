use std::path::PathBuf;
use std::process::{Command as ProcessCommand, Stdio};

use crate::error::CliError;

pub async fn run_dev(database_url: &str, port: u16) -> Result<(), CliError> {
    let dev_dir = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".dbward")
        .join("dev");
    std::fs::create_dir_all(&dev_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dev_dir, std::fs::Permissions::from_mode(0o700));
    }

    let server_binary = find_binary("dbward-server")?;
    let agent_binary = find_binary("dbward-agent")?;

    let results_dir = dev_dir.join("results");
    std::fs::create_dir_all(&results_dir)?;

    // Write server config
    let server_config_path = dev_dir.join("server.toml");
    let server_config = format!(
        r#"state_dir = "{state_dir}"

[auth]
default_role = "developer"

[result_storage]
backend = "local"
root_dir = "{results}"

[[databases]]
name = "app"
environments = ["development"]

[[workflows]]
database = "*"
environment = "*"

[workflows.auto_approve]
mode = "always"
"#,
        state_dir = dev_dir.display(),
        results = results_dir.display()
    );
    std::fs::write(&server_config_path, &server_config)?;

    let listen = format!("127.0.0.1:{port}");
    let server_url = format!("http://{listen}");

    eprintln!("dbward dev starting...");
    eprintln!("  Server: {server_url}");
    eprintln!("  Database: {database_url}");
    eprintln!();

    // Spawn server (auto-initializes on first run)
    let mut server_child = ProcessCommand::new(&server_binary)
        .arg("--listen")
        .arg(&listen)
        .arg("--config")
        .arg(&server_config_path)
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| CliError::Server(format!("failed to start server: {e}")))?;

    // Wait for token files to appear (written by auto-bootstrap on first run)
    let admin_token_path = dev_dir.join("admin-token");
    let agent_token_path = dev_dir.join("agent-token");
    let dev_token_path = dev_dir.join("developer-token");

    for i in 0..30 {
        if admin_token_path.exists() && agent_token_path.exists() {
            break;
        }
        if i == 29 {
            cleanup_child(&mut server_child);
            return Err(CliError::Server(
                "timeout waiting for bootstrap token files".into(),
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    let admin_token = std::fs::read_to_string(&admin_token_path).unwrap_or_default();
    let dev_token = std::fs::read_to_string(&dev_token_path).unwrap_or_default();
    let agent_token = std::fs::read_to_string(&agent_token_path).unwrap_or_default();

    let client_config_path = dev_dir.join("client.toml");
    let agent_config_path = dev_dir.join("agent.toml");

    // If token files were already present (reuse existing config)
    let reusing_config =
        admin_token.is_empty() && client_config_path.exists() && agent_config_path.exists();

    if admin_token.is_empty() && !reusing_config {
        cleanup_child(&mut server_child);
        return Err(CliError::Server(
            "server did not produce bootstrap tokens and no existing config found. Remove ~/.dbward/dev and retry.".into(),
        ));
    }

    // Wait for server readiness
    let ready = wait_for_ready(&server_url, 10).await;
    if !ready {
        cleanup_child(&mut server_child);
        return Err(CliError::Server(
            "server failed to become ready within 10s".into(),
        ));
    }

    // Write client config (skip if reusing existing)
    if !reusing_config {
        let client_config =
            format!("[server]\nurl = \"{server_url}\"\ntoken = \"{admin_token}\"\n");
        if let Err(e) = write_secure(&client_config_path, client_config.as_bytes()) {
            cleanup_child(&mut server_child);
            return Err(e);
        }
    }

    // Write agent config (skip if reusing existing)
    if !reusing_config {
        let agent_config_path_inner = dev_dir.join("agent.toml");
        let agent_config = format!(
            r#"agent_id = "dev-agent"
poll_interval_ms = 500

[server]
url = "{server_url}"
agent_token = "{agent_token}"

[databases.app.development]
url = "{database_url}"
"#
        );
        if let Err(e) = write_secure(&agent_config_path_inner, agent_config.as_bytes()) {
            cleanup_child(&mut server_child);
            return Err(e);
        }
    }

    // Spawn agent
    let mut agent_child = ProcessCommand::new(&agent_binary)
        .arg("--config")
        .arg(&agent_config_path)
        .spawn()
        .map_err(|e| {
            cleanup_child(&mut server_child);
            CliError::Server(format!("failed to start agent: {e}"))
        })?;

    eprintln!("  Admin token:     {admin_token}");
    eprintln!("  Developer token: {dev_token}");
    eprintln!();
    eprintln!("  Config: {}", client_config_path.display());
    eprintln!(
        "  Try: dbward --config {} --database app execute \"SELECT 1\"",
        client_config_path.display()
    );
    eprintln!();
    if reusing_config {
        eprintln!("  (reusing existing config from previous session)");
        eprintln!();
    }
    eprintln!("Press Ctrl-C to stop.");

    // Wait for ctrl-c
    tokio::signal::ctrl_c().await.ok();
    eprintln!("\nShutting down...");

    let _ = agent_child.kill();
    let _ = server_child.kill();
    let _ = agent_child.wait();
    let _ = server_child.wait();

    Ok(())
}

fn cleanup_child(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

async fn wait_for_ready(url: &str, timeout_secs: u64) -> bool {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .unwrap();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    while tokio::time::Instant::now() < deadline {
        if let Ok(resp) = client.get(format!("{url}/ready")).send().await
            && resp.status().is_success()
        {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    false
}

fn write_secure(path: &std::path::Path, content: &[u8]) -> Result<(), CliError> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?
            .write_all(content)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, content)?;
    }
    Ok(())
}

fn find_binary(name: &str) -> Result<PathBuf, CliError> {
    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe.with_file_name(name);
        if sibling.exists() {
            return Ok(sibling);
        }
    }
    let path_var = std::env::var("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&std::ffi::OsString::from(path_var)) {
        let candidate = dir.join(name);
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(CliError::Server(format!(
        "'{name}' not found. Install it or place it next to the dbward binary."
    )))
}
