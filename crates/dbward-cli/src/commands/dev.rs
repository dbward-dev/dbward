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
        r#"[result_storage]
backend = "local"
root_dir = "{results}"

[[databases]]
name = "app"
environments = ["development"]

[[workflows]]
database = "*"
environment = "*"
"#,
        results = results_dir.display()
    );
    std::fs::write(&server_config_path, &server_config)?;

    let listen = format!("127.0.0.1:{port}");
    let data_path = dev_dir.join("dbward.db");
    let server_url = format!("http://{listen}");

    eprintln!("dbward dev starting...");
    eprintln!("  Server: {server_url}");
    eprintln!("  Database: {database_url}");
    eprintln!();

    // Spawn server with --dev-bootstrap to get tokens on stdout
    let mut server_child = ProcessCommand::new(&server_binary)
        .arg("--listen")
        .arg(&listen)
        .arg("--data")
        .arg(&data_path)
        .arg("--config")
        .arg(&server_config_path)
        .arg("--dev-bootstrap")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| CliError::Server(format!("failed to start server: {e}")))?;

    // Read bootstrap tokens from server stdout (JSON line)
    let tokens = read_bootstrap_tokens(&mut server_child)?;
    let admin_token = tokens.get("admin").cloned().unwrap_or_default();
    let dev_token = tokens.get("developer").cloned().unwrap_or_default();
    let agent_token = tokens.get("agent").cloned().unwrap_or_default();

    if admin_token.is_empty() {
        cleanup_child(&mut server_child);
        return Err(CliError::Server(
            "server did not produce bootstrap tokens".into(),
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

    // Write client config
    let client_config_path = dev_dir.join("client.toml");
    let client_config = format!("[server]\nurl = \"{server_url}\"\ntoken = \"{dev_token}\"\n");
    if let Err(e) = write_secure(&client_config_path, client_config.as_bytes()) {
        cleanup_child(&mut server_child);
        return Err(e);
    }

    // Write agent config
    let agent_config_path = dev_dir.join("agent.toml");
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
    if let Err(e) = write_secure(&agent_config_path, agent_config.as_bytes()) {
        cleanup_child(&mut server_child);
        return Err(e);
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
        "  Try: dbward --config {} execute \"SELECT 1\"",
        client_config_path.display()
    );
    eprintln!();
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

fn read_bootstrap_tokens(
    child: &mut std::process::Child,
) -> Result<std::collections::HashMap<String, String>, CliError> {
    use std::io::BufRead;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| CliError::Server("cannot read server stdout".into()))?;
    let reader = std::io::BufReader::new(stdout);
    // Server outputs one JSON line: {"admin":"token","developer":"token","agent":"token"}
    for line in reader.lines().take(10) {
        let line = line.map_err(|e| CliError::Server(format!("read stdout: {e}")))?;
        if let Ok(map) = serde_json::from_str::<std::collections::HashMap<String, String>>(&line)
            && map.contains_key("admin")
        {
            return Ok(map);
        }
    }
    Err(CliError::Server(
        "server did not output bootstrap tokens".into(),
    ))
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
