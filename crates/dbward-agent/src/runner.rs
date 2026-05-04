use std::time::Duration;

use dbward_core::{AgentConfig, Engine, Error};
use dbward_migrate::Migrator;


use crate::server_client::AgentClient;

/// Run the agent poll loop. Blocks until interrupted.
pub async fn run(config: AgentConfig) -> Result<(), Error> {
    let client = AgentClient::new(&config.server.url, &config.server.agent_token);
    let poll_interval = Duration::from_millis(config.poll_interval_ms);

    // Fetch server's public key for token verification
    let public_key = client.get_public_key().await?;
    eprintln!("agent {} started, polling {}", config.agent_id, config.server.url);

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                eprintln!("agent shutting down");
                return Ok(());
            }
            _ = poll_once(&config, &client, &public_key) => {}
        }
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                eprintln!("agent shutting down");
                return Ok(());
            }
            _ = tokio::time::sleep(poll_interval) => {}
        }
    }
}

async fn poll_once(
    config: &AgentConfig,
    client: &AgentClient,
    public_key: &ed25519_dalek::VerifyingKey,
) {
    let jobs = match client
        .poll(
            &config.capabilities.databases,
            &config.capabilities.environments,
            &config.capabilities.operations,
        )
        .await
    {
        Ok(j) => j,
        Err(e) => {
            eprintln!("poll failed: {e}");
            return;
        }
    };

    for job in jobs {
        let request_id = match job["id"].as_str() {
            Some(id) => id.to_string(),
            None => continue,
        };

        if let Err(e) = execute_job(config, client, public_key, &request_id, &job).await {
            eprintln!("job {request_id} failed: {e}");
        }
    }
}

async fn execute_job(
    config: &AgentConfig,
    client: &AgentClient,
    public_key: &ed25519_dalek::VerifyingKey,
    request_id: &str,
    _job: &serde_json::Value,
) -> Result<(), Error> {
    // Claim
    let claim = client.claim(request_id, &config.agent_id).await?;
    let exec_id = claim["execution_id"]
        .as_str()
        .ok_or_else(|| Error::Server("missing execution_id in claim".into()))?;
    let operation = claim["operation"].as_str().unwrap_or("");
    let environment = claim["environment"].as_str().unwrap_or("");
    let database = claim["database"].as_str().unwrap_or("");
    let detail = claim["detail"].as_str().unwrap_or("");

    eprintln!("claimed job {request_id} ({operation} on {database})");

    // Verify token
    let token: dbward_core::token::ExecutionToken =
        serde_json::from_value(claim["execution_token"].clone())
            .map_err(|e| Error::Server(format!("invalid execution_token: {e}")))?;

    dbward_core::token::verify_token(&token, public_key, operation, environment, database, detail)?;

    // Resolve DB and execute
    let resolved = config.resolve_database(database)?;
    let env = match environment {
        "production" => dbward_core::Environment::Production,
        "staging" => dbward_core::Environment::Staging,
        "development" => dbward_core::Environment::Development,
        other => dbward_core::Environment::Custom(other.to_string()),
    };

    let (result_value, success) = match execute_operation(&resolved, env, operation, detail).await {
        Ok(text) => {
            let val: serde_json::Value =
                serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text));
            (Some(val), true)
        }
        Err(e) => {
            let msg = e.to_string();
            eprintln!("job {request_id} execution failed: {msg}");
            client.send_result(exec_id, false, None, Some(&msg)).await?;
            return Ok(());
        }
    };

    eprintln!("job {request_id} execution completed");
    client
        .send_result(exec_id, success, result_value, None)
        .await?;
    Ok(())
}

async fn execute_operation(
    resolved: &dbward_core::ResolvedDatabaseConfig,
    env: dbward_core::Environment,
    operation: &str,
    detail: &str,
) -> Result<String, Error> {
    match operation {
        "execute_query" => {
            let mut engine = Engine::new(resolved, env).await?;
            let result = engine
                .execute_query("agent", "developer", detail)
                .await?;
            if result.rows.is_empty() {
                Ok(format!("Rows affected: {}", result.rows_affected))
            } else {
                serde_json::to_string_pretty(&result.rows).map_err(|e| Error::Server(e.to_string()))
            }
        }
        "migrate_up" => {
            let engine = Engine::new(resolved, env).await?;
            let migrator = Migrator::new(engine.driver().clone(), resolved.migrations_dir.clone());
            let count = detail.strip_prefix("count:").and_then(|s| s.parse().ok());
            let count = if count == Some(0) { None } else { count };
            let r = migrator.up(count).await?;
            if r.applied.is_empty() {
                Ok("No pending migrations.".into())
            } else {
                Ok(format!(
                    "Applied {} migration(s):\n{}",
                    r.applied.len(),
                    r.applied.join("\n")
                ))
            }
        }
        "migrate_down" => {
            let engine = Engine::new(resolved, env).await?;
            let migrator = Migrator::new(engine.driver().clone(), resolved.migrations_dir.clone());
            let count = detail.strip_prefix("count:").and_then(|s| s.parse().ok());
            let r = migrator.down(count).await?;
            if r.rolled_back.is_empty() {
                Ok("Nothing to rollback.".into())
            } else {
                Ok(format!("Rolled back:\n{}", r.rolled_back.join("\n")))
            }
        }
        "migrate_status" => {
            let engine = Engine::new(resolved, env).await?;
            let migrator = Migrator::new(engine.driver().clone(), resolved.migrations_dir.clone());
            let statuses = migrator.status().await?;
            if statuses.is_empty() {
                Ok("No migration files found.".into())
            } else {
                Ok(statuses
                    .iter()
                    .map(|s| {
                        let mark = if s.applied { "[x]" } else { "[ ]" };
                        format!("{mark} {}_{}", s.version, s.name)
                    })
                    .collect::<Vec<_>>()
                    .join("\n"))
            }
        }
        _ => Err(Error::Server(format!("unsupported operation: {operation}"))),
    }
}
