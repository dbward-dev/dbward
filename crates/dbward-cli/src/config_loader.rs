use std::path::Path;

use dbward_core::{ClientConfig, Error};

pub fn load(config_path: &Path) -> Result<ClientConfig, Error> {
    let mut config = load_from_toml::<ClientConfig>(config_path)?;
    config.resolve_relative_paths(config_base_dir(config_path)?);
    Ok(config)
}

pub fn load_agent(config_path: &Path) -> Result<dbward_agent::AgentConfig, Error> {
    let mut config = load_from_toml::<dbward_core::AgentConfig>(config_path)?;
    config.resolve_relative_paths(config_base_dir(config_path)?);
    config.validate()?;
    Ok(core_to_agent_config(&config))
}

fn core_to_agent_config(core: &dbward_core::AgentConfig) -> dbward_agent::AgentConfig {
    use dbward_agent::config::{DatabaseEntry, ServerConfig};
    use std::collections::HashMap;

    let databases: HashMap<String, HashMap<String, DatabaseEntry>> = core
        .databases
        .iter()
        .map(|(db, envs)| {
            let env_map = envs
                .iter()
                .map(|(env, cfg)| (env.clone(), DatabaseEntry { url: cfg.url.clone() }))
                .collect();
            (db.clone(), env_map)
        })
        .collect();

    dbward_agent::AgentConfig {
        agent_id: Some(core.agent_id.clone()),
        poll_interval_ms: Some(core.poll_interval_ms),
        max_concurrent_tasks: Some(core.max_concurrent_tasks),
        drain_timeout_secs: Some(core.drain_timeout_secs),
        statement_timeout_secs: core.statement_timeout_secs,
        server: ServerConfig {
            url: core.server.url.clone(),
            agent_token: core.server.agent_token.clone(),
        },
        databases,
    }
}

fn load_from_toml<T>(config_path: &Path) -> Result<T, Error>
where
    T: serde::de::DeserializeOwned,
{
    if !config_path.exists() {
        return Err(Error::Config(format!(
            "config file not found: {}. Run 'dbward init' or create dbward.toml",
            config_path.display()
        )));
    }
    let content = std::fs::read_to_string(config_path).map_err(Error::Io)?;
    let mut value: toml::Value = toml::from_str(&content)
        .map_err(|e| Error::Config(format!("{}: {e}", config_path.display())))?;
    dbward_core::env_expand::expand_env_vars(&mut value)?;
    value
        .try_into()
        .map_err(|e| Error::Config(format!("{}: {e}", config_path.display())))
}

fn config_base_dir(config_path: &Path) -> Result<&Path, Error> {
    config_path.parent().ok_or_else(|| {
        Error::Config(format!(
            "config path has no parent directory: {}",
            config_path.display()
        ))
    })
}
