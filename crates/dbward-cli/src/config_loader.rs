use std::path::Path;

use dbward_core::{AgentConfig, ClientConfig, Error};

pub fn load(config_path: &Path) -> Result<ClientConfig, Error> {
    let mut config = load_from_toml::<ClientConfig>(config_path)?;
    config.resolve_relative_paths(config_base_dir(config_path)?);
    Ok(config)
}

pub fn load_agent(config_path: &Path) -> Result<AgentConfig, Error> {
    let mut config = load_from_toml::<AgentConfig>(config_path)?;
    config.resolve_relative_paths(config_base_dir(config_path)?);
    Ok(config)
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
