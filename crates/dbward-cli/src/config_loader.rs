use std::path::Path;

use dbward_core::{ClientConfig, Error};

pub fn load(config_path: &Path) -> Result<ClientConfig, Error> {
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
