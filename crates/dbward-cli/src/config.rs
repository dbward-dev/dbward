pub use dbward_config::ClientConfig;
pub use dbward_config::client::*;

use std::path::Path;

use crate::error::CliError;

pub fn load(config_path: &Path) -> Result<ClientConfig, CliError> {
    ClientConfig::load(config_path).map_err(|e| CliError::Config(e.to_string()))
}
