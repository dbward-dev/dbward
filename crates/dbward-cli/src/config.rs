pub use dbward_config::ClientConfig;
pub use dbward_config::client::*;
pub use dbward_config::{
    MergedConfig, Source, global_config_dir, load_merged, scoped_credentials_path,
};

use std::path::Path;

use crate::error::CliError;

pub fn load(config_path: &Path) -> Result<ClientConfig, CliError> {
    ClientConfig::load(config_path).map_err(|e| CliError::Config(e.to_string()))
}

pub fn load_resolved(
    explicit_config: Option<&Path>,
    merge_global: bool,
) -> Result<MergedConfig, CliError> {
    load_merged(explicit_config, merge_global).map_err(|e| CliError::Config(e.to_string()))
}
