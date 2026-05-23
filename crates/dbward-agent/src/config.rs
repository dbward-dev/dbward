pub use dbward_config::AgentConfig;
pub use dbward_config::agent::*;

use crate::AgentError;

/// Wrapper to convert ConfigError into AgentError for backward compatibility.
pub fn load_from_file(path: &std::path::Path) -> Result<AgentConfig, AgentError> {
    AgentConfig::load(path).map_err(|e| AgentError::Config(e.to_string()))
}
