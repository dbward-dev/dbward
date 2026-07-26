pub mod agent;
pub mod client;
pub mod diagnostics;
mod error;
pub mod expand;
pub mod merged;
pub mod server;
pub mod transport;
pub mod validation;

pub use agent::AgentConfig;
pub use client::ClientConfig;
pub use error::ConfigError;
pub use expand::{ENV_VAR_PATTERN, expand_env_vars, expand_toml_value};
pub use merged::{MergedConfig, Source, global_config_dir, load_merged, scoped_credentials_path};
pub use server::ServerConfig;
pub use server::{
    ApproverDef, ApproverSelectorType, WorkflowStepDef, WorkflowStepModeDef,
};
pub use validation::{
    CoverageEntry, DeadStepEntry, EnvVarIssueEntry, EnvVarIssueType, InvalidWorkflowEntry,
    IssueContext, SlackConfigEntry, SqlReviewSafetyEntry, ValidationIssue, ValidationSeverity,
};
