use axum::http::StatusCode;
use rusqlite::Connection;
use std::fmt;

use crate::api_error::ApiError;
use crate::license::License;
use crate::server_config::{ResultStorageConfig, ServerConfig};

pub const FREE_WORKFLOWS: usize = 5;
pub const FREE_AGENTS: usize = 3;
pub const FREE_DATABASES: usize = 3;
pub const FREE_WEBHOOKS: usize = 3;
pub const FREE_EXECUTION_POLICIES: usize = 3;
pub const FREE_TOKENS: usize = 10;

const WAITLIST_URL: &str = "https://dbward.dev/waitlist";

#[derive(Debug, Clone, Copy)]
pub enum Resource {
    Workflow,
    ExecutionPolicy,
    Agent,
    Database,
    Token,
}

impl Resource {
    pub fn limit(&self) -> usize {
        match self {
            Self::Workflow => FREE_WORKFLOWS,
            Self::ExecutionPolicy => FREE_EXECUTION_POLICIES,
            Self::Agent => FREE_AGENTS,
            Self::Database => FREE_DATABASES,
            Self::Token => FREE_TOKENS,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Workflow => "Workflow rule",
            Self::ExecutionPolicy => "Execution policy",
            Self::Agent => "Agent",
            Self::Database => "Database connection",
            Self::Token => "API token",
        }
    }

    fn count_query(&self) -> &'static str {
        match self {
            Self::Workflow => "SELECT COUNT(*) FROM workflows",
            Self::ExecutionPolicy => "SELECT COUNT(*) FROM execution_policies",
            Self::Agent => "SELECT COUNT(*) FROM agents",
            Self::Database => {
                "SELECT COUNT(DISTINCT j.value) FROM agents, json_each(json_extract(capabilities_json, '$.databases')) AS j"
            }
            Self::Token => "SELECT COUNT(*) FROM tokens WHERE revoked_at IS NULL",
        }
    }
}

/// Check if a new resource can be created within Free tier limits.
///
/// IMPORTANT: Caller must hold the SQLite mutex lock from this call through
/// the subsequent INSERT to avoid TOCTOU races.
pub fn check_can_create(
    conn: &Connection,
    resource: Resource,
    license: &License,
) -> Result<(), ApiError> {
    if license.is_pro() {
        return Ok(());
    }
    let count: usize = conn
        .query_row(resource.count_query(), [], |row| row.get(0))
        .map_err(|e| ApiError::internal(format!("limit check failed: {e}")))?;
    if count >= resource.limit() {
        return Err(ApiError::new(
            StatusCode::PAYMENT_REQUIRED,
            format!(
                "{} limit reached ({}/{}).",
                resource.name(),
                count,
                resource.limit()
            ),
        )
        .with_code("plan_limit_reached")
        .with_hint(format!("Upgrade to dbward Pro → {WAITLIST_URL}")));
    }
    Ok(())
}

/// Check database connection limit (called after upsert, so uses `>` not `>=`).
pub fn check_database_limit(conn: &Connection, license: &License) -> Result<(), ApiError> {
    if license.is_pro() {
        return Ok(());
    }
    let count: usize = conn
        .query_row(Resource::Database.count_query(), [], |row| row.get(0))
        .map_err(|e| ApiError::internal(format!("limit check failed: {e}")))?;
    if count > Resource::Database.limit() {
        return Err(ApiError::new(
            StatusCode::PAYMENT_REQUIRED,
            format!(
                "{} limit reached ({}/{}).",
                Resource::Database.name(),
                count,
                Resource::Database.limit()
            ),
        )
        .with_code("plan_limit_reached")
        .with_hint(format!("Upgrade to dbward Pro → {WAITLIST_URL}")));
    }
    Ok(())
}

/// Gate a Pro-only feature.
pub fn require_pro(feature: &str, license: &License) -> Result<(), ApiError> {
    if license.is_pro() {
        return Ok(());
    }
    Err(ApiError::new(
        StatusCode::PAYMENT_REQUIRED,
        format!("{feature} requires dbward Pro."),
    )
    .with_code("pro_required")
    .with_hint(format!("Join the waitlist → {WAITLIST_URL}")))
}

// ─── Config validation (startup) ────────────────────────────────────────────

#[derive(Debug)]
pub enum ConfigWarning {
    /// Resource count exceeds Free limit; excess will be ignored.
    Truncated {
        resource: &'static str,
        actual: usize,
        limit: usize,
    },
    /// Entire resource requires Pro; all entries ignored.
    ProRequired(&'static str),
    /// Feature requires Pro and cannot be silently skipped; startup must fail.
    HardBlock(&'static str),
}

impl fmt::Display for ConfigWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated {
                resource,
                actual,
                limit,
            } => write!(
                f,
                "{resource}: {actual} configured, Free plan allows {limit}. Excess ignored."
            ),
            Self::ProRequired(resource) => {
                write!(f, "{resource} requires dbward Pro. Ignored.")
            }
            Self::HardBlock(feature) => {
                write!(f, "{feature} requires dbward Pro. → {WAITLIST_URL}")
            }
        }
    }
}

/// Validate config against Free tier limits. Returns warnings (no side effects).
pub fn validate_config(config: &ServerConfig, license: &License) -> Vec<ConfigWarning> {
    if license.is_pro() {
        return vec![];
    }
    let mut w = vec![];
    if config.workflows.len() > FREE_WORKFLOWS {
        w.push(ConfigWarning::Truncated {
            resource: "workflows",
            actual: config.workflows.len(),
            limit: FREE_WORKFLOWS,
        });
    }
    if config.webhooks.len() > FREE_WEBHOOKS {
        w.push(ConfigWarning::Truncated {
            resource: "webhooks",
            actual: config.webhooks.len(),
            limit: FREE_WEBHOOKS,
        });
    }
    if config.execution_policies.len() > FREE_EXECUTION_POLICIES {
        w.push(ConfigWarning::Truncated {
            resource: "execution_policies",
            actual: config.execution_policies.len(),
            limit: FREE_EXECUTION_POLICIES,
        });
    }
    if !config.result_policies.is_empty() {
        w.push(ConfigWarning::ProRequired("result_policies"));
    }
    if !config.notification_policies.is_empty() {
        w.push(ConfigWarning::ProRequired("notification_policies"));
    }
    if config.auth.as_ref().and_then(|a| a.oidc.as_ref()).is_some() {
        w.push(ConfigWarning::HardBlock("OIDC/SSO"));
    }
    if matches!(config.result_storage, Some(ResultStorageConfig::S3 { .. })) {
        w.push(ConfigWarning::HardBlock("S3 result storage"));
    }
    w
}

/// Apply Free tier limits by truncating excess config entries.
/// Note: agents and tokens are DB-managed, not config-managed, so not truncated here.
pub fn apply_free_limits(mut config: ServerConfig) -> ServerConfig {
    config.workflows.truncate(FREE_WORKFLOWS);
    config.webhooks.truncate(FREE_WEBHOOKS);
    config.execution_policies.truncate(FREE_EXECUTION_POLICIES);
    config.result_policies.clear();
    config.notification_policies.clear();
    config
}

#[cfg(test)]
mod tests {
    use super::*;

    fn free_license() -> License {
        License {
            plan: crate::license::Plan::Free,
        }
    }

    fn pro_license() -> License {
        License {
            plan: crate::license::Plan::Pro,
        }
    }

    // --- validate_config ---

    #[test]
    fn validate_config_empty_for_pro() {
        let config = ServerConfig::default();
        assert!(validate_config(&config, &pro_license()).is_empty());
    }

    #[test]
    fn validate_config_no_warnings_under_limit() {
        let config = ServerConfig::default();
        assert!(validate_config(&config, &free_license()).is_empty());
    }

    #[test]
    fn validate_config_warns_excess_workflows() {
        let mut config = ServerConfig::default();
        config.workflows = (0..FREE_WORKFLOWS + 2)
            .map(|i| crate::server_config::WorkflowDef {
                database: format!("db{i}"),
                environment: "*".into(),
                operations: vec![],
                steps: vec![],
                require_reason: false,
                allow_same_approver_across_steps: false,
                allow_self_approve: false,
            })
            .collect();
        let warnings = validate_config(&config, &free_license());
        assert!(warnings.iter().any(|w| matches!(
            w,
            ConfigWarning::Truncated {
                resource: "workflows",
                ..
            }
        )));
    }

    #[test]
    fn validate_config_blocks_oidc() {
        let mut config = ServerConfig::default();
        config.auth = Some(crate::server_config::AuthConfig {
            mode: "oidc".into(),
            oidc: Some(crate::server_config::OidcConfig {
                issuer: "https://example.com".into(),
                client_id: "id".into(),
                client_secret_env: None,
                jwks_uri: None,
                default_role: "readonly".into(),
                role_mappings: vec![],
            }),
            break_glass_roles: vec![],
        });
        let warnings = validate_config(&config, &free_license());
        assert!(
            warnings
                .iter()
                .any(|w| matches!(w, ConfigWarning::HardBlock("OIDC/SSO")))
        );
    }

    // --- apply_free_limits ---

    #[test]
    fn apply_free_limits_truncates() {
        let mut config = ServerConfig::default();
        config.workflows = (0..10)
            .map(|i| crate::server_config::WorkflowDef {
                database: format!("db{i}"),
                environment: "*".into(),
                operations: vec![],
                steps: vec![],
                require_reason: false,
                allow_same_approver_across_steps: false,
                allow_self_approve: false,
            })
            .collect();
        let limited = apply_free_limits(config);
        assert_eq!(limited.workflows.len(), FREE_WORKFLOWS);
    }

    // --- require_pro ---

    #[test]
    fn require_pro_passes_for_pro() {
        assert!(require_pro("feature", &pro_license()).is_ok());
    }

    #[test]
    fn require_pro_blocks_for_free() {
        let err = require_pro("feature", &free_license()).unwrap_err();
        assert_eq!(err.status, StatusCode::PAYMENT_REQUIRED);
    }

    // --- Resource ---

    #[test]
    fn resource_limits_are_correct() {
        assert_eq!(Resource::Workflow.limit(), 5);
        assert_eq!(Resource::Agent.limit(), 3);
        assert_eq!(Resource::Database.limit(), 3);
        assert_eq!(Resource::Token.limit(), 10);
    }
}
