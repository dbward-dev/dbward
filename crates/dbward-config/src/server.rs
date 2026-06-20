use std::collections::{HashMap, HashSet};
use std::path::Path;

use serde::Deserialize;

use crate::ConfigError;
use crate::expand::expand_env_vars;

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    /// Directory for server state (SQLite DB, signing keys, agent-token).
    /// Required — no default. Relative paths resolve against config file parent.
    pub state_dir: String,
    #[serde(default)]
    pub result_storage: ResultStorageConfig,
    #[serde(default)]
    pub result_channel: ResultChannelConfig,
    #[serde(default)]
    pub databases: Vec<DatabaseDef>,
    #[serde(default)]
    pub workflows: Vec<WorkflowDef>,
    #[serde(default)]
    pub webhooks: Vec<WebhookDef>,
    #[serde(default)]
    pub execution_policies: Vec<ExecutionPolicyDef>,
    #[serde(default)]
    pub result_policies: Vec<ResultPolicyDef>,
    #[serde(default)]
    pub notification_policies: Vec<NotificationPolicyDef>,
    #[serde(default)]
    pub users: Vec<UserDef>,
    #[serde(default)]
    pub retention: RetentionConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    #[serde(default)]
    pub allow_private_networks: bool,
    #[serde(default)]
    pub sql_review: SqlReviewConfig,
    #[serde(default)]
    pub auto_approve: Vec<AutoApproveConfig>,
    #[serde(default)]
    pub slack: Option<SlackConfig>,
    #[serde(default)]
    pub mcp: McpConfig,
}

impl ServerConfig {
    /// Load, expand env vars, parse, and validate in one step.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path).map_err(|e| ConfigError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        Self::from_str(&content, &path.display().to_string())
    }

    /// Parse from TOML string. Expands env vars and validates.
    pub fn from_str(input: &str, source: &str) -> Result<Self, ConfigError> {
        let expanded = expand_env_vars(input)?;
        let cfg: Self = toml::from_str(&expanded).map_err(|e| ConfigError::Parse {
            path: source.to_string(),
            message: e.to_string(),
        })?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Parse from TOML string without full auth-connection validation (for reload).
    pub fn parse_for_reload(
        input: &str,
        source: &str,
        active_auth_mode: &str,
    ) -> Result<Self, ConfigError> {
        let expanded = expand_env_vars(input)?;
        let cfg: Self = toml::from_str(&expanded).map_err(|e| ConfigError::Parse {
            path: source.to_string(),
            message: e.to_string(),
        })?;
        cfg.validate_for_reload(active_auth_mode)?;
        Ok(cfg)
    }

    /// Resolve effective auth mode based on explicit setting and OIDC presence.
    pub fn effective_auth_mode(&self) -> &str {
        match &self.auth.mode {
            Some(m) => m.as_str(),
            None => {
                if self.auth.oidc.is_some() {
                    "both"
                } else {
                    "token"
                }
            }
        }
    }

    /// Reload validation: skips auth connection settings (restart-only).
    /// Still validates auth.mode values and role_mappings for active auth mode.
    pub fn validate_for_reload(&self, active_auth_mode: &str) -> Result<(), ConfigError> {
        self.validate_common()?;
        // Reject invalid auth.mode values even on reload
        if let Some(ref m) = self.auth.mode {
            match m.as_str() {
                "token" | "oidc" | "both" => {}
                other => {
                    return Err(ConfigError::Validation(format!(
                        "auth.mode: unknown value '{other}' (expected: token, oidc, both)"
                    )));
                }
            }
        }
        // Validate role_mappings when active mode uses OIDC (these are reloadable)
        if active_auth_mode == "oidc" || active_auth_mode == "both" {
            self.validate_oidc_role_mappings()?;
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), ConfigError> {
        self.validate_common()?;
        self.validate_auth_connection()?;
        let effective = self.effective_auth_mode();
        if effective == "oidc" || effective == "both" {
            self.validate_oidc_role_mappings()?;
        }
        Ok(())
    }

    fn validate_auth_connection(&self) -> Result<(), ConfigError> {
        // auth.mode value validation
        if let Some(ref m) = self.auth.mode {
            match m.as_str() {
                "token" | "oidc" | "both" => {}
                other => {
                    return Err(ConfigError::Validation(format!(
                        "auth.mode: unknown value '{other}' (expected: token, oidc, both)"
                    )));
                }
            }
        }

        let effective = self.effective_auth_mode();

        // mode requiring OIDC must have [auth.oidc]
        if (effective == "oidc" || effective == "both") && self.auth.oidc.is_none() {
            return Err(ConfigError::Validation(format!(
                "auth.mode = \"{effective}\" requires [auth.oidc] configuration section"
            )));
        }

        // OIDC config field validation (only when effective mode uses OIDC)
        if (effective == "oidc" || effective == "both")
            && let Some(ref oidc) = self.auth.oidc
        {
            let issuer = oidc.issuer_url.trim();
            if issuer.is_empty() {
                return Err(ConfigError::Validation(
                    "auth.oidc.issuer_url cannot be empty".into(),
                ));
            }
            if !issuer.starts_with("http://") && !issuer.starts_with("https://") {
                return Err(ConfigError::Validation(format!(
                    "auth.oidc.issuer_url: must start with http:// or https://, got '{issuer}'"
                )));
            }

            if let Some(ref jwks) = oidc.jwks_uri {
                let jwks_trimmed = jwks.trim();
                if jwks_trimmed.is_empty() {
                    return Err(ConfigError::Validation(
                        "auth.oidc.jwks_uri: cannot be empty (omit the field to use default)"
                            .into(),
                    ));
                }
                if !jwks_trimmed.starts_with("http://") && !jwks_trimmed.starts_with("https://") {
                    return Err(ConfigError::Validation(format!(
                        "auth.oidc.jwks_uri: must start with http:// or https://, got '{jwks_trimmed}'"
                    )));
                }
            }

            let has_client_id = oidc
                .client_id
                .as_deref()
                .is_some_and(|s| !s.trim().is_empty());
            let has_audience = !oidc.audience.trim().is_empty();
            if !has_client_id && !has_audience {
                return Err(ConfigError::Validation(
                    "auth.oidc: at least one of client_id or audience must be non-empty".into(),
                ));
            }
        }

        Ok(())
    }

    fn validate_oidc_role_mappings(&self) -> Result<(), ConfigError> {
        let builtin_roles: std::collections::HashSet<&str> =
            ["admin", "developer", "readonly", "agent-default"]
                .into_iter()
                .collect();
        let custom: std::collections::HashSet<&str> =
            self.auth.roles.iter().map(|r| r.name.as_str()).collect();
        let all_roles: std::collections::HashSet<&str> = builtin_roles
            .iter()
            .copied()
            .chain(custom.iter().copied())
            .collect();

        if let Some(ref oidc) = self.auth.oidc {
            for mapping in &oidc.role_mappings {
                if !all_roles.contains(mapping.role.as_str()) {
                    return Err(ConfigError::Validation(format!(
                        "auth.oidc.role_mappings: role '{}' is not defined in auth.roles or built-in",
                        mapping.role
                    )));
                }
            }
        }
        Ok(())
    }

    fn validate_common(&self) -> Result<(), ConfigError> {
        if self.retention.approval_ttl_secs == 0 {
            return Err(ConfigError::Validation(
                "retention.approval_ttl_secs must be > 0 (immediate expiry makes approval impossible)".into(),
            ));
        }

        // Workflow operations overlap within same (db, env) scope
        type ScopeEntries = Vec<(usize, Vec<String>)>;
        let mut scope_ops: HashMap<(&str, &str), ScopeEntries> = HashMap::new();
        for (i, wf) in self.workflows.iter().enumerate() {
            scope_ops
                .entry((wf.database.as_str(), wf.environment.as_str()))
                .or_default()
                .push((i, wf.operations.clone()));
        }
        for ((db, env), entries) in &scope_ops {
            let has_catchall = entries.iter().any(|(_, ops)| ops.is_empty());
            if has_catchall && entries.len() > 1 {
                return Err(ConfigError::Validation(format!(
                    "workflow validation: database={db}, environment={env} has both catchall (operations omitted) and specific operations workflows — ambiguous"
                )));
            }
            let mut seen: HashSet<&str> = HashSet::new();
            for (idx, ops) in entries {
                for op in ops {
                    if !seen.insert(op.as_str()) {
                        return Err(ConfigError::Validation(format!(
                            "workflow validation: operation '{op}' appears in multiple workflows for database={db}, environment={env} (workflow index {idx})"
                        )));
                    }
                }
            }
        }

        // Auto-approve scope uniqueness
        let mut aa_scopes: HashSet<(&str, &str)> = HashSet::new();
        for a in &self.auto_approve {
            if !aa_scopes.insert((a.database.as_str(), a.environment.as_str())) {
                return Err(ConfigError::Validation(format!(
                    "auto_approve validation: duplicate scope (database={}, environment={})",
                    a.database, a.environment
                )));
            }
        }

        // Webhook id validation
        {
            let id_re = regex::Regex::new(r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?$").unwrap();
            let mut seen_ids: HashSet<&str> = HashSet::new();
            for (i, wh) in self.webhooks.iter().enumerate() {
                if wh.id.is_empty() {
                    let suggestion = slug_from_url(&wh.url);
                    return Err(ConfigError::Validation(format!(
                        "webhooks[{i}] is missing required 'id' field.\n       suggested: id = \"{suggestion}\""
                    )));
                }
                if wh.id.len() > 64 {
                    return Err(ConfigError::Validation(format!(
                        "webhooks[{i}].id '{}' exceeds 64 characters",
                        wh.id
                    )));
                }
                if !id_re.is_match(&wh.id) {
                    return Err(ConfigError::Validation(format!(
                        "webhooks[{i}].id '{}' must match [a-z0-9][a-z0-9\\-]*",
                        wh.id
                    )));
                }
                if !seen_ids.insert(wh.id.as_str()) {
                    return Err(ConfigError::Validation(format!(
                        "webhooks[{i}].id '{}' is duplicated",
                        wh.id
                    )));
                }
            }
        }

        // Notification policy: webhooks must reference defined webhook IDs
        {
            let webhook_ids: HashSet<&str> = self.webhooks.iter().map(|w| w.id.as_str()).collect();
            for (i, np) in self.notification_policies.iter().enumerate() {
                for wh_id in &np.webhooks {
                    if !webhook_ids.contains(wh_id.as_str()) {
                        return Err(ConfigError::Validation(format!(
                            "notification_policies[{i}].webhooks: '{}' does not match any [[webhooks]].id",
                            wh_id
                        )));
                    }
                }
            }
        }

        // Result policy delivery_mode validation
        for (i, rp) in self.result_policies.iter().enumerate() {
            match rp.delivery_mode.as_str() {
                "both" | "store_only" | "stream" => {}
                other => {
                    return Err(ConfigError::Validation(format!(
                        "result_policies[{i}].delivery_mode: unknown value '{other}' (expected: both, store_only, stream)"
                    )));
                }
            }
        }

        // User validation
        {
            let mut seen_user_ids: HashSet<&str> = HashSet::new();
            for (i, u) in self.users.iter().enumerate() {
                if u.id.is_empty() {
                    return Err(ConfigError::Validation(format!(
                        "users[{i}]: 'id' cannot be empty"
                    )));
                }
                if !seen_user_ids.insert(u.id.as_str()) {
                    return Err(ConfigError::Validation(format!(
                        "users[{i}]: duplicate user id '{}'",
                        u.id
                    )));
                }
                match u.status.as_str() {
                    "active" | "suspended" => {}
                    other => {
                        return Err(ConfigError::Validation(format!(
                            "users[{i}].status: unknown value '{other}' (expected: active, suspended)"
                        )));
                    }
                }
            }
        }

        // Execution policy timeout consistency
        for (i, ep) in self.execution_policies.iter().enumerate() {
            if ep.max_executions == Some(0) {
                return Err(ConfigError::Validation(format!(
                    "execution_policies[{i}]: max_executions must be >= 1"
                )));
            }
            if let (Some(st), Some(max_st)) =
                (ep.statement_timeout_secs, ep.max_statement_timeout_secs)
                && st > max_st
            {
                return Err(ConfigError::Validation(format!(
                    "execution_policies[{i}]: statement_timeout_secs must not exceed max_statement_timeout_secs"
                )));
            }
            if let (Some(mig_st), Some(max_st)) = (
                ep.migration_statement_timeout_secs,
                ep.max_statement_timeout_secs,
            ) && mig_st > 0
                && mig_st > max_st
            {
                return Err(ConfigError::Validation(format!(
                    "execution_policies[{i}]: migration_statement_timeout_secs must not exceed max_statement_timeout_secs"
                )));
            }
        }

        // Custom role definitions
        let builtin_roles: HashSet<&str> = ["admin", "developer", "readonly", "agent-default"]
            .into_iter()
            .collect();
        let mut custom_role_names: HashSet<&str> = HashSet::new();
        for rc in &self.auth.roles {
            if builtin_roles.contains(rc.name.as_str()) {
                return Err(ConfigError::Validation(format!(
                    "auth.roles: '{}' is a built-in role and cannot be redefined",
                    rc.name
                )));
            }
            if !custom_role_names.insert(rc.name.as_str()) {
                return Err(ConfigError::Validation(format!(
                    "auth.roles: duplicate role name '{}'",
                    rc.name
                )));
            }
            if rc.permissions.is_empty() {
                return Err(ConfigError::Validation(format!(
                    "auth.roles[{}]: permissions cannot be empty",
                    rc.name
                )));
            }
            for perm in &rc.permissions {
                if perm.parse::<dbward_domain::auth::Permission>().is_err() {
                    return Err(ConfigError::Validation(format!(
                        "auth.roles[{}]: unknown permission '{}'",
                        rc.name, perm
                    )));
                }
            }
            for db in &rc.databases {
                if db != "*" && dbward_domain::values::DatabaseName::new(db).is_err() {
                    return Err(ConfigError::Validation(format!(
                        "auth.roles[{}]: invalid database name '{}'",
                        rc.name, db
                    )));
                }
            }
            for env in &rc.environments {
                if env != "*" && dbward_domain::values::Environment::new(env).is_err() {
                    return Err(ConfigError::Validation(format!(
                        "auth.roles[{}]: invalid environment name '{}'",
                        rc.name, env
                    )));
                }
            }
        }

        // Group definitions
        let mut group_names: HashSet<&str> = HashSet::new();
        for gc in &self.auth.groups {
            if !group_names.insert(gc.name.as_str()) {
                return Err(ConfigError::Validation(format!(
                    "auth.groups: duplicate group name '{}'",
                    gc.name
                )));
            }
            if gc.members.is_empty() {
                return Err(ConfigError::Validation(format!(
                    "auth.groups[{}]: members cannot be empty",
                    gc.name
                )));
            }
        }

        // role_bindings must reference defined roles
        let all_defined_roles: HashSet<&str> = builtin_roles
            .iter()
            .copied()
            .chain(custom_role_names.iter().copied())
            .collect();
        for rb in &self.auth.role_bindings {
            if !all_defined_roles.contains(rb.role.as_str()) {
                return Err(ConfigError::Validation(format!(
                    "auth.role_bindings: role '{}' is not defined in auth.roles or built-in",
                    rb.role
                )));
            }
        }
        if let Some(ref default) = self.auth.default_role
            && !all_defined_roles.contains(default.as_str())
        {
            return Err(ConfigError::Validation(format!(
                "auth.default_role: role '{}' is not defined in auth.roles or built-in",
                default
            )));
        }

        // role_binding duplicates (same role + sorted subjects + sorted groups)
        {
            let mut seen: HashSet<String> = HashSet::new();
            for (i, rb) in self.auth.role_bindings.iter().enumerate() {
                if rb.subjects.is_empty() && rb.groups.is_empty() {
                    return Err(ConfigError::Validation(format!(
                        "auth.role_bindings[{i}]: must have at least one subject or group"
                    )));
                }
                let mut sorted_subjects = rb.subjects.clone();
                sorted_subjects.sort();
                sorted_subjects.dedup();
                let mut sorted_groups = rb.groups.clone();
                sorted_groups.sort();
                sorted_groups.dedup();
                let key = format!(
                    "{}|{}|{}",
                    rb.role,
                    sorted_subjects.join(","),
                    sorted_groups.join(",")
                );
                if !seen.insert(key) {
                    return Err(ConfigError::Validation(format!(
                        "auth.role_bindings[{i}]: duplicate binding for role '{}' with same subjects/groups",
                        rb.role
                    )));
                }
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Sub-types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct RetentionConfig {
    #[serde(default = "default_request_ttl")]
    pub request_ttl_days: u64,
    #[serde(default = "default_audit_ttl")]
    pub audit_ttl_days: u64,
    #[serde(default = "default_result_ttl")]
    pub result_ttl_days: u64,
    #[serde(default = "default_approval_ttl")]
    pub approval_ttl_secs: u64,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            request_ttl_days: default_request_ttl(),
            audit_ttl_days: default_audit_ttl(),
            result_ttl_days: default_result_ttl(),
            approval_ttl_secs: default_approval_ttl(),
        }
    }
}

fn default_request_ttl() -> u64 {
    90
}
fn default_audit_ttl() -> u64 {
    365
}
fn default_result_ttl() -> u64 {
    30
}
fn default_approval_ttl() -> u64 {
    86400
}

#[derive(Debug, Deserialize, Default)]
pub struct AuthConfig {
    /// None = omitted (default resolved by context), Some = explicitly set.
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub oidc: Option<OidcConfig>,
    #[serde(default)]
    pub role_bindings: Vec<RoleBinding>,
    pub default_role: Option<String>,
    #[serde(default)]
    pub roles: Vec<RoleConfig>,
    #[serde(default)]
    pub groups: Vec<GroupConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RoleConfig {
    pub name: String,
    pub permissions: Vec<String>,
    #[serde(default)]
    pub databases: Vec<String>,
    #[serde(default)]
    pub environments: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct GroupConfig {
    pub name: String,
    pub members: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct RoleBinding {
    pub role: String,
    #[serde(default)]
    pub subjects: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct OidcConfig {
    #[serde(alias = "issuer")]
    pub issuer_url: String,
    #[serde(default)]
    pub audience: String,
    #[serde(default)]
    pub jwks_uri: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub role_mappings: Vec<OidcRoleMapping>,
    pub default_role: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct OidcRoleMapping {
    pub claim: String,
    pub value: String,
    pub role: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct AuditConfig {
    #[serde(default = "default_redaction")]
    pub redaction: String,
}

fn default_redaction() -> String {
    "literals".into()
}

#[derive(Debug, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default)]
    pub format: LogFormat,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
            format: LogFormat::Text,
        }
    }
}

fn default_log_level() -> String {
    "info".into()
}

#[derive(Debug, Deserialize, Default, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

#[derive(Debug, Deserialize, Default)]
pub struct ResultStorageConfig {
    #[serde(default = "default_backend")]
    pub backend: String,
    pub root_dir: Option<String>,
    pub bucket: Option<String>,
    pub region: Option<String>,
    pub endpoint: Option<String>,
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
    #[serde(default)]
    pub path_style: bool,
    #[serde(default = "default_result_prefix")]
    pub prefix: Option<String>,
    #[serde(default = "default_max_persist_bytes")]
    pub max_persist_bytes: usize,
}

fn default_backend() -> String {
    "local".into()
}
fn default_result_prefix() -> Option<String> {
    Some("results".into())
}
fn default_max_persist_bytes() -> usize {
    10 * 1024 * 1024
}

#[derive(Debug, Deserialize)]
pub struct ResultChannelConfig {
    #[serde(default = "default_max_slots")]
    pub max_slots: usize,
    #[serde(default = "default_slot_ttl_secs")]
    pub slot_ttl_secs: u64,
}

impl Default for ResultChannelConfig {
    fn default() -> Self {
        Self {
            max_slots: default_max_slots(),
            slot_ttl_secs: default_slot_ttl_secs(),
        }
    }
}

fn default_max_slots() -> usize {
    10_000
}
fn default_slot_ttl_secs() -> u64 {
    600
}

#[derive(Debug, Deserialize)]
pub struct DatabaseDef {
    pub name: String,
    #[serde(default)]
    pub environments: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowDef {
    #[serde(default = "star")]
    pub database: String,
    #[serde(default = "star")]
    pub environment: String,
    #[serde(default)]
    pub operations: Vec<String>,
    #[serde(default)]
    pub steps: Vec<serde_json::Value>,
    #[serde(default)]
    pub require_reason: bool,
    #[serde(default)]
    pub allow_self_approve: bool,
    #[serde(default = "default_true")]
    pub allow_same_approver_across_steps: bool,
    #[serde(default = "default_true")]
    pub explain: bool,
    #[serde(default)]
    pub pending_ttl_secs: Option<u64>,
    #[serde(default)]
    pub statement_timeout_secs: Option<u64>,
}

fn default_true() -> bool {
    true
}

fn star() -> String {
    "*".into()
}

#[derive(Debug, Deserialize)]
pub struct WebhookDef {
    #[serde(default)]
    pub id: String,
    pub url: String,
    #[serde(default)]
    pub events: Vec<String>,
    #[serde(default = "default_webhook_format")]
    pub format: String,
    pub secret: Option<String>,
}

fn default_webhook_format() -> String {
    "generic".into()
}

/// Generate a suggested webhook ID from a URL by extracting the hostname slug.
fn slug_from_url(url: &str) -> String {
    let host = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or("webhook")
        .split(':')
        .next()
        .unwrap_or("webhook");
    let slug: String = host
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let slug = slug.trim_matches('-').to_string();
    if slug.is_empty() {
        "webhook".to_string()
    } else {
        slug
    }
}

#[derive(Debug, Deserialize)]
pub struct ExecutionPolicyDef {
    #[serde(default = "star")]
    pub database: String,
    #[serde(default = "star")]
    pub environment: String,
    #[serde(default)]
    pub max_executions: Option<u32>,
    #[serde(default)]
    pub execution_window_secs: Option<u64>,
    #[serde(default)]
    pub retry_on_failure: Option<bool>,
    #[serde(default)]
    pub statement_timeout_secs: Option<u32>,
    #[serde(default)]
    pub max_statement_timeout_secs: Option<u32>,
    #[serde(default)]
    pub max_rows: Option<u32>,
    #[serde(default)]
    pub migration_lease_duration_secs: Option<u32>,
    #[serde(default)]
    pub migration_statement_timeout_secs: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct ResultPolicyDef {
    #[serde(default = "star")]
    pub database: String,
    #[serde(default = "star")]
    pub environment: String,
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
    #[serde(default = "default_delivery_mode")]
    pub delivery_mode: String,
    #[serde(default)]
    pub access: Vec<String>,
}

fn default_retention_days() -> u32 {
    30
}
fn default_delivery_mode() -> String {
    "both".into()
}

#[derive(Debug, Deserialize)]
pub struct NotificationPolicyDef {
    #[serde(default = "star")]
    pub database: String,
    #[serde(default = "star")]
    pub environment: String,
    #[serde(default)]
    pub webhooks: Vec<String>,
    #[serde(default)]
    pub events: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct UserDef {
    pub id: String,
    #[serde(default = "default_user_status")]
    pub status: String,
}

fn default_user_status() -> String {
    "active".into()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SqlReviewConfig {
    #[serde(default = "default_block")]
    pub no_where_delete: String,
    #[serde(default = "default_block")]
    pub no_where_update: String,
    #[serde(default = "default_block")]
    pub drop_table: String,
    #[serde(default = "default_warn")]
    pub drop_column: String,
    #[serde(default = "default_warn")]
    pub not_null_without_default: String,
    #[serde(default = "default_warn")]
    pub create_index_not_concurrently: String,
    #[serde(default = "default_warn")]
    pub alter_column_type: String,
    #[serde(default = "default_block")]
    pub truncate: String,
    #[serde(default = "default_warn")]
    pub mixed_ddl_dml: String,
    #[serde(default = "default_warn")]
    pub large_in_list: String,
}

impl Default for SqlReviewConfig {
    fn default() -> Self {
        Self {
            no_where_delete: "block".into(),
            no_where_update: "block".into(),
            drop_table: "block".into(),
            drop_column: "warn".into(),
            not_null_without_default: "warn".into(),
            create_index_not_concurrently: "warn".into(),
            alter_column_type: "warn".into(),
            truncate: "block".into(),
            mixed_ddl_dml: "warn".into(),
            large_in_list: "warn".into(),
        }
    }
}

fn default_block() -> String {
    "block".into()
}

fn default_warn() -> String {
    "warn".into()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutoApproveConfig {
    #[serde(default = "star")]
    pub database: String,
    #[serde(default = "star")]
    pub environment: String,
    #[serde(default = "default_risk_none")]
    pub risk: String,
    #[serde(default = "default_allow_read_only")]
    pub allow_read_only: bool,
    #[serde(default = "default_allow_safe_ddl")]
    pub allow_safe_ddl: bool,
    #[serde(default = "default_max_estimated_rows")]
    pub max_estimated_rows: u64,
}

fn default_risk_none() -> String {
    "none".into()
}
fn default_allow_read_only() -> bool {
    true
}
fn default_allow_safe_ddl() -> bool {
    true
}
fn default_max_estimated_rows() -> u64 {
    1000
}

#[derive(Debug, Deserialize)]
pub struct SlackConfig {
    pub bot_token: String,
    pub signing_secret: String,
    #[serde(default = "default_slack_channel")]
    pub channel: String,
    #[serde(default)]
    pub channels: HashMap<String, String>,
}

fn default_slack_channel() -> String {
    "#db-approvals".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cfg(extra: &str) -> String {
        format!("state_dir = \"/tmp\"\n{extra}")
    }

    #[test]
    fn minimal_valid_config() {
        let toml = test_cfg(
            r#"
[[databases]]
name = "app"
environments = ["dev"]

[[workflows]]
database = "*"
environment = "*"
"#,
        );
        let cfg = ServerConfig::from_str(&toml, "test").unwrap();
        assert_eq!(cfg.databases.len(), 1);
        assert_eq!(cfg.retention.approval_ttl_secs, 86400);
    }

    #[test]
    fn rejects_zero_approval_ttl() {
        let toml = test_cfg(
            r#"
[retention]
approval_ttl_secs = 0
"#,
        );
        let err = ServerConfig::from_str(&toml, "test").unwrap_err();
        assert!(err.to_string().contains("approval_ttl_secs"));
    }

    #[test]
    fn rejects_timeout_exceeding_max() {
        let toml = test_cfg(
            r#"
[[execution_policies]]
statement_timeout_secs = 500
max_statement_timeout_secs = 300
"#,
        );
        let err = ServerConfig::from_str(&toml, "test").unwrap_err();
        assert!(err.to_string().contains("must not exceed"));
    }

    #[test]
    fn rejects_migration_timeout_exceeding_max() {
        let toml = test_cfg(
            r#"
[[execution_policies]]
migration_statement_timeout_secs = 700
max_statement_timeout_secs = 600
"#,
        );
        let err = ServerConfig::from_str(&toml, "test").unwrap_err();
        assert!(err.to_string().contains("migration_statement_timeout_secs"));
    }

    #[test]
    fn accepts_migration_timeout_zero() {
        let toml = test_cfg(
            r#"
[[execution_policies]]
migration_statement_timeout_secs = 0
max_statement_timeout_secs = 600
"#,
        );
        assert!(ServerConfig::from_str(&toml, "test").is_ok());
    }

    #[test]
    fn rejects_duplicate_auto_approve_scope() {
        let toml = test_cfg(
            r#"
[[auto_approve]]
database = "app"
environment = "dev"

[[auto_approve]]
database = "app"
environment = "dev"
"#,
        );
        let err = ServerConfig::from_str(&toml, "test").unwrap_err();
        assert!(err.to_string().contains("duplicate scope"));
    }

    #[test]
    fn webhook_valid_id() {
        let toml = test_cfg(
            r#"
[[webhooks]]
id = "ops-alerts"
url = "https://hooks.slack.com/services/T123"
"#,
        );
        let cfg = ServerConfig::from_str(&toml, "test").unwrap();
        assert_eq!(cfg.webhooks[0].id, "ops-alerts");
    }

    #[test]
    fn webhook_rejects_missing_id() {
        let toml = test_cfg(
            r#"
[[webhooks]]
url = "https://hooks.slack.com/services/T123"
"#,
        );
        let err = ServerConfig::from_str(&toml, "test").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("missing required 'id'"), "got: {msg}");
        assert!(msg.contains("suggested"), "got: {msg}");
    }

    #[test]
    fn webhook_rejects_invalid_id_format() {
        let toml = test_cfg(
            r#"
[[webhooks]]
id = "UPPER-CASE"
url = "https://example.com"
"#,
        );
        let err = ServerConfig::from_str(&toml, "test").unwrap_err();
        assert!(err.to_string().contains("must match"));
    }

    #[test]
    fn webhook_rejects_duplicate_id() {
        let toml = test_cfg(
            r#"
[[webhooks]]
id = "same"
url = "https://a.example.com"

[[webhooks]]
id = "same"
url = "https://b.example.com"
"#,
        );
        let err = ServerConfig::from_str(&toml, "test").unwrap_err();
        assert!(err.to_string().contains("duplicated"));
    }

    #[test]
    fn webhook_rejects_too_long_id() {
        let long_id = "a".repeat(65);
        let toml = test_cfg(&format!(
            r#"
[[webhooks]]
id = "{long_id}"
url = "https://example.com"
"#,
        ));
        let err = ServerConfig::from_str(&toml, "test").unwrap_err();
        assert!(err.to_string().contains("exceeds 64"));
    }

    #[test]
    fn slug_from_url_extracts_hostname() {
        assert_eq!(
            slug_from_url("https://hooks.slack.com/services/T123"),
            "hooks-slack-com"
        );
        assert_eq!(slug_from_url("http://localhost:9999"), "localhost");
        assert_eq!(slug_from_url("https://example.com/path"), "example-com");
    }

    #[test]
    fn result_policy_valid() {
        let toml = test_cfg(
            r#"
[[result_policies]]
database = "app"
environment = "production"
retention_days = 7
delivery_mode = "store_only"
access = ["requester", "role:admin"]
"#,
        );
        let cfg = ServerConfig::from_str(&toml, "test").unwrap();
        assert_eq!(cfg.result_policies.len(), 1);
        assert_eq!(cfg.result_policies[0].retention_days, 7);
    }

    #[test]
    fn result_policy_rejects_invalid_delivery_mode() {
        let toml = test_cfg(
            r#"
[[result_policies]]
delivery_mode = "invalid"
"#,
        );
        let err = ServerConfig::from_str(&toml, "test").unwrap_err();
        assert!(err.to_string().contains("unknown value 'invalid'"));
    }

    #[test]
    fn notification_policy_valid() {
        let toml = test_cfg(
            r#"
[[webhooks]]
id = "ops"
url = "https://hooks.slack.com/x"

[[notification_policies]]
database = "app"
environment = "production"
webhooks = ["ops"]
events = ["request_completed"]
"#,
        );
        let cfg = ServerConfig::from_str(&toml, "test").unwrap();
        assert_eq!(cfg.notification_policies.len(), 1);
    }

    #[test]
    fn notification_policy_rejects_unknown_webhook_id() {
        let toml = test_cfg(
            r#"
[[notification_policies]]
webhooks = ["nonexistent"]
events = ["request_completed"]
"#,
        );
        let err = ServerConfig::from_str(&toml, "test").unwrap_err();
        assert!(err.to_string().contains("does not match any"));
    }
}

#[cfg(test)]
mod auth_roles_tests {
    use super::*;

    fn parse(toml: &str) -> Result<ServerConfig, ConfigError> {
        let full = format!("state_dir = \"/tmp\"\n{toml}");
        ServerConfig::from_str(&full, "test")
    }

    fn base_config(extra: &str) -> String {
        format!(
            r#"
[[databases]]
name = "app"
environments = ["production"]

[[workflows]]
database = "app"
environment = "production"

[[workflows.steps]]
type = "approval"
mode = "any"

[[workflows.steps.approvers]]
role = "admin"
min = 1

[auth]
mode = "token"

[result_storage]
root_dir = "/tmp/r"

[sql_review]
no_where_delete = "warn"
no_where_update = "warn"

{extra}
"#
        )
    }

    #[test]
    fn valid_custom_role() {
        let cfg = parse(&base_config(
            r#"
[[auth.roles]]
name = "dba"
permissions = ["request.approve", "request.view"]
databases = ["app"]
environments = ["production"]
"#,
        ))
        .unwrap();
        assert_eq!(cfg.auth.roles.len(), 1);
        assert_eq!(cfg.auth.roles[0].name, "dba");
    }

    #[test]
    fn valid_wildcard_scope() {
        parse(&base_config(
            r#"
[[auth.roles]]
name = "superuser"
permissions = ["*"]
"#,
        ))
        .unwrap();
    }

    #[test]
    fn reject_builtin_name() {
        let err = parse(&base_config(
            r#"
[[auth.roles]]
name = "admin"
permissions = ["request.view"]
"#,
        ))
        .unwrap_err();
        assert!(err.to_string().contains("built-in role"));
    }

    #[test]
    fn reject_empty_permissions() {
        let err = parse(&base_config(
            r#"
[[auth.roles]]
name = "empty"
permissions = []
"#,
        ))
        .unwrap_err();
        assert!(err.to_string().contains("permissions cannot be empty"));
    }

    #[test]
    fn reject_unknown_permission() {
        let err = parse(&base_config(
            r#"
[[auth.roles]]
name = "bad"
permissions = ["request.fly"]
"#,
        ))
        .unwrap_err();
        assert!(err.to_string().contains("unknown permission"));
    }

    #[test]
    fn reject_duplicate_role_name() {
        let err = parse(&base_config(
            r#"
[[auth.roles]]
name = "dba"
permissions = ["request.approve"]

[[auth.roles]]
name = "dba"
permissions = ["request.view"]
"#,
        ))
        .unwrap_err();
        assert!(err.to_string().contains("duplicate role name"));
    }

    #[test]
    fn reject_undefined_role_in_bindings() {
        let err = parse(&base_config(
            r#"
[[auth.role_bindings]]
role = "ghost"
subjects = ["alice"]
"#,
        ))
        .unwrap_err();
        assert!(err.to_string().contains("not defined"));
    }

    #[test]
    fn valid_group_definition() {
        let cfg = parse(&base_config(
            r#"
[[auth.groups]]
name = "team-a"
members = ["alice", "bob"]
"#,
        ))
        .unwrap();
        assert_eq!(cfg.auth.groups.len(), 1);
    }

    #[test]
    fn reject_empty_group_members() {
        let err = parse(&base_config(
            r#"
[[auth.groups]]
name = "empty-team"
members = []
"#,
        ))
        .unwrap_err();
        assert!(err.to_string().contains("members cannot be empty"));
    }

    #[test]
    fn reject_duplicate_group() {
        let err = parse(&base_config(
            r#"
[[auth.groups]]
name = "team"
members = ["alice"]

[[auth.groups]]
name = "team"
members = ["bob"]
"#,
        ))
        .unwrap_err();
        assert!(err.to_string().contains("duplicate group name"));
    }

    #[test]
    fn role_binding_with_config_role_passes() {
        parse(&base_config(
            r#"
[[auth.roles]]
name = "dba"
permissions = ["request.approve"]

[[auth.role_bindings]]
role = "dba"
subjects = ["carol"]
"#,
        ))
        .unwrap();
    }
}

#[cfg(test)]
mod auth_mode_tests {
    use super::*;

    fn parse(toml: &str) -> Result<ServerConfig, ConfigError> {
        let full = format!("state_dir = \"/tmp\"\n{toml}");
        ServerConfig::from_str(&full, "test")
    }

    #[test]
    fn mode_omitted_no_oidc_defaults_to_token() {
        let cfg = parse("").unwrap();
        assert_eq!(cfg.effective_auth_mode(), "token");
        assert!(cfg.auth.mode.is_none());
    }

    #[test]
    fn mode_omitted_with_oidc_defaults_to_both() {
        let cfg = parse(
            r#"
[auth.oidc]
issuer_url = "https://auth.example.com"
audience = "dbward"
"#,
        )
        .unwrap();
        assert_eq!(cfg.effective_auth_mode(), "both");
    }

    #[test]
    fn mode_token_explicit_ok() {
        let cfg = parse("[auth]\nmode = \"token\"\n").unwrap();
        assert_eq!(cfg.effective_auth_mode(), "token");
    }

    #[test]
    fn mode_invalid_rejected() {
        let err = parse("[auth]\nmode = \"invalid\"\n").unwrap_err();
        assert!(err.to_string().contains("unknown value 'invalid'"));
    }

    #[test]
    fn mode_oidc_without_section_rejected() {
        let err = parse("[auth]\nmode = \"oidc\"\n").unwrap_err();
        assert!(err.to_string().contains("requires [auth.oidc]"));
    }

    #[test]
    fn mode_both_without_section_rejected() {
        let err = parse("[auth]\nmode = \"both\"\n").unwrap_err();
        assert!(err.to_string().contains("requires [auth.oidc]"));
    }

    #[test]
    fn oidc_issuer_empty_rejected() {
        let err = parse(
            r#"
[auth]
mode = "oidc"
[auth.oidc]
issuer_url = ""
audience = "dbward"
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("issuer_url cannot be empty"));
    }

    #[test]
    fn oidc_issuer_bad_scheme_rejected() {
        let err = parse(
            r#"
[auth]
mode = "oidc"
[auth.oidc]
issuer_url = "ftp://example.com"
audience = "dbward"
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("must start with http://"));
    }

    #[test]
    fn oidc_audience_and_client_id_both_empty_rejected() {
        let err = parse(
            r#"
[auth]
mode = "oidc"
[auth.oidc]
issuer_url = "https://auth.example.com"
audience = ""
client_id = ""
"#,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("client_id or audience must be non-empty")
        );
    }

    #[test]
    fn oidc_jwks_uri_whitespace_rejected() {
        let err = parse(
            r#"
[auth]
mode = "oidc"
[auth.oidc]
issuer_url = "https://auth.example.com"
audience = "dbward"
jwks_uri = "   "
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("jwks_uri: cannot be empty"));
    }

    #[test]
    fn oidc_jwks_uri_bad_scheme_rejected() {
        let err = parse(
            r#"
[auth]
mode = "oidc"
[auth.oidc]
issuer_url = "https://auth.example.com"
audience = "dbward"
jwks_uri = "ftp://keys.example.com"
"#,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("jwks_uri: must start with http://")
        );
    }

    #[test]
    fn oidc_valid_config_accepted() {
        let cfg = parse(
            r#"
[auth]
mode = "oidc"
[auth.oidc]
issuer_url = "https://auth.example.com/realms/test"
audience = "dbward"
"#,
        )
        .unwrap();
        assert_eq!(cfg.effective_auth_mode(), "oidc");
    }

    #[test]
    fn both_mode_with_oidc_valid() {
        let cfg = parse(
            r#"
[auth]
mode = "both"
[auth.oidc]
issuer_url = "https://auth.example.com/realms/test"
audience = "dbward"
"#,
        )
        .unwrap();
        assert_eq!(cfg.effective_auth_mode(), "both");
    }

    #[test]
    fn token_mode_with_oidc_section_accepted() {
        // OIDC config present but mode=token → OIDC ignored, no validation on OIDC fields
        let cfg = parse(
            r#"
[auth]
mode = "token"
[auth.oidc]
issuer_url = "not-a-url"
audience = ""
"#,
        )
        .unwrap();
        assert_eq!(cfg.effective_auth_mode(), "token");
    }

    #[test]
    fn validate_for_reload_rejects_invalid_mode() {
        let full = "state_dir = \"/tmp\"\n[auth]\nmode = \"bogus\"\n";
        let expanded = crate::expand::expand_env_vars(full).unwrap();
        let cfg: ServerConfig = toml::from_str(&expanded).unwrap();
        let err = cfg.validate_for_reload("token").unwrap_err();
        assert!(err.to_string().contains("unknown value 'bogus'"));
    }

    #[test]
    fn validate_for_reload_skips_oidc_connection_check() {
        // mode=oidc without [auth.oidc] → validate_for_reload should NOT fail
        // (auth connection is restart-only)
        let full = "state_dir = \"/tmp\"\n[auth]\nmode = \"oidc\"\n";
        let expanded = crate::expand::expand_env_vars(full).unwrap();
        let cfg: ServerConfig = toml::from_str(&expanded).unwrap();
        // active mode is "token" so role_mappings check is skipped
        assert!(cfg.validate_for_reload("token").is_ok());
    }
}

// --- MCP Config ---

#[derive(Debug, Clone, Deserialize)]
pub struct McpConfig {
    /// Enable /mcp endpoint. Default: true.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// CORS allowed origins for browser-based MCP clients. Empty = CORS disabled.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// Default environment when MCP client omits it. Default: "development".
    #[serde(default = "default_environment")]
    pub default_environment: String,
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allowed_origins: vec![],
            default_environment: "development".into(),
        }
    }
}

fn default_environment() -> String {
    "development".into()
}
