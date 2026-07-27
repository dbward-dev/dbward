use std::collections::{HashMap, HashSet};
use std::path::Path;

use serde::Deserialize;

use crate::ConfigError;
use crate::diagnostics::{audit_env_vars, env_issues_to_validation_issues};
use crate::expand::expand_env_vars;
use crate::validation::{ValidationIssue, ValidationSeverity};

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
    #[serde(default, deserialize_with = "deserialize_sql_review")]
    pub sql_review: Vec<SqlReviewEntry>,
    #[serde(default)]
    pub auto_approve: Vec<serde_json::Value>,
    #[serde(default)]
    pub slack: Option<SlackConfig>,
    #[serde(default)]
    pub mcp: McpConfig,
    #[serde(default)]
    pub preflight: Option<PreflightConfig>,
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
        check_deprecated_fields(&expanded, source)?;
        let cfg: Self = toml::from_str(&expanded).map_err(|e| ConfigError::Parse {
            path: source.to_string(),
            message: e.to_string(),
        })?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Parse from TOML string without full auth-connection validation (for reload).
    pub fn parse_for_reload(input: &str, source: &str) -> Result<Self, ConfigError> {
        let expanded = expand_env_vars(input)?;
        check_deprecated_fields(&expanded, source)?;
        let cfg: Self = toml::from_str(&expanded).map_err(|e| ConfigError::Parse {
            path: source.to_string(),
            message: e.to_string(),
        })?;
        cfg.validate_for_reload()?;
        Ok(cfg)
    }

    /// Resolve effective auth mode based on OIDC presence.
    pub fn effective_auth_mode(&self) -> &str {
        if self.auth.oidc.is_some() {
            "both"
        } else {
            "token"
        }
    }

    /// Reload validation: skips OIDC connection checks (restart-only).
    /// Validates role_mappings when [auth.oidc] is present (config correctness always enforced).
    pub fn validate_for_reload(&self) -> Result<(), ConfigError> {
        self.validate_common()?;
        // Validate role_mappings when OIDC section is present
        if self.auth.oidc.is_some() {
            self.validate_oidc_role_mappings()?;
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), ConfigError> {
        self.validate_common()?;
        self.validate_auth_connection()?;
        if self.auth.oidc.is_some() {
            self.validate_oidc_role_mappings()?;
        }
        Ok(())
    }

    fn validate_auth_connection(&self) -> Result<(), ConfigError> {
        // OIDC config field validation (only when section is present)
        if let Some(ref oidc) = self.auth.oidc {
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
        let builtin_roles: std::collections::HashSet<&str> = [
            "admin",
            "requester",
            "approver",
            "operator",
            "agent-default",
        ]
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

        // Legacy [[auto_approve]] rejection
        if !self.auto_approve.is_empty() {
            return Err(ConfigError::Validation(
                "[[auto_approve]] is no longer supported. \
                 Move auto_approve settings into [workflows.auto_approve]. \
                 See: docs/guides/policies/auto-approve.md"
                    .into(),
            ));
        }

        // Workflow auto_approve validation
        for (i, wf) in self.workflows.iter().enumerate() {
            // Count only supported step types (Unknown steps are ignored at runtime)
            let supported_steps_count = wf.steps.iter().filter(|s| s.step_type.is_supported()).count();
            
            if wf.auto_approve.is_none() && supported_steps_count == 0 {
                return Err(ConfigError::Validation(format!(
                    "workflows[{i}]: must have [workflows.auto_approve], [[workflows.steps]], or both"
                )));
            }
            if let Some(AutoApproveDef::Always) = &wf.auto_approve
                && supported_steps_count > 0
            {
                return Err(ConfigError::Validation(format!(
                    "workflows[{i}]: mode = \"always\" makes steps unreachable — \
                     remove [[workflows.steps]] or use mode = \"risk_based\""
                )));
            }
            if let Some(AutoApproveDef::RiskBased { risk, .. }) = &wf.auto_approve {
                if supported_steps_count == 0 {
                    return Err(ConfigError::Validation(format!(
                        "workflows[{i}]: risk_based auto_approve without steps has no fallback — \
                         add [[workflows.steps]] or use mode = \"always\""
                    )));
                }
                if !["low", "medium", "high"].contains(&risk.as_str()) {
                    return Err(ConfigError::Validation(format!(
                        "workflows[{i}].auto_approve.risk: unknown value '{risk}' (expected: low, medium, high)"
                    )));
                }
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
                "both" | "stream" => {}
                other => {
                    return Err(ConfigError::Validation(format!(
                        "result_policies[{i}].delivery_mode: unknown value '{other}' (expected: both, stream)"
                    )));
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
        let builtin_roles: HashSet<&str> = [
            "admin",
            "requester",
            "approver",
            "operator",
            "agent-default",
        ]
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
                // Format: "perm_name" or "perm_name:ownership" (own|any)
                let (perm_part, ownership_part) = if let Some(idx) = perm.rfind(':') {
                    let (p, o) = perm.split_at(idx);
                    (p, Some(&o[1..]))
                } else {
                    (perm.as_str(), None)
                };

                // Validate the permission part
                let parsed = perm_part.parse::<dbward_domain::auth::Permission>();
                if parsed.is_err() {
                    return Err(ConfigError::Validation(format!(
                        "auth.roles[{}]: unknown permission '{}'",
                        rc.name, perm
                    )));
                }

                // Validate ownership suffix if present
                if let Some(ownership) = ownership_part {
                    // Wildcard `*` implies Any; explicit ownership suffix is not allowed
                    if parsed.unwrap() == dbward_domain::auth::Permission::All {
                        return Err(ConfigError::Validation(format!(
                            "auth.roles[{}]: permission '*' cannot have an ownership suffix (it is implicitly 'any')",
                            rc.name
                        )));
                    }
                    if ownership != "own" && ownership != "any" {
                        return Err(ConfigError::Validation(format!(
                            "auth.roles[{}]: invalid ownership '{}' in '{}' (expected 'own' or 'any')",
                            rc.name, ownership, perm
                        )));
                    }
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
        let all_defined_roles: HashSet<&str> = builtin_roles
            .iter()
            .copied()
            .chain(custom_role_names.iter().copied())
            .collect();
        let mut group_names: HashSet<&str> = HashSet::new();
        for gc in &self.auth.groups {
            if !group_names.insert(gc.name.as_str()) {
                return Err(ConfigError::Validation(format!(
                    "auth.groups: duplicate group name '{}'",
                    gc.name
                )));
            }
            if gc.roles.is_empty() {
                return Err(ConfigError::Validation(format!(
                    "auth.groups[{}]: roles cannot be empty",
                    gc.name
                )));
            }
            for role in &gc.roles {
                if !all_defined_roles.contains(role.as_str()) {
                    return Err(ConfigError::Validation(format!(
                        "auth.groups[{}]: role '{}' is not defined in auth.roles or built-in",
                        gc.name, role
                    )));
                }
            }
        }

        // default_role must reference defined roles
        if let Some(ref default) = self.auth.default_role
            && !all_defined_roles.contains(default.as_str())
        {
            return Err(ConfigError::Validation(format!(
                "auth.default_role: role '{}' is not defined in auth.roles or built-in",
                default
            )));
        }

        // sql_review: (database, environment) uniqueness + reserved word + rule value validation
        {
            let valid_actions = ["block", "warn", "off"];
            let mut sr_scopes: HashSet<(String, String)> = HashSet::new();
            for (i, sr) in self.sql_review.iter().enumerate() {
                if sr.database == "any" || sr.environment == "any" {
                    return Err(ConfigError::Validation(format!(
                        "sql_review[{i}]: 'any' is reserved (use '*' for wildcard)"
                    )));
                }
                let scope = (sr.database.clone(), sr.environment.clone());
                if !sr_scopes.insert(scope) {
                    return Err(ConfigError::Validation(format!(
                        "sql_review[{i}]: duplicate scope (database='{}', environment='{}')",
                        sr.database, sr.environment
                    )));
                }
                let rules: &[(&str, &str)] = &[
                    ("no_where_delete", &sr.no_where_delete),
                    ("no_where_update", &sr.no_where_update),
                    ("drop_table", &sr.drop_table),
                    ("drop_column", &sr.drop_column),
                    ("drop_index", &sr.drop_index),
                    ("drop_view", &sr.drop_view),
                    ("drop_sequence", &sr.drop_sequence),
                    ("create_sequence", &sr.create_sequence),
                    ("not_null_without_default", &sr.not_null_without_default),
                    (
                        "create_index_not_concurrently",
                        &sr.create_index_not_concurrently,
                    ),
                    ("alter_column_type", &sr.alter_column_type),
                    ("truncate", &sr.truncate),
                    ("mixed_ddl_dml", &sr.mixed_ddl_dml),
                    ("large_in_list", &sr.large_in_list),
                ];
                for (field, value) in rules {
                    if !valid_actions.contains(value) {
                        return Err(ConfigError::Validation(format!(
                            "sql_review[{i}].{field}: invalid value '{}' (expected: block, warn, off)",
                            value
                        )));
                    }
                }
            }
        }

        Ok(())
    }

    // ========================================
    // Diagnostics API (collect all issues)
    // ========================================

    /// Static diagnostics: all issues without early exit.
    ///
    /// Includes: env var audit + deprecated fields check + parse + semantic validation.
    /// Used by: validate subcommand, doctor
    ///
    /// # Arguments
    /// * `raw_content` - Raw TOML content (before env var expansion)
    /// * `source` - Source identifier for error messages (e.g., file path)
    pub fn diagnose_static(raw_content: &str, source: &str) -> DiagnosticsResult {
        let mut issues = Vec::new();

        // Phase 1: Raw env var audit (before expansion)
        let env_issues = audit_env_vars(raw_content);
        issues.extend(env_issues_to_validation_issues(&env_issues));

        // Phase 2a: Expand env vars
        let expanded = match expand_env_vars(raw_content) {
            Ok(s) => s,
            Err(e) => {
                // Expansion error - add as issue and return early (can't parse)
                issues.push(ValidationIssue::error("env_expand", e.to_string()));
                return DiagnosticsResult {
                    config: None,
                    issues,
                };
            }
        };

        // Phase 2b: Check deprecated fields (collect as issues, don't fail)
        if let Err(e) = check_deprecated_fields(&expanded, source) {
            issues.push(ValidationIssue::error("deprecated_field", e.to_string()));
            // Continue - we can still try to parse
        }

        // Phase 2c: Parse TOML
        let cfg: Self = match toml::from_str(&expanded) {
            Ok(c) => c,
            Err(e) => {
                issues.push(ValidationIssue::error(
                    "toml_parse",
                    format!("{source}: {e}"),
                ));
                return DiagnosticsResult {
                    config: None,
                    issues,
                };
            }
        };

        // Phase 3: Semantic validation (collect issues)
        cfg.validate_collecting(&mut issues);

        DiagnosticsResult {
            config: Some(cfg),
            issues,
        }
    }

    /// Validate and collect issues (for diagnose_static).
    /// This mirrors validate_common() but collects issues instead of failing fast.
    fn validate_collecting(&self, issues: &mut Vec<ValidationIssue>) {
        // retention.approval_ttl_secs
        if self.retention.approval_ttl_secs == 0 {
            issues.push(ValidationIssue::error(
                "approval_ttl",
                "retention.approval_ttl_secs must be > 0 (immediate expiry makes approval impossible)",
            ));
        }

        // Workflow operations overlap
        self.validate_workflow_operations_overlap(issues);

        // Legacy [[auto_approve]] rejection
        if !self.auto_approve.is_empty() {
            issues.push(ValidationIssue::error(
                "legacy_auto_approve",
                "[[auto_approve]] is no longer supported. Move auto_approve settings into [workflows.auto_approve]. See: docs/guides/policies/auto-approve.md",
            ));
        }

        // Workflow auto_approve validation
        self.validate_workflow_auto_approve(issues);

        // Webhook validation
        self.validate_webhooks(issues);

        // Notification policy validation
        self.validate_notification_policies(issues);

        // Result policy validation
        self.validate_result_policies(issues);

        // Execution policy validation
        self.validate_execution_policies(issues);

        // Auth validation
        self.validate_auth(issues);

        // SQL review validation
        self.validate_sql_review(issues);

        // OIDC role mappings (if OIDC is configured)
        if self.auth.oidc.is_some() {
            self.validate_oidc_role_mappings_collecting(issues);
        }

        // Auth connection (OIDC config fields)
        self.validate_auth_connection_collecting(issues);

        // ========================================
        // Warning-level checks
        // ========================================

        // Workflow step types: warn if unknown step types are used
        self.validate_workflow_step_types(issues);

        // Workflow coverage: check if all registered DB×env have a matching workflow
        self.validate_workflow_coverage(issues);

        // Workflow refs: check if workflow db/env references exist in databases
        self.validate_workflow_refs(issues);

        // SQL review safety: warn if destructive DDL rules are disabled in production
        self.validate_sql_review_safety(issues);
    }

    /// Warn if unknown step types are used (forward compatibility).
    fn validate_workflow_step_types(&self, issues: &mut Vec<ValidationIssue>) {
        for (wf_idx, wf) in self.workflows.iter().enumerate() {
            for (step_idx, step) in wf.steps.iter().enumerate() {
                if !step.step_type.is_supported() {
                    issues.push(
                        ValidationIssue::warning(
                            "workflow_step_type_unknown",
                            format!(
                                "workflows[{wf_idx}].steps[{step_idx}]: unknown step type (only 'approval' is currently supported)"
                            ),
                        )
                        .with_hint("This step will be ignored at runtime"),
                    );
                }
            }
        }
    }

    fn validate_workflow_operations_overlap(&self, issues: &mut Vec<ValidationIssue>) {
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
                issues.push(ValidationIssue::error(
                    "workflow_operations_overlap",
                    format!(
                        "workflow validation: database={db}, environment={env} has both catchall (operations omitted) and specific operations workflows — ambiguous"
                    ),
                ));
            }
            let mut seen: HashSet<&str> = HashSet::new();
            for (idx, ops) in entries {
                for op in ops {
                    if !seen.insert(op.as_str()) {
                        issues.push(ValidationIssue::error(
                            "workflow_operations_overlap",
                            format!(
                                "workflow validation: operation '{op}' appears in multiple workflows for database={db}, environment={env} (workflow index {idx})"
                            ),
                        ));
                    }
                }
            }
        }
    }

    fn validate_workflow_auto_approve(&self, issues: &mut Vec<ValidationIssue>) {
        for (i, wf) in self.workflows.iter().enumerate() {
            // Count only supported step types (Unknown steps are ignored at runtime)
            let supported_steps_count = wf.steps.iter().filter(|s| s.step_type.is_supported()).count();
            
            if wf.auto_approve.is_none() && supported_steps_count == 0 {
                issues.push(ValidationIssue::error(
                    "workflow_missing_approval",
                    format!("workflows[{i}]: must have [workflows.auto_approve], [[workflows.steps]], or both"),
                ));
            }
            if let Some(AutoApproveDef::Always) = &wf.auto_approve
                && supported_steps_count > 0
            {
                issues.push(ValidationIssue::error(
                    "workflow_unreachable_steps",
                    format!("workflows[{i}]: mode = \"always\" makes steps unreachable — remove [[workflows.steps]] or use mode = \"risk_based\""),
                ));
            }
            if let Some(AutoApproveDef::RiskBased { risk, .. }) = &wf.auto_approve {
                if supported_steps_count == 0 {
                    issues.push(ValidationIssue::error(
                        "workflow_missing_fallback",
                        format!("workflows[{i}]: risk_based auto_approve without steps has no fallback — add [[workflows.steps]] or use mode = \"always\""),
                    ));
                }
                if !["low", "medium", "high"].contains(&risk.as_str()) {
                    issues.push(ValidationIssue::error(
                        "workflow_invalid_risk",
                        format!("workflows[{i}].auto_approve.risk: unknown value '{risk}' (expected: low, medium, high)"),
                    ));
                }
            }
        }
    }

    fn validate_webhooks(&self, issues: &mut Vec<ValidationIssue>) {
        let id_re = regex::Regex::new(r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?$").unwrap();
        let mut seen_ids: HashSet<&str> = HashSet::new();
        for (i, wh) in self.webhooks.iter().enumerate() {
            if wh.id.is_empty() {
                let suggestion = slug_from_url(&wh.url);
                issues.push(
                    ValidationIssue::error(
                        "webhook_id_missing",
                        format!("webhooks[{i}] is missing required 'id' field"),
                    )
                    .with_hint(format!("suggested: id = \"{suggestion}\"")),
                );
            } else {
                if wh.id.len() > 64 {
                    issues.push(ValidationIssue::error(
                        "webhook_id_too_long",
                        format!("webhooks[{i}].id '{}' exceeds 64 characters", wh.id),
                    ));
                }
                if !id_re.is_match(&wh.id) {
                    issues.push(ValidationIssue::error(
                        "webhook_id_format",
                        format!("webhooks[{i}].id '{}' must match [a-z0-9][a-z0-9\\-]*", wh.id),
                    ));
                }
                if !seen_ids.insert(wh.id.as_str()) {
                    issues.push(ValidationIssue::error(
                        "webhook_id_duplicate",
                        format!("webhooks[{i}].id '{}' is duplicated", wh.id),
                    ));
                }
            }
        }
    }

    fn validate_notification_policies(&self, issues: &mut Vec<ValidationIssue>) {
        let webhook_ids: HashSet<&str> = self.webhooks.iter().map(|w| w.id.as_str()).collect();
        for (i, np) in self.notification_policies.iter().enumerate() {
            for wh_id in &np.webhooks {
                if !webhook_ids.contains(wh_id.as_str()) {
                    issues.push(ValidationIssue::error(
                        "notification_webhook_ref",
                        format!(
                            "notification_policies[{i}].webhooks: '{}' does not match any [[webhooks]].id",
                            wh_id
                        ),
                    ));
                }
            }
        }
    }

    fn validate_result_policies(&self, issues: &mut Vec<ValidationIssue>) {
        for (i, rp) in self.result_policies.iter().enumerate() {
            match rp.delivery_mode.as_str() {
                "both" | "stream" => {}
                other => {
                    issues.push(ValidationIssue::error(
                        "result_policy_delivery_mode",
                        format!(
                            "result_policies[{i}].delivery_mode: unknown value '{other}' (expected: both, stream)"
                        ),
                    ));
                }
            }
        }
    }

    fn validate_execution_policies(&self, issues: &mut Vec<ValidationIssue>) {
        for (i, ep) in self.execution_policies.iter().enumerate() {
            if ep.max_executions == Some(0) {
                issues.push(ValidationIssue::error(
                    "execution_policy_max",
                    format!("execution_policies[{i}]: max_executions must be >= 1"),
                ));
            }
            if let (Some(st), Some(max_st)) =
                (ep.statement_timeout_secs, ep.max_statement_timeout_secs)
                && st > max_st
            {
                issues.push(ValidationIssue::error(
                    "execution_policy_timeout",
                    format!("execution_policies[{i}]: statement_timeout_secs must not exceed max_statement_timeout_secs"),
                ));
            }
            if let (Some(mig_st), Some(max_st)) = (
                ep.migration_statement_timeout_secs,
                ep.max_statement_timeout_secs,
            ) && mig_st > 0
                && mig_st > max_st
            {
                issues.push(ValidationIssue::error(
                    "execution_policy_migration_timeout",
                    format!("execution_policies[{i}]: migration_statement_timeout_secs must not exceed max_statement_timeout_secs"),
                ));
            }
        }
    }

    fn validate_auth(&self, issues: &mut Vec<ValidationIssue>) {
        let builtin_roles: HashSet<&str> = [
            "admin",
            "requester",
            "approver",
            "operator",
            "agent-default",
        ]
        .into_iter()
        .collect();
        let mut custom_role_names: HashSet<&str> = HashSet::new();

        // Custom role definitions
        for rc in &self.auth.roles {
            if builtin_roles.contains(rc.name.as_str()) {
                issues.push(ValidationIssue::error(
                    "role_builtin_collision",
                    format!("auth.roles: '{}' is a built-in role and cannot be redefined", rc.name),
                ));
            }
            if !custom_role_names.insert(rc.name.as_str()) {
                issues.push(ValidationIssue::error(
                    "role_duplicate",
                    format!("auth.roles: duplicate role name '{}'", rc.name),
                ));
            }
            if rc.permissions.is_empty() {
                issues.push(ValidationIssue::error(
                    "role_no_permissions",
                    format!("auth.roles[{}]: permissions cannot be empty", rc.name),
                ));
            }
            for perm in &rc.permissions {
                self.validate_permission(rc.name.as_str(), perm, issues);
            }
            for db in &rc.databases {
                if db != "*" && dbward_domain::values::DatabaseName::new(db).is_err() {
                    issues.push(ValidationIssue::error(
                        "role_invalid_database",
                        format!("auth.roles[{}]: invalid database name '{}'", rc.name, db),
                    ));
                }
            }
            for env in &rc.environments {
                if env != "*" && dbward_domain::values::Environment::new(env).is_err() {
                    issues.push(ValidationIssue::error(
                        "role_invalid_environment",
                        format!("auth.roles[{}]: invalid environment name '{}'", rc.name, env),
                    ));
                }
            }
        }

        // Group definitions
        let all_defined_roles: HashSet<&str> = builtin_roles
            .iter()
            .copied()
            .chain(custom_role_names.iter().copied())
            .collect();
        let mut group_names: HashSet<&str> = HashSet::new();
        for gc in &self.auth.groups {
            if !group_names.insert(gc.name.as_str()) {
                issues.push(ValidationIssue::error(
                    "group_duplicate",
                    format!("auth.groups: duplicate group name '{}'", gc.name),
                ));
            }
            if gc.roles.is_empty() {
                issues.push(ValidationIssue::error(
                    "group_no_roles",
                    format!("auth.groups[{}]: roles cannot be empty", gc.name),
                ));
            }
            for role in &gc.roles {
                if !all_defined_roles.contains(role.as_str()) {
                    issues.push(ValidationIssue::error(
                        "group_role_ref",
                        format!(
                            "auth.groups[{}]: role '{}' is not defined in auth.roles or built-in",
                            gc.name, role
                        ),
                    ));
                }
            }
        }

        // default_role must reference defined roles
        if let Some(ref default) = self.auth.default_role
            && !all_defined_roles.contains(default.as_str())
        {
            issues.push(ValidationIssue::error(
                "default_role_ref",
                format!(
                    "auth.default_role: role '{}' is not defined in auth.roles or built-in",
                    default
                ),
            ));
        }
    }

    fn validate_permission(&self, role_name: &str, perm: &str, issues: &mut Vec<ValidationIssue>) {
        let (perm_part, ownership_part) = if let Some(idx) = perm.rfind(':') {
            let (p, o) = perm.split_at(idx);
            (p, Some(&o[1..]))
        } else {
            (perm, None)
        };

        let parsed = perm_part.parse::<dbward_domain::auth::Permission>();
        if parsed.is_err() {
            issues.push(ValidationIssue::error(
                "role_unknown_permission",
                format!("auth.roles[{}]: unknown permission '{}'", role_name, perm),
            ));
            return;
        }

        if let Some(ownership) = ownership_part {
            if parsed.unwrap() == dbward_domain::auth::Permission::All {
                issues.push(ValidationIssue::error(
                    "role_permission_ownership",
                    format!(
                        "auth.roles[{}]: permission '*' cannot have an ownership suffix (it is implicitly 'any')",
                        role_name
                    ),
                ));
            } else if ownership != "own" && ownership != "any" {
                issues.push(ValidationIssue::error(
                    "role_invalid_ownership",
                    format!(
                        "auth.roles[{}]: invalid ownership '{}' in '{}' (expected 'own' or 'any')",
                        role_name, ownership, perm
                    ),
                ));
            }
        }
    }

    fn validate_sql_review(&self, issues: &mut Vec<ValidationIssue>) {
        let valid_actions = ["block", "warn", "off"];
        let mut sr_scopes: HashSet<(String, String)> = HashSet::new();
        for (i, sr) in self.sql_review.iter().enumerate() {
            if sr.database == "any" || sr.environment == "any" {
                issues.push(ValidationIssue::error(
                    "sql_review_reserved",
                    format!("sql_review[{i}]: 'any' is reserved (use '*' for wildcard)"),
                ));
            }
            let scope = (sr.database.clone(), sr.environment.clone());
            if !sr_scopes.insert(scope) {
                issues.push(ValidationIssue::error(
                    "sql_review_duplicate",
                    format!(
                        "sql_review[{i}]: duplicate scope (database='{}', environment='{}')",
                        sr.database, sr.environment
                    ),
                ));
            }
            let rules: &[(&str, &str)] = &[
                ("no_where_delete", &sr.no_where_delete),
                ("no_where_update", &sr.no_where_update),
                ("drop_table", &sr.drop_table),
                ("drop_column", &sr.drop_column),
                ("drop_index", &sr.drop_index),
                ("drop_view", &sr.drop_view),
                ("drop_sequence", &sr.drop_sequence),
                ("create_sequence", &sr.create_sequence),
                ("not_null_without_default", &sr.not_null_without_default),
                ("create_index_not_concurrently", &sr.create_index_not_concurrently),
                ("alter_column_type", &sr.alter_column_type),
                ("truncate", &sr.truncate),
                ("mixed_ddl_dml", &sr.mixed_ddl_dml),
                ("large_in_list", &sr.large_in_list),
            ];
            for (field, value) in rules {
                if !valid_actions.contains(value) {
                    issues.push(ValidationIssue::error(
                        "sql_review_invalid_action",
                        format!(
                            "sql_review[{i}].{field}: invalid value '{}' (expected: block, warn, off)",
                            value
                        ),
                    ));
                }
            }
        }
    }

    fn validate_oidc_role_mappings_collecting(&self, issues: &mut Vec<ValidationIssue>) {
        let builtin_roles: HashSet<&str> = [
            "admin",
            "requester",
            "approver",
            "operator",
            "agent-default",
        ]
        .into_iter()
        .collect();
        let custom: HashSet<&str> = self.auth.roles.iter().map(|r| r.name.as_str()).collect();
        let all_roles: HashSet<&str> = builtin_roles
            .iter()
            .copied()
            .chain(custom.iter().copied())
            .collect();

        if let Some(ref oidc) = self.auth.oidc {
            for mapping in &oidc.role_mappings {
                if !all_roles.contains(mapping.role.as_str()) {
                    issues.push(ValidationIssue::error(
                        "oidc_role_mapping_ref",
                        format!(
                            "auth.oidc.role_mappings: role '{}' is not defined in auth.roles or built-in",
                            mapping.role
                        ),
                    ));
                }
            }
        }
    }

    fn validate_auth_connection_collecting(&self, issues: &mut Vec<ValidationIssue>) {
        if let Some(ref oidc) = self.auth.oidc {
            let issuer = oidc.issuer_url.trim();
            if issuer.is_empty() {
                issues.push(ValidationIssue::error(
                    "oidc_issuer_empty",
                    "auth.oidc.issuer_url cannot be empty",
                ));
            } else if !issuer.starts_with("http://") && !issuer.starts_with("https://") {
                issues.push(ValidationIssue::error(
                    "oidc_issuer_scheme",
                    format!("auth.oidc.issuer_url: must start with http:// or https://, got '{issuer}'"),
                ));
            }

            if let Some(ref jwks) = oidc.jwks_uri {
                let jwks_trimmed = jwks.trim();
                if jwks_trimmed.is_empty() {
                    issues.push(ValidationIssue::error(
                        "oidc_jwks_empty",
                        "auth.oidc.jwks_uri: cannot be empty (omit the field to use default)",
                    ));
                } else if !jwks_trimmed.starts_with("http://") && !jwks_trimmed.starts_with("https://") {
                    issues.push(ValidationIssue::error(
                        "oidc_jwks_scheme",
                        format!("auth.oidc.jwks_uri: must start with http:// or https://, got '{jwks_trimmed}'"),
                    ));
                }
            }

            let has_client_id = oidc
                .client_id
                .as_deref()
                .is_some_and(|s| !s.trim().is_empty());
            let has_audience = !oidc.audience.trim().is_empty();
            if !has_client_id && !has_audience {
                issues.push(ValidationIssue::error(
                    "oidc_no_audience",
                    "auth.oidc: at least one of client_id or audience must be non-empty",
                ));
            }
        }
    }

    // ========================================
    // Warning-level checks (for diagnose_static)
    // ========================================

    /// Check if all registered DB×env pairs have a matching workflow.
    /// Uncovered pairs will reject all requests (fail-closed).
    fn validate_workflow_coverage(&self, issues: &mut Vec<ValidationIssue>) {
        use crate::validation::CoverageEntry;

        if self.databases.is_empty() || self.workflows.is_empty() {
            return; // Other checks handle these cases
        }

        let mut coverage_entries = Vec::new();
        let mut gap_count = 0usize;
        let mut total_pairs = 0usize;

        for db in &self.databases {
            if db.name == "*" {
                continue; // Skip wildcard databases
            }
            for env in &db.environments {
                if env == "*" {
                    continue; // Skip wildcard environments
                }
                total_pairs += 1;

                // Find best matching workflow using specificity score
                let matched = self
                    .workflows
                    .iter()
                    .filter(|wf| {
                        Self::workflow_covers_scope(
                            wf.database.as_str(),
                            wf.environment.as_str(),
                            db.name.as_str(),
                            env.as_str(),
                        )
                    })
                    .max_by_key(|wf| {
                        let mut score = 0u8;
                        if wf.environment != "*" && wf.environment == *env {
                            score += 4;
                        }
                        if wf.database != "*" && wf.database == db.name {
                            score += 2;
                        }
                        score
                    });

                let (workflow_label, auto_approve_label) = match matched {
                    Some(wf) => {
                        let wf_label = format!("({},{})", wf.database, wf.environment);
                        let aa_label = match &wf.auto_approve {
                            Some(AutoApproveDef::Always) => Some("always".to_string()),
                            Some(AutoApproveDef::RiskBased { risk, .. }) => {
                                Some(format!("risk_based({risk})"))
                            }
                            None => None,
                        };
                        (Some(wf_label), aa_label)
                    }
                    None => {
                        gap_count += 1;
                        (None, None)
                    }
                };

                coverage_entries.push(CoverageEntry {
                    database: db.name.clone(),
                    environment: env.clone(),
                    workflow: workflow_label,
                    auto_approve: auto_approve_label,
                });
            }
        }

        if gap_count > 0 && gap_count < total_pairs {
            // Some but not all pairs are uncovered -> Warning
            issues.push(
                ValidationIssue::warning(
                    "workflow_coverage",
                    format!("{gap_count} of {total_pairs} DB×env pairs have no workflow"),
                )
                .with_hint("Uncovered pairs will reject all requests (fail-closed)")
                .with_context(crate::validation::IssueContext::WorkflowCoverage(
                    coverage_entries,
                )),
            );
        } else if gap_count == total_pairs && total_pairs > 0 {
            // All pairs uncovered -> Error (this is more serious)
            issues.push(
                ValidationIssue::error(
                    "workflow_coverage",
                    format!("all {gap_count} DB×env pairs have no workflow"),
                )
                .with_hint("Add [[workflows]] matching your databases")
                .with_context(crate::validation::IssueContext::WorkflowCoverage(
                    coverage_entries,
                )),
            );
        }
        // If gap_count == 0, all covered -> no issue
    }

    /// Check if a workflow pattern covers a specific (db, env) pair.
    fn workflow_covers_scope(wf_db: &str, wf_env: &str, db: &str, env: &str) -> bool {
        let db_match = wf_db == "*" || wf_db == db;
        let env_match = wf_env == "*" || wf_env == env;
        db_match && env_match
    }

    /// Check if workflow db/env references exist in registered databases.
    /// Dead workflows (referencing non-existent db/env) are warnings unless all are dead.
    fn validate_workflow_refs(&self, issues: &mut Vec<ValidationIssue>) {
        use crate::validation::InvalidWorkflowEntry;

        if self.workflows.is_empty() {
            // No workflows defined -> Error (fail-closed)
            issues.push(
                ValidationIssue::error(
                    "workflow_refs",
                    "no workflows defined — all requests will be rejected (fail-closed)",
                )
                .with_hint("Add [[workflows]] sections"),
            );
            return;
        }

        // Build set of all registered (db, env) pairs
        let mut registered_pairs: HashSet<(&str, &str)> = HashSet::new();
        for db in &self.databases {
            for env in &db.environments {
                registered_pairs.insert((db.name.as_str(), env.as_str()));
            }
        }
        let registered_dbs: HashSet<&str> =
            self.databases.iter().map(|d| d.name.as_str()).collect();

        let mut dead_entries = Vec::new();

        for (i, wf) in self.workflows.iter().enumerate() {
            // Wildcard db/env always valid
            if wf.database == "*" && wf.environment == "*" {
                continue;
            }

            let workflow_name = format!("({},{})", wf.database, wf.environment);

            // Check database
            if wf.database != "*" && !registered_dbs.contains(wf.database.as_str()) {
                dead_entries.push(InvalidWorkflowEntry {
                    workflow_index: i,
                    workflow_name: workflow_name.clone(),
                    reason: format!("database '{}' not registered", wf.database),
                });
                continue;
            }

            // Check environment (if both are concrete)
            if wf.database != "*"
                && wf.environment != "*"
                && !registered_pairs.contains(&(wf.database.as_str(), wf.environment.as_str()))
            {
                dead_entries.push(InvalidWorkflowEntry {
                    workflow_index: i,
                    workflow_name,
                    reason: format!(
                        "environment '{}' not in database '{}'",
                        wf.environment, wf.database
                    ),
                });
                continue;
            }

            // workflow with db=* but env=concrete: check if ANY db has that env
            if wf.database == "*" && wf.environment != "*" {
                let env_exists = self
                    .databases
                    .iter()
                    .any(|db| db.environments.iter().any(|e| e == &wf.environment));
                if !env_exists {
                    dead_entries.push(InvalidWorkflowEntry {
                        workflow_index: i,
                        workflow_name,
                        reason: format!(
                            "environment '{}' not found in any database",
                            wf.environment
                        ),
                    });
                }
            }
        }

        if !dead_entries.is_empty() {
            if dead_entries.len() == self.workflows.len() {
                // All workflows are dead -> Error
                issues.push(
                    ValidationIssue::error(
                        "workflow_refs",
                        format!(
                            "all {} workflows reference unregistered databases/environments",
                            dead_entries.len()
                        ),
                    )
                    .with_hint("Add [[databases]] for referenced databases")
                    .with_context(crate::validation::IssueContext::InvalidWorkflows(
                        dead_entries,
                    )),
                );
            } else {
                // Some workflows are dead -> Warning
                let dead_names: Vec<_> = dead_entries
                    .iter()
                    .map(|e| format!("workflows[{}]", e.workflow_index))
                    .collect();
                issues.push(
                    ValidationIssue::warning(
                        "workflow_refs",
                        format!("{} dead workflow(s): {}", dead_entries.len(), dead_names.join(", ")),
                    )
                    .with_context(crate::validation::IssueContext::InvalidWorkflows(
                        dead_entries,
                    )),
                );
            }
        }
    }

    /// Warn if destructive DDL rules (drop_table, truncate) are disabled in production scope.
    fn validate_sql_review_safety(&self, issues: &mut Vec<ValidationIssue>) {
        use crate::validation::SqlReviewSafetyEntry;

        let mut warnings = Vec::new();

        for sr in &self.sql_review {
            // Check if this is a production scope
            if sr.environment == "*" || sr.environment.contains("prod") {
                if sr.drop_table == "off" {
                    warnings.push(SqlReviewSafetyEntry {
                        database: sr.database.clone(),
                        environment: sr.environment.clone(),
                        rule: "drop_table=off".to_string(),
                    });
                }
                if sr.truncate == "off" {
                    warnings.push(SqlReviewSafetyEntry {
                        database: sr.database.clone(),
                        environment: sr.environment.clone(),
                        rule: "truncate=off".to_string(),
                    });
                }
            }
        }

        if !warnings.is_empty() {
            issues.push(
                ValidationIssue::warning(
                    "sql_review_safety",
                    format!(
                        "{} dangerous sql_review setting(s) detected in production scope",
                        warnings.len()
                    ),
                )
                .with_hint(
                    "Disabling drop_table or truncate rules in production reduces safety guarantees",
                )
                .with_context(crate::validation::IssueContext::SqlReviewSafety(warnings)),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Diagnostics Result
// ---------------------------------------------------------------------------

/// Result of static configuration diagnostics.
///
/// Contains both the parsed config (if parsing succeeded) and all validation issues.
#[derive(Debug)]
pub struct DiagnosticsResult {
    /// Parsed config, if TOML parsing and basic structure were valid.
    /// May be `Some` even when there are semantic errors.
    pub config: Option<ServerConfig>,
    /// All validation issues (errors and warnings).
    pub issues: Vec<ValidationIssue>,
}

impl DiagnosticsResult {
    /// Returns true if there are any Error-level issues.
    pub fn has_errors(&self) -> bool {
        self.issues
            .iter()
            .any(|i| i.severity == ValidationSeverity::Error)
    }

    /// Returns an iterator over Warning-level issues only.
    pub fn warnings(&self) -> impl Iterator<Item = &ValidationIssue> {
        self.issues
            .iter()
            .filter(|i| i.severity == ValidationSeverity::Warning)
    }

    /// Returns true if the config was successfully parsed.
    pub fn is_parseable(&self) -> bool {
        self.config.is_some()
    }
}

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
    #[serde(default)]
    pub oidc: Option<OidcConfig>,
    pub default_role: Option<String>,
    #[serde(default)]
    pub roles: Vec<RoleConfig>,
    #[serde(default)]
    pub groups: Vec<GroupConfig>,
    #[serde(default)]
    pub token_policy: TokenPolicyConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TokenPolicyConfig {
    /// Maximum number of active tokens per user/agent subject.
    /// Default: 5. Set to 0 for unlimited.
    #[serde(default = "TokenPolicyConfig::default_max_active")]
    pub max_active_tokens_per_user: u32,
}

impl Default for TokenPolicyConfig {
    fn default() -> Self {
        Self {
            max_active_tokens_per_user: 5,
        }
    }
}

impl TokenPolicyConfig {
    fn default_max_active() -> u32 {
        5
    }
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
    pub roles: Vec<String>,
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

#[derive(Debug, Deserialize)]
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

impl Default for ResultStorageConfig {
    fn default() -> Self {
        Self {
            backend: default_backend(),
            root_dir: None,
            bucket: None,
            region: None,
            endpoint: None,
            access_key_id: None,
            secret_access_key: None,
            path_style: false,
            prefix: default_result_prefix(),
            max_persist_bytes: default_max_persist_bytes(),
        }
    }
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
    pub auto_approve: Option<AutoApproveDef>,
    #[serde(default)]
    pub steps: Vec<WorkflowStepDef>,
    #[serde(default)]
    pub require_reason: bool,
    #[serde(default)]
    pub allow_self_approve: bool,
    #[serde(default)]
    pub allow_same_approver_across_steps: bool,
    #[serde(default = "default_true")]
    pub explain: bool,
    #[serde(default)]
    pub pending_ttl_secs: Option<u64>,
    #[serde(default)]
    pub statement_timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum AutoApproveDef {
    Always,
    RiskBased {
        risk: String,
        #[serde(default = "default_allow_read_only")]
        allow_read_only: bool,
        #[serde(default = "default_allow_safe_ddl")]
        allow_safe_ddl: bool,
        #[serde(default = "default_max_estimated_rows")]
        max_estimated_rows: i64,
    },
}

// ============================================================================
// Validated workflow step types (output of validation)
// ============================================================================

/// Validated workflow step definition.
///
/// This is the output type after parsing and validating raw TOML steps.
/// Used by both `ServerConfig` (after validation) and for conversion to domain types.
///
/// Note: `step_type` is kept for forward compatibility. Currently only "approval"
/// is implemented. Unknown types are parsed but will produce a warning.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct WorkflowStepDef {
    /// Step type. Currently only "approval" is supported.
    #[serde(rename = "type", default)]
    pub step_type: WorkflowStepType,
    #[serde(default)]
    pub mode: WorkflowStepModeDef,
    #[serde(default)]
    pub approvers: Vec<ApproverDef>,
}

/// Workflow step type.
///
/// Currently only `Approval` is implemented. Unknown types are accepted
/// for forward compatibility but will produce a warning during validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WorkflowStepType {
    /// Human approval step (default).
    #[default]
    Approval,
    /// Unknown step type (for forward compatibility).
    Unknown(()),
}

impl WorkflowStepType {
    /// Check if this is a known, supported step type.
    pub fn is_supported(&self) -> bool {
        matches!(self, Self::Approval)
    }

    /// Get the string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Approval => "approval",
            Self::Unknown(_) => "unknown",
        }
    }
}

impl<'de> serde::Deserialize<'de> for WorkflowStepType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(match s.to_lowercase().as_str() {
            "approval" => Self::Approval,
            _ => Self::Unknown(()),
        })
    }
}

/// Workflow step approval mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowStepModeDef {
    /// All approvers must approve.
    #[default]
    All,
    /// Any one approver is sufficient.
    Any,
}

// Note: WorkflowStepModeDef doesn't need from_str - serde handles deserialization.

/// Validated approver definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApproverDef {
    pub selector_type: ApproverSelectorType,
    pub value: String,
    pub min: Option<u32>,
}

impl<'de> serde::Deserialize<'de> for ApproverDef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        #[derive(Deserialize)]
        struct RawApprover {
            role: Option<String>,
            group: Option<String>,
            user: Option<String>,
            min: Option<u32>,
        }

        let raw = RawApprover::deserialize(deserializer)?;

        let (selector_type, value) = match (&raw.role, &raw.group, &raw.user) {
            (Some(r), None, None) => (ApproverSelectorType::Role, r.clone()),
            (None, Some(g), None) => (ApproverSelectorType::Group, g.clone()),
            (None, None, Some(u)) => (ApproverSelectorType::User, u.clone()),
            (None, None, None) => {
                return Err(D::Error::custom(
                    "approver must have one of: role, group, user",
                ));
            }
            _ => {
                return Err(D::Error::custom(
                    "approver must have exactly one of: role, group, user",
                ));
            }
        };

        Ok(ApproverDef {
            selector_type,
            value,
            min: raw.min,
        })
    }
}

/// Type of approver selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApproverSelectorType {
    Role,
    Group,
    User,
}

impl ApproverSelectorType {
    /// Convert to string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Role => "role",
            Self::Group => "group",
            Self::User => "user",
        }
    }
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

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct SqlReviewEntry {
    #[serde(default = "star")]
    pub database: String,
    #[serde(default = "star")]
    pub environment: String,
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
    #[serde(default = "default_warn")]
    pub drop_index: String,
    #[serde(default = "default_warn")]
    pub drop_view: String,
    #[serde(default = "default_warn")]
    pub drop_sequence: String,
    #[serde(default = "default_off")]
    pub create_sequence: String,
}

/// Legacy trap: catches old [sql_review] table form and gives helpful error.
fn deserialize_sql_review<'de, D>(deserializer: D) -> Result<Vec<SqlReviewEntry>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;

    // Deserialize raw value first, then try to interpret it.
    let raw = serde_json::Value::deserialize(deserializer)?;

    // If it's an array, it's the new [[sql_review]] format — deserialize strictly.
    if raw.is_array() {
        let entries: Vec<SqlReviewEntry> = serde_json::from_value(raw)
            .map_err(|e| serde::de::Error::custom(format!("sql_review: {e}")))?;
        return Ok(entries);
    }

    // If it's an object (table), it's the legacy [sql_review] format.
    if raw.is_object() {
        return Err(serde::de::Error::custom(
            "sql_review: use [[sql_review]] (array of tables), not [sql_review]",
        ));
    }

    Err(serde::de::Error::custom(
        "sql_review: expected array ([[sql_review]]) or table ([sql_review])",
    ))
}

fn default_block() -> String {
    "block".into()
}

fn default_warn() -> String {
    "warn".into()
}

fn default_off() -> String {
    "off".into()
}

fn default_allow_read_only() -> bool {
    true
}
fn default_allow_safe_ddl() -> bool {
    true
}
fn default_max_estimated_rows() -> i64 {
    1000
}

#[derive(Debug, Deserialize)]
pub struct SlackConfig {
    pub bot_token: String,
    pub signing_secret: String,
    #[serde(default = "default_slack_channel")]
    pub channel: String,
    #[serde(default)]
    pub onboarding: Option<SlackOnboardingConfig>,
}

/// Configuration for Slack-based user onboarding (/dbward join).
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct SlackOnboardingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub assignable_roles: Vec<String>,
    #[serde(default)]
    pub assignable_groups: Vec<String>,
    #[serde(default)]
    pub restricted_roles: Vec<String>,
    #[serde(default = "default_request_ttl_hours")]
    pub request_ttl_hours: u64,
}

fn default_request_ttl_hours() -> u64 {
    72
}

fn default_slack_channel() -> String {
    "#db-approvals".into()
}

/// Detect deprecated config fields before deserialization.
/// serde silently ignores unknown fields, so we parse as raw TOML Value first.
fn check_deprecated_fields(toml_str: &str, source: &str) -> Result<(), ConfigError> {
    let raw: toml::Value = toml::from_str(toml_str).map_err(|e| ConfigError::Parse {
        path: source.to_string(),
        message: e.to_string(),
    })?;
    let table = match raw.as_table() {
        Some(t) => t,
        None => return Ok(()),
    };

    if table.contains_key("users") {
        return Err(ConfigError::Validation(
            "[[users]] is no longer supported. Use `dbward user add` to manage users via API/CLI."
                .into(),
        ));
    }

    if let Some(auth) = table.get("auth").and_then(|v| v.as_table()) {
        if auth.contains_key("role_bindings") {
            return Err(ConfigError::Validation(
                "[[auth.role_bindings]] is no longer supported. \
                 Roles are now assigned directly via `dbward user add --role` or through [[auth.groups]].roles."
                    .into(),
            ));
        }
        if let Some(groups) = auth.get("groups").and_then(|v| v.as_array()) {
            for (i, g) in groups.iter().enumerate() {
                if g.as_table().is_some_and(|t| t.contains_key("members")) {
                    return Err(ConfigError::Validation(format!(
                        "auth.groups[{i}].members is no longer supported. \
                         Use `dbward user add --group` to manage group membership via API/CLI."
                    )));
                }
            }
        }
    }

    Ok(())
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

[workflows.auto_approve]
mode = "always"
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
    fn rejects_legacy_auto_approve() {
        let toml = test_cfg(
            r#"
[[auto_approve]]
database = "app"
environment = "dev"
"#,
        );
        let err = ServerConfig::from_str(&toml, "test").unwrap_err();
        assert!(err.to_string().contains("no longer supported"));
    }

    #[test]
    fn rejects_always_with_steps() {
        let toml = test_cfg(
            r#"
[[workflows]]
database = "*"
environment = "*"
[workflows.auto_approve]
mode = "always"
[[workflows.steps]]
type = "approval"
[[workflows.steps.approvers]]
role = "admin"
min = 1
"#,
        );
        let err = ServerConfig::from_str(&toml, "test").unwrap_err();
        assert!(err.to_string().contains("steps unreachable"));
    }

    #[test]
    fn rejects_risk_based_without_steps() {
        let toml = test_cfg(
            r#"
[[workflows]]
database = "*"
environment = "*"
[workflows.auto_approve]
mode = "risk_based"
risk = "low"
"#,
        );
        let err = ServerConfig::from_str(&toml, "test").unwrap_err();
        assert!(err.to_string().contains("no fallback"));
    }

    #[test]
    fn rejects_no_auto_approve_no_steps() {
        let toml = test_cfg(
            r#"
[[workflows]]
database = "*"
environment = "*"
"#,
        );
        let err = ServerConfig::from_str(&toml, "test").unwrap_err();
        assert!(err.to_string().contains("must have"));
    }

    #[test]
    fn rejects_invalid_risk_value() {
        let toml = test_cfg(
            r#"
[[workflows]]
database = "*"
environment = "*"
[workflows.auto_approve]
mode = "risk_based"
risk = "extreme"
[[workflows.steps]]
type = "approval"
[[workflows.steps.approvers]]
role = "admin"
min = 1
"#,
        );
        let err = ServerConfig::from_str(&toml, "test").unwrap_err();
        assert!(err.to_string().contains("unknown value"));
    }

    #[test]
    fn accepts_valid_risk_based() {
        let toml = test_cfg(
            r#"
[[workflows]]
database = "*"
environment = "*"
[workflows.auto_approve]
mode = "risk_based"
risk = "medium"
[[workflows.steps]]
type = "approval"
[[workflows.steps.approvers]]
role = "admin"
min = 1
"#,
        );
        ServerConfig::from_str(&toml, "test").unwrap();
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
delivery_mode = "both"
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

    #[test]
    fn sql_review_legacy_format_rejected() {
        let toml = test_cfg(
            r#"
[sql_review]
no_where_delete = "block"
"#,
        );
        let err = ServerConfig::from_str(&toml, "test").unwrap_err();
        assert!(err.to_string().contains("not [sql_review]"), "got: {}", err);
    }

    #[test]
    fn sql_review_reserved_word_any() {
        let toml = test_cfg(
            r#"
[[sql_review]]
database = "any"
"#,
        );
        let err = ServerConfig::from_str(&toml, "test").unwrap_err();
        assert!(err.to_string().contains("reserved"));
    }

    #[test]
    fn sql_review_duplicate_scope() {
        let toml = test_cfg(
            r#"
[[sql_review]]
database = "app"
environment = "prod"

[[sql_review]]
database = "app"
environment = "prod"
"#,
        );
        let err = ServerConfig::from_str(&toml, "test").unwrap_err();
        assert!(err.to_string().contains("duplicate scope"));
    }

    #[test]
    fn sql_review_invalid_action() {
        let toml = test_cfg(
            r#"
[[sql_review]]
drop_table = "yolo"
"#,
        );
        let err = ServerConfig::from_str(&toml, "test").unwrap_err();
        assert!(err.to_string().contains("invalid value"));
    }

    #[test]
    fn sql_review_unknown_field_rejected() {
        let toml = test_cfg(
            r#"
[[sql_review]]
drop_tables = "block"
"#,
        );
        let err = ServerConfig::from_str(&toml, "test").unwrap_err();
        assert!(err.to_string().contains("unknown field"), "got: {}", err);
    }

    // ========================================
    // diagnose_static tests
    // ========================================

    #[test]
    fn diagnose_static_valid_config() {
        let toml = test_cfg(
            r#"
[[databases]]
name = "app"
environments = ["dev"]

[[workflows]]
database = "*"
environment = "*"

[workflows.auto_approve]
mode = "always"
"#,
        );
        let result = ServerConfig::diagnose_static(&toml, "test");
        assert!(result.is_parseable());
        assert!(!result.has_errors());
    }

    #[test]
    fn diagnose_static_collects_multiple_errors() {
        let toml = test_cfg(
            r#"
[retention]
approval_ttl_secs = 0

[[workflows]]
database = "*"
environment = "*"
"#,
        );
        let result = ServerConfig::diagnose_static(&toml, "test");
        // Should parse but have errors
        assert!(result.is_parseable());
        assert!(result.has_errors());
        // Should have at least two errors: approval_ttl and workflow missing approval
        let error_ids: Vec<_> = result
            .issues
            .iter()
            .filter(|i| i.is_error())
            .map(|i| i.id)
            .collect();
        assert!(error_ids.contains(&"approval_ttl"));
        assert!(error_ids.contains(&"workflow_missing_approval"));
    }

    #[test]
    fn diagnose_static_parse_error() {
        let toml = "state_dir = \"/tmp\"\n[invalid toml syntax";
        let result = ServerConfig::diagnose_static(toml, "test");
        assert!(!result.is_parseable());
        assert!(result.has_errors());
        assert!(result
            .issues
            .iter()
            .any(|i| i.id == "toml_parse"));
    }

    #[test]
    fn diagnose_static_workflow_coverage_warning() {
        // Database "app" has "dev" and "prod", but workflow only covers "*"+"dev"
        let toml = test_cfg(
            r#"
[[databases]]
name = "app"
environments = ["dev", "prod"]

[[workflows]]
database = "*"
environment = "dev"

[workflows.auto_approve]
mode = "always"
"#,
        );
        let result = ServerConfig::diagnose_static(&toml, "test");
        assert!(result.is_parseable());
        // Should have a warning for uncovered "prod"
        let warnings: Vec<_> = result.warnings().collect();
        assert!(
            warnings.iter().any(|w| w.id == "workflow_coverage"),
            "expected workflow_coverage warning, got: {:?}",
            warnings
        );
    }

    #[test]
    fn diagnose_static_workflow_refs_warning() {
        // Workflow references non-existent database
        let toml = test_cfg(
            r#"
[[databases]]
name = "app"
environments = ["dev"]

[[workflows]]
database = "nonexistent"
environment = "*"

[workflows.auto_approve]
mode = "always"

[[workflows]]
database = "*"
environment = "*"

[workflows.auto_approve]
mode = "always"
"#,
        );
        let result = ServerConfig::diagnose_static(&toml, "test");
        assert!(result.is_parseable());
        // Should have a warning for dead workflow
        let warnings: Vec<_> = result.warnings().collect();
        assert!(
            warnings.iter().any(|w| w.id == "workflow_refs"),
            "expected workflow_refs warning, got: {:?}",
            warnings
        );
    }

    #[test]
    fn diagnose_static_workflow_refs_all_dead_error() {
        // All workflows reference non-existent databases -> Error
        let toml = test_cfg(
            r#"
[[databases]]
name = "app"
environments = ["dev"]

[[workflows]]
database = "nonexistent"
environment = "*"

[workflows.auto_approve]
mode = "always"
"#,
        );
        let result = ServerConfig::diagnose_static(&toml, "test");
        assert!(result.is_parseable());
        // Should have an error since all workflows are dead
        let errors: Vec<_> = result.issues.iter().filter(|i| i.is_error()).collect();
        assert!(
            errors.iter().any(|e| e.id == "workflow_refs"),
            "expected workflow_refs error, got: {:?}",
            errors
        );
    }

    #[test]
    fn diagnose_static_no_workflows_error() {
        // No workflows defined -> Error
        let toml = test_cfg(
            r#"
[[databases]]
name = "app"
environments = ["dev"]
"#,
        );
        let result = ServerConfig::diagnose_static(&toml, "test");
        assert!(result.is_parseable());
        let errors: Vec<_> = result.issues.iter().filter(|i| i.is_error()).collect();
        assert!(
            errors.iter().any(|e| e.id == "workflow_refs"),
            "expected workflow_refs error for no workflows, got: {:?}",
            errors
        );
    }

    #[test]
    fn diagnose_static_sql_review_safety_warning() {
        // Dangerous SQL review settings in production
        let toml = test_cfg(
            r#"
[[databases]]
name = "app"
environments = ["production"]

[[workflows]]
database = "*"
environment = "*"

[workflows.auto_approve]
mode = "always"

[[sql_review]]
environment = "production"
drop_table = "off"
truncate = "off"
"#,
        );
        let result = ServerConfig::diagnose_static(&toml, "test");
        assert!(result.is_parseable());
        let warnings: Vec<_> = result.warnings().collect();
        assert!(
            warnings.iter().any(|w| w.id == "sql_review_safety"),
            "expected sql_review_safety warning, got: {:?}",
            warnings
        );
    }

    #[test]
    fn workflow_step_type_approval_default() {
        let toml = test_cfg(
            r#"
[[databases]]
name = "app"
environments = ["dev"]

[[workflows]]
database = "*"
environment = "*"

[[workflows.steps]]
[[workflows.steps.approvers]]
role = "admin"
"#,
        );
        let cfg = ServerConfig::from_str(&toml, "test").unwrap();
        assert_eq!(cfg.workflows[0].steps[0].step_type, WorkflowStepType::Approval);
    }

    #[test]
    fn workflow_step_type_explicit_approval() {
        let toml = test_cfg(
            r#"
[[databases]]
name = "app"
environments = ["dev"]

[[workflows]]
database = "*"
environment = "*"

[[workflows.steps]]
type = "approval"
[[workflows.steps.approvers]]
role = "admin"
"#,
        );
        let cfg = ServerConfig::from_str(&toml, "test").unwrap();
        assert_eq!(cfg.workflows[0].steps[0].step_type, WorkflowStepType::Approval);
        assert!(cfg.workflows[0].steps[0].step_type.is_supported());
    }

    #[test]
    fn workflow_step_type_unknown_warns() {
        let toml = test_cfg(
            r#"
[[databases]]
name = "app"
environments = ["dev"]

[[workflows]]
database = "*"
environment = "*"

# Unknown step types require auto_approve since they're ignored at runtime
[workflows.auto_approve]
mode = "always"

[[workflows.steps]]
type = "future_type"
[[workflows.steps.approvers]]
role = "admin"
"#,
        );
        // Should parse successfully (auto_approve covers the workflow)
        let cfg = ServerConfig::from_str(&toml, "test").unwrap();
        assert!(!cfg.workflows[0].steps[0].step_type.is_supported());
        
        // diagnose_static should produce a warning for unknown step type
        let result = ServerConfig::diagnose_static(&toml, "test");
        assert!(result.is_parseable());
        let warnings: Vec<_> = result.warnings().collect();
        assert!(
            warnings.iter().any(|w| w.id == "workflow_step_type_unknown"),
            "expected workflow_step_type_unknown warning, got: {:?}",
            warnings
        );
    }
    
    #[test]
    fn workflow_unknown_step_only_without_auto_approve_errors() {
        let toml = test_cfg(
            r#"
[[databases]]
name = "app"
environments = ["dev"]

[[workflows]]
database = "*"
environment = "*"

[[workflows.steps]]
type = "future_type"
[[workflows.steps.approvers]]
role = "admin"
"#,
        );
        // Should fail: unknown step types are ignored, so effectively no steps
        let err = ServerConfig::from_str(&toml, "test").unwrap_err();
        assert!(err.to_string().contains("must have"));
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

[result_storage]
root_dir = "/tmp/r"

[[sql_review]]
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
permissions = ["request.dml", "request.view"]
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
permissions = ["request.dml"]

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
        // V25: [[auth.role_bindings]] is deprecated → startup error
        let err = parse(&base_config(
            r#"
[[auth.role_bindings]]
role = "ghost"
subjects = ["alice"]
"#,
        ))
        .unwrap_err();
        assert!(err.to_string().contains("no longer supported"));
    }

    #[test]
    fn valid_group_definition() {
        let cfg = parse(&base_config(
            r#"
[[auth.groups]]
name = "team-a"
roles = ["requester"]
"#,
        ))
        .unwrap();
        assert_eq!(cfg.auth.groups.len(), 1);
        assert_eq!(cfg.auth.groups[0].roles, vec!["requester"]);
    }

    #[test]
    fn reject_empty_group_roles() {
        let err = parse(&base_config(
            r#"
[[auth.groups]]
name = "empty-team"
roles = []
"#,
        ))
        .unwrap_err();
        assert!(err.to_string().contains("roles cannot be empty"));
    }

    #[test]
    fn reject_duplicate_group() {
        let err = parse(&base_config(
            r#"
[[auth.groups]]
name = "team"
roles = ["requester"]

[[auth.groups]]
name = "team"
roles = ["admin"]
"#,
        ))
        .unwrap_err();
        assert!(err.to_string().contains("duplicate group name"));
    }

    #[test]
    fn reject_undefined_role_in_group() {
        let err = parse(&base_config(
            r#"
[[auth.groups]]
name = "team"
roles = ["nonexistent"]
"#,
        ))
        .unwrap_err();
        assert!(err.to_string().contains("not defined"));
    }

    #[test]
    fn reject_deprecated_group_members() {
        let err = parse(&base_config(
            r#"
[[auth.groups]]
name = "team"
members = ["alice"]
"#,
        ))
        .unwrap_err();
        assert!(err.to_string().contains("members is no longer supported"));
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
    fn no_oidc_effective_mode_is_token() {
        let cfg = parse("").unwrap();
        assert_eq!(cfg.effective_auth_mode(), "token");
    }

    #[test]
    fn oidc_present_effective_mode_is_both() {
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
    fn mode_field_is_silently_ignored() {
        let cfg = parse("[auth]\nmode = \"token\"\n").unwrap();
        assert_eq!(cfg.effective_auth_mode(), "token");
    }

    #[test]
    fn oidc_issuer_empty_rejected() {
        let err = parse(
            r#"
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
    fn oidc_section_with_valid_config_accepted() {
        let cfg = parse(
            r#"
[auth.oidc]
issuer_url = "https://auth.example.com/realms/test"
audience = "dbward"
"#,
        )
        .unwrap();
        assert_eq!(cfg.effective_auth_mode(), "both");
    }

    #[test]
    fn validate_for_reload_validates_role_mappings_when_oidc_present() {
        let full = r#"
state_dir = "/tmp"
[auth.oidc]
issuer_url = "https://auth.example.com"
audience = "dbward"
[[auth.oidc.role_mappings]]
claim = "groups"
value = "admins"
role = "nonexistent_role"
"#;
        let expanded = crate::expand::expand_env_vars(full).unwrap();
        let cfg: ServerConfig = toml::from_str(&expanded).unwrap();
        let err = cfg.validate_for_reload().unwrap_err();
        assert!(err.to_string().contains("nonexistent_role"));
    }

    #[test]
    fn validate_for_reload_skips_role_mappings_when_no_oidc() {
        let full = "state_dir = \"/tmp\"\n[auth]\ndefault_role = \"requester\"\n";
        let expanded = crate::expand::expand_env_vars(full).unwrap();
        let cfg: ServerConfig = toml::from_str(&expanded).unwrap();
        assert!(cfg.validate_for_reload().is_ok());
    }

    #[test]
    fn parse_for_reload_ignores_mode_field() {
        let full = "state_dir = \"/tmp\"\n[auth]\nmode = \"token\"\n";
        let cfg = ServerConfig::parse_for_reload(full, "test").unwrap();
        assert_eq!(cfg.effective_auth_mode(), "token");
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
    /// Session TTL in seconds. Default: 3600 (1 hour).
    #[serde(default)]
    pub session_ttl_secs: Option<u64>,
    /// Maximum concurrent sessions. Default: 1000.
    #[serde(default)]
    pub max_sessions: Option<usize>,
    /// Elicitation response timeout in seconds. Default: 300 (5 min).
    #[serde(default)]
    pub elicitation_timeout_secs: Option<u64>,
    /// Max events per stream replay buffer. Default: 100.
    #[serde(default)]
    pub replay_buffer_size: Option<usize>,
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allowed_origins: vec![],
            default_environment: "development".into(),
            session_ttl_secs: None,
            max_sessions: None,
            elicitation_timeout_secs: None,
            replay_buffer_size: None,
        }
    }
}

fn default_environment() -> String {
    "development".into()
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PreflightConfig {
    pub max_concurrent_per_user: Option<u32>,
    pub max_explain_timeout_ms: Option<u64>,
    pub rate_limit_per_minute: Option<u32>,
}
