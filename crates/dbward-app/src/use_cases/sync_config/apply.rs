use dbward_domain::entities::{Webhook, WebhookFormat, WebhookStatus};
use dbward_domain::policies::{DeliveryMode, ExecutionPolicy, NotificationPolicy, ResultPolicy};
use dbward_domain::values::{DatabaseName, Environment, Selector};
use sha2::{Digest, Sha256};

use crate::error::AppError;

use super::{
    DatabaseInput, ExecutionPolicyInput, GroupInput, NotificationPolicyInput, ResultPolicyInput,
    RoleBindingInput, RoleInput, SyncConfig, UserInput, WebhookInput, WorkflowInput,
};

/// Generate a stable ID suffix from content via SHA-256 truncated to 12 hex chars.
fn sha_suffix(content: &str) -> String {
    let hash = Sha256::digest(content.as_bytes());
    hex::encode(&hash[..6])
}

impl SyncConfig {
    // ─────────────────────────────────────────────────────────────────────────
    // databases (StrongRuntime)
    // ─────────────────────────────────────────────────────────────────────────

    pub(super) fn sync_databases(
        &self,
        inputs: Vec<DatabaseInput>,
    ) -> Result<(u64, u64), AppError> {
        // 1. UPSERT all TOML entries
        let mut toml_ids = Vec::new();
        let mut upserted = 0u64;
        for db in &inputs {
            for env in &db.environments {
                let db_name = DatabaseName::new(&db.name)
                    .map_err(|e| AppError::Validation(format!("database name: {e}")))?;
                let environment = Environment::new(env)
                    .map_err(|e| AppError::Validation(format!("environment: {e}")))?;
                self.database_registry.register(&db_name, &environment)?;
                toml_ids.push(format!("{}:{}", db_name, environment));
                upserted += 1;
            }
        }

        // 2. Stale reconciliation (StrongRuntime): orphan if FK-referenced, delete otherwise
        let (orphaned, deleted) = self.database_registry.reconcile_stale(&toml_ids)?;

        // 3. License check (after reconcile so stale rows are removed/orphaned)
        let all = self.database_registry.list_active()?;
        let unique_names: std::collections::HashSet<_> = all.iter().map(|(name, _)| name).collect();
        let total = unique_names.len() as u32;
        if total > self.license_checker.max_databases() {
            return Err(AppError::Validation(format!(
                "database limit exceeded (max {}, have {total})",
                self.license_checker.max_databases()
            )));
        }

        Ok((orphaned + deleted, upserted))
    }

    // ─────────────────────────────────────────────────────────────────────────
    // users (AllowDangling)
    // ─────────────────────────────────────────────────────────────────────────

    pub(super) fn sync_users(&self, inputs: Vec<UserInput>) -> Result<(u64, u64), AppError> {
        let mut toml_ids = Vec::new();
        let mut upserted = 0u64;
        let now = self.clock.now();
        for u in &inputs {
            let status = match u.status.as_str() {
                "suspended" => dbward_domain::entities::UserStatus::Suspended,
                _ => dbward_domain::entities::UserStatus::Active,
            };
            let user = dbward_domain::entities::User {
                id: u.id.clone(),
                display_name: None,
                email: None,
                groups: vec![],
                roles: vec![],
                status,
                last_seen_at: None,
                created_at: now,
                updated_at: now,
            };
            self.user_repo.upsert(&user)?;
            self.user_repo.set_source(&u.id, "config")?;
            toml_ids.push(u.id.clone());
            upserted += 1;
        }
        // AllowDangling: unconditional delete of stale
        let deleted = self.user_repo.delete_stale_config(&toml_ids)?;
        Ok((deleted, upserted))
    }

    // ─────────────────────────────────────────────────────────────────────────
    // groups (AllowDangling)
    // ─────────────────────────────────────────────────────────────────────────

    pub(super) fn sync_groups(&self, inputs: Vec<GroupInput>) -> Result<(u64, u64), AppError> {
        let mut toml_ids = Vec::new();
        let mut upserted = 0u64;
        for g in &inputs {
            self.group_repo.create(&g.name, &g.members, "config")?;
            toml_ids.push(g.name.clone());
            upserted += 1;
        }
        let deleted = self.group_repo.delete_stale_config(&toml_ids)?;
        Ok((deleted, upserted))
    }

    // ─────────────────────────────────────────────────────────────────────────
    // roles (ValidatedInBatch)
    // ─────────────────────────────────────────────────────────────────────────

    pub(super) fn sync_roles(&self, inputs: Vec<RoleInput>) -> Result<(u64, u64), AppError> {
        let mut toml_ids = Vec::new();
        let mut upserted = 0u64;
        for r in &inputs {
            let perms: Vec<dbward_domain::auth::Permission> = r
                .permissions
                .iter()
                .map(|s| {
                    s.parse::<dbward_domain::auth::Permission>()
                        .map_err(|e| AppError::Validation(format!("role '{}': {e}", r.name)))
                })
                .collect::<Result<_, _>>()?;
            let databases = if r.databases.is_empty() {
                vec![DatabaseName::wildcard()]
            } else {
                r.databases
                    .iter()
                    .map(|d| {
                        if d == "*" {
                            Ok(DatabaseName::wildcard())
                        } else {
                            DatabaseName::new(d)
                                .map_err(|e| AppError::Validation(format!("role db: {e}")))
                        }
                    })
                    .collect::<Result<_, _>>()?
            };
            let environments = if r.environments.is_empty() {
                vec![Environment::wildcard()]
            } else {
                r.environments
                    .iter()
                    .map(|e| {
                        if e == "*" {
                            Ok(Environment::wildcard())
                        } else {
                            Environment::new(e)
                                .map_err(|e2| AppError::Validation(format!("role env: {e2}")))
                        }
                    })
                    .collect::<Result<_, _>>()?
            };
            let def = dbward_domain::auth::RoleDefinition {
                name: r.name.clone(),
                permissions: perms,
                databases,
                environments,
            };
            self.policy_repo.create_role(&def)?;
            toml_ids.push(r.name.clone());
            upserted += 1;
        }
        // ValidatedInBatch: delete stale roles (not in current TOML)
        self.policy_repo.delete_stale_config_roles(&toml_ids)?;
        Ok((0, upserted))
    }

    // ─────────────────────────────────────────────────────────────────────────
    // role_bindings (ValidatedInBatch)
    // ─────────────────────────────────────────────────────────────────────────

    pub(super) fn sync_role_bindings(
        &self,
        inputs: Vec<RoleBindingInput>,
    ) -> Result<(u64, u64), AppError> {
        let mut toml_ids = Vec::new();
        let mut upserted = 0u64;
        for rb in inputs.iter() {
            let id = make_role_binding_id(&rb.role, &rb.subjects, &rb.groups);
            self.role_binding_repo
                .create(&id, &rb.role, &rb.subjects, &rb.groups, "config")?;
            toml_ids.push(id);
            upserted += 1;
        }
        let deleted = self.role_binding_repo.delete_stale_config(&toml_ids)?;
        Ok((deleted, upserted))
    }

    // ─────────────────────────────────────────────────────────────────────────
    // webhooks (CancelDependents)
    // ─────────────────────────────────────────────────────────────────────────

    pub fn sync_webhooks(&self, webhooks: Vec<WebhookInput>) -> Result<(u64, u64), AppError> {
        let mut parsed = Vec::with_capacity(webhooks.len());
        let now = self.clock.now();
        for wh in webhooks.iter() {
            self.ssrf_validator
                .validate_url(&wh.url)
                .map_err(|e| AppError::Validation(format!("webhook '{}': {e}", wh.id)))?;
            let format = match wh.format.as_str() {
                "slack" => WebhookFormat::Slack,
                "generic" => WebhookFormat::Generic,
                other => {
                    return Err(AppError::Validation(format!(
                        "webhook: unknown format '{other}'"
                    )));
                }
            };
            parsed.push(Webhook {
                id: wh.id.clone(),
                url: wh.url.clone(),
                events: wh.events.clone(),
                format,
                secret: wh.secret.clone(),
                status: WebhookStatus::Active,
                created_at: Some(now),
                updated_at: Some(now),
            });
        }

        // UPSERT all webhooks
        for webhook in &parsed {
            self.webhook_repo.create(webhook)?;
        }

        // CancelDependents: delete stale webhooks
        let toml_ids: Vec<String> = parsed.iter().map(|w| w.id.clone()).collect();
        let deleted = self.webhook_repo.delete_stale_config(&toml_ids)?;
        Ok((deleted, parsed.len() as u64))
    }

    // ─────────────────────────────────────────────────────────────────────────
    // workflows (ValidatedInBatch)
    // ─────────────────────────────────────────────────────────────────────────

    pub fn sync_workflows(&self, workflows: Vec<WorkflowInput>) -> Result<(u64, u64), AppError> {
        let mut parsed = Vec::with_capacity(workflows.len());
        for wf in workflows.iter() {
            let id = make_workflow_id(&wf.database, &wf.environment, &wf.operations);
            let workflow = super::convert::parse_workflow(&id, wf)?;
            parsed.push(workflow);
        }

        // UPSERT (create_workflow uses ON CONFLICT DO UPDATE)
        for workflow in &parsed {
            self.policy_repo.create_workflow(workflow)?;
        }
        let toml_ids: Vec<String> = parsed.iter().map(|w| w.id.clone()).collect();
        let deleted = self.policy_repo.delete_stale_workflows(&toml_ids)?;
        Ok((deleted, parsed.len() as u64))
    }

    // ─────────────────────────────────────────────────────────────────────────
    // execution_policies (ValidatedInBatch)
    // ─────────────────────────────────────────────────────────────────────────

    pub fn sync_execution_policies(
        &self,
        policies: Vec<ExecutionPolicyInput>,
    ) -> Result<(u64, u64), AppError> {
        let mut parsed = Vec::with_capacity(policies.len());
        for (i, ep) in policies.iter().enumerate() {
            let database = if ep.database == "*" {
                DatabaseName::wildcard()
            } else {
                DatabaseName::new(&ep.database)
                    .map_err(|e| AppError::Validation(format!("execution_policy[{i}] db: {e}")))?
            };
            let environment = if ep.environment == "*" {
                Environment::wildcard()
            } else {
                Environment::new(&ep.environment)
                    .map_err(|e| AppError::Validation(format!("execution_policy[{i}] env: {e}")))?
            };

            let id = format!("ep:{}:{}", ep.database, ep.environment);
            let defaults = ExecutionPolicy::default();
            parsed.push(ExecutionPolicy {
                id,
                database,
                environment,
                max_executions: ep.max_executions.unwrap_or(defaults.max_executions),
                execution_window_secs: ep
                    .execution_window_secs
                    .unwrap_or(defaults.execution_window_secs),
                retry_on_failure: ep.retry_on_failure.unwrap_or(defaults.retry_on_failure),
                statement_timeout_secs: ep
                    .statement_timeout_secs
                    .unwrap_or(defaults.statement_timeout_secs),
                max_statement_timeout_secs: ep
                    .max_statement_timeout_secs
                    .unwrap_or(defaults.max_statement_timeout_secs),
                max_rows: ep.max_rows,
                migration_lease_duration_secs: ep.migration_lease_duration_secs,
                migration_statement_timeout_secs: ep.migration_statement_timeout_secs,
                created_at: None,
                updated_at: None,
            });
        }

        for (i, policy) in parsed.iter().enumerate() {
            policy
                .validate()
                .map_err(|e| AppError::Validation(format!("execution_policy[{i}]: {e}")))?;
        }

        for policy in &parsed {
            self.policy_repo.create_execution_policy(policy)?;
        }
        let toml_ids: Vec<String> = parsed.iter().map(|p| p.id.clone()).collect();
        let deleted = self
            .policy_repo
            .delete_stale_execution_policies(&toml_ids)?;
        Ok((deleted, parsed.len() as u64))
    }

    // ─────────────────────────────────────────────────────────────────────────
    // result_policies (ValidatedInBatch)
    // ─────────────────────────────────────────────────────────────────────────

    pub(super) fn sync_result_policies(
        &self,
        policies: Vec<ResultPolicyInput>,
    ) -> Result<(u64, u64), AppError> {
        let mut parsed = Vec::with_capacity(policies.len());
        for (i, rp) in policies.iter().enumerate() {
            let database = if rp.database == "*" {
                DatabaseName::wildcard()
            } else {
                DatabaseName::new(&rp.database)
                    .map_err(|e| AppError::Validation(format!("result_policy[{i}] db: {e}")))?
            };
            let environment = if rp.environment == "*" {
                Environment::wildcard()
            } else {
                Environment::new(&rp.environment)
                    .map_err(|e| AppError::Validation(format!("result_policy[{i}] env: {e}")))?
            };
            let delivery_mode = match rp.delivery_mode.as_str() {
                "store_only" => DeliveryMode::StoreOnly,
                "stream" => DeliveryMode::Stream,
                _ => DeliveryMode::Both,
            };
            let access = rp
                .access
                .iter()
                .map(|s| {
                    Selector::parse(s).map_err(|e| {
                        AppError::Validation(format!("result_policy[{i}].access: {e}"))
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;

            let id = format!("rp:{}:{}", rp.database, rp.environment);
            parsed.push(ResultPolicy {
                id,
                database,
                environment,
                retention_days: rp.retention_days,
                delivery_mode,
                access,
                created_at: None,
                updated_at: None,
            });
        }

        for policy in &parsed {
            self.policy_repo.create_result_policy(policy)?;
        }
        let toml_ids: Vec<String> = parsed.iter().map(|p| p.id.clone()).collect();
        let deleted = self.policy_repo.delete_stale_result_policies(&toml_ids)?;
        Ok((deleted, parsed.len() as u64))
    }

    // ─────────────────────────────────────────────────────────────────────────
    // notification_policies (ValidatedInBatch)
    // ─────────────────────────────────────────────────────────────────────────

    pub(super) fn sync_notification_policies(
        &self,
        policies: Vec<NotificationPolicyInput>,
    ) -> Result<(u64, u64), AppError> {
        let mut parsed = Vec::with_capacity(policies.len());
        for (i, np) in policies.iter().enumerate() {
            let database = if np.database == "*" {
                DatabaseName::wildcard()
            } else {
                DatabaseName::new(&np.database).map_err(|e| {
                    AppError::Validation(format!("notification_policy[{i}] db: {e}"))
                })?
            };
            let environment = if np.environment == "*" {
                Environment::wildcard()
            } else {
                Environment::new(&np.environment).map_err(|e| {
                    AppError::Validation(format!("notification_policy[{i}] env: {e}"))
                })?
            };
            let id = format!("np:{}:{}", np.database, np.environment);
            parsed.push(NotificationPolicy {
                id,
                database,
                environment,
                webhooks: np.webhooks.clone(),
                events: np.events.clone(),
            });
        }

        for policy in &parsed {
            self.policy_repo.create_notification_policy(policy)?;
        }
        let toml_ids: Vec<String> = parsed.iter().map(|p| p.id.clone()).collect();
        let deleted = self
            .policy_repo
            .delete_stale_notification_policies(&toml_ids)?;
        Ok((deleted, parsed.len() as u64))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Stable ID generation helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Workflow ID: `wf:{db}:{env}:{sha(sorted_ops)[..12]}`
fn make_workflow_id(database: &str, environment: &str, operations: &[String]) -> String {
    let mut sorted_ops = operations.to_vec();
    sorted_ops.sort();
    let ops_str = sorted_ops.join(",");
    format!("wf:{}:{}:{}", database, environment, sha_suffix(&ops_str))
}

/// RoleBinding ID: `rb:{role}:{sha(sorted_subjects+sorted_groups)[..12]}`
fn make_role_binding_id(role: &str, subjects: &[String], groups: &[String]) -> String {
    let mut sorted_subjects = subjects.to_vec();
    sorted_subjects.sort();
    sorted_subjects.dedup();
    let mut sorted_groups = groups.to_vec();
    sorted_groups.sort();
    sorted_groups.dedup();
    let content = format!("{},{}", sorted_subjects.join(","), sorted_groups.join(","));
    format!("rb:{}:{}", role, sha_suffix(&content))
}

// ---------------------------------------------------------------------------
// Schema Guardrail: REFERENCE_MAP (CFG-24)
// ---------------------------------------------------------------------------

/// Category for how stale config entries interact with their dependents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ReferenceCategory {
    StrongRuntime,
    CancelDependents,
    ValidatedInBatch,
    AllowDangling,
}

/// All known cross-table references (FK + logical) that affect config sync.
/// CI test verifies this list stays in sync with schema.rs.
#[allow(dead_code)]
pub const REFERENCE_MAP: &[(&str, &str, ReferenceCategory)] = &[
    (
        "requests.database_id",
        "databases",
        ReferenceCategory::StrongRuntime,
    ),
    (
        "webhook_deliveries.webhook_id",
        "webhooks",
        ReferenceCategory::CancelDependents,
    ),
    (
        "notification_policies.webhooks_json",
        "webhooks",
        ReferenceCategory::ValidatedInBatch,
    ),
    (
        "role_bindings.role",
        "roles",
        ReferenceCategory::ValidatedInBatch,
    ),
    (
        "requests.requester",
        "users",
        ReferenceCategory::AllowDangling,
    ),
    (
        "approvals.actor_id",
        "users",
        ReferenceCategory::AllowDangling,
    ),
];

#[cfg(test)]
mod reference_map_tests {
    use super::*;

    /// Ensure REFERENCE_MAP covers all REFERENCES clauses and known logical refs in schema.rs.
    #[test]
    fn reference_map_covers_all_fk_and_logical_refs() {
        let schema_source = include_str!("../../../../dbward-infra/src/sqlite/schema.rs");

        // All FK-referenced config-managed tables must appear as targets in REFERENCE_MAP
        let config_tables = ["databases", "webhooks", "roles", "users"];
        let map_targets: std::collections::HashSet<&str> =
            REFERENCE_MAP.iter().map(|(_, target, _)| *target).collect();

        for table in config_tables {
            assert!(
                map_targets.contains(table),
                "config table '{table}' is referenced but not in REFERENCE_MAP"
            );
        }

        // Known logical references must be present
        let map_sources: std::collections::HashSet<&str> =
            REFERENCE_MAP.iter().map(|(src, _, _)| *src).collect();
        let logical_refs = [
            "webhook_deliveries.webhook_id",
            "notification_policies.webhooks_json",
        ];
        for src in logical_refs {
            assert!(
                map_sources.contains(src),
                "logical reference '{src}' not in REFERENCE_MAP"
            );
        }

        // No stale entries: all tables referenced in REFERENCE_MAP must exist in schema
        for (src, target, _) in REFERENCE_MAP {
            let src_table = src.split('.').next().unwrap();
            assert!(
                schema_source.contains(&format!("CREATE TABLE IF NOT EXISTS {src_table}")),
                "REFERENCE_MAP source table '{src_table}' not found in schema"
            );
            assert!(
                schema_source.contains(&format!("CREATE TABLE IF NOT EXISTS {target}")),
                "REFERENCE_MAP target table '{target}' not found in schema"
            );
        }
    }
}
