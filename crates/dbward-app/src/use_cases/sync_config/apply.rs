use dbward_domain::entities::{Webhook, WebhookFormat, WebhookStatus};
use dbward_domain::policies::{DeliveryMode, ExecutionPolicy, NotificationPolicy, ResultPolicy};
use dbward_domain::values::{DatabaseName, Environment, Selector};

use crate::error::AppError;

use super::{
    DatabaseInput, ExecutionPolicyInput, GroupInput, NotificationPolicyInput, ResultPolicyInput,
    RoleBindingInput, RoleInput, SyncConfig, UserInput, WebhookInput, WorkflowInput,
};

impl SyncConfig {
    pub(super) fn sync_databases(
        &self,
        inputs: Vec<DatabaseInput>,
    ) -> Result<(u64, u64), AppError> {
        let deleted = self.database_registry.delete_by_source("config")?;
        let mut inserted = 0u64;
        for db in &inputs {
            for env in &db.environments {
                let db_name = DatabaseName::new(&db.name)
                    .map_err(|e| AppError::Validation(format!("database name: {e}")))?;
                let environment = Environment::new(env)
                    .map_err(|e| AppError::Validation(format!("environment: {e}")))?;
                self.database_registry.register(&db_name, &environment)?;
                inserted += 1;
            }
        }
        // License check: count unique database names (not db+env pairs)
        let all = self.database_registry.list()?;
        let unique_names: std::collections::HashSet<_> = all.iter().map(|(name, _)| name).collect();
        let total = unique_names.len() as u32;
        if total > self.license_checker.max_databases() {
            return Err(AppError::Validation(format!(
                "database limit exceeded (max {}, have {total})",
                self.license_checker.max_databases()
            )));
        }
        Ok((deleted, inserted))
    }

    pub(super) fn sync_users(&self, inputs: Vec<UserInput>) -> Result<(u64, u64), AppError> {
        let deleted = self.user_repo.delete_by_source("config")?;
        let mut inserted = 0u64;
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
            inserted += 1;
        }
        Ok((deleted, inserted))
    }

    pub(super) fn sync_groups(&self, inputs: Vec<GroupInput>) -> Result<(u64, u64), AppError> {
        let deleted = self.group_repo.delete_by_source("config")?;
        let mut inserted = 0u64;
        for g in &inputs {
            self.group_repo.create(&g.name, &g.members, "config")?;
            inserted += 1;
        }
        Ok((deleted, inserted))
    }

    pub(super) fn sync_roles(&self, inputs: Vec<RoleInput>) -> Result<(u64, u64), AppError> {
        let deleted = self.policy_repo.delete_roles_by_source("config")?;
        let mut inserted = 0u64;
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
            inserted += 1;
        }
        Ok((deleted, inserted))
    }

    pub(super) fn sync_role_bindings(
        &self,
        inputs: Vec<RoleBindingInput>,
    ) -> Result<(u64, u64), AppError> {
        let deleted = self.role_binding_repo.delete_by_source("config")?;
        let mut inserted = 0u64;
        for (i, rb) in inputs.iter().enumerate() {
            let id = format!("rb-{i}");
            self.role_binding_repo
                .create(&id, &rb.role, &rb.subjects, &rb.groups, "config")?;
            inserted += 1;
        }
        Ok((deleted, inserted))
    }

    pub fn sync_webhooks(&self, webhooks: Vec<WebhookInput>) -> Result<(u64, u64), AppError> {
        // Validate all webhooks BEFORE deleting
        let mut parsed = Vec::with_capacity(webhooks.len());
        let now = self.clock.now();
        for wh in webhooks.iter() {
            // SSRF check on webhook URL
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

        let deleted = self.webhook_repo.delete_by_source("config")?;
        // TODO(CFG-24): Remove config-wh-{i} cleanup after v0.1.6 (legacy IDs)
        for i in 0..100 {
            let _ = self.webhook_repo.delete(&format!("config-wh-{i}"));
        }

        for webhook in &parsed {
            self.webhook_repo.create(webhook)?;
        }
        Ok((deleted, parsed.len() as u64))
    }

    pub fn sync_workflows(&self, workflows: Vec<WorkflowInput>) -> Result<(u64, u64), AppError> {
        // Validate all workflows BEFORE deleting
        let mut parsed = Vec::with_capacity(workflows.len());
        for (i, wf) in workflows.iter().enumerate() {
            let id = format!("wf-{i}");
            let workflow = super::convert::parse_workflow(&id, wf)?;
            parsed.push(workflow);
        }

        let deleted = self.policy_repo.delete_workflows_by_source("config")?;
        // TODO(CFG-24): Remove config-wf-{i} cleanup after v0.1.6 (legacy IDs)
        for i in 0..100 {
            let _ = self.policy_repo.delete_workflow(&format!("config-wf-{i}"));
        }

        for workflow in &parsed {
            self.policy_repo.create_workflow(workflow)?;
        }
        Ok((deleted, parsed.len() as u64))
    }

    pub fn sync_execution_policies(
        &self,
        policies: Vec<ExecutionPolicyInput>,
    ) -> Result<(u64, u64), AppError> {
        // Validate all BEFORE deleting
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

            let defaults = ExecutionPolicy::default();
            parsed.push(ExecutionPolicy {
                id: format!("ep-{i}"),
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

        // Validate all policies (timeout constraints etc.)
        for (i, policy) in parsed.iter().enumerate() {
            policy
                .validate()
                .map_err(|e| AppError::Validation(format!("execution_policy[{i}]: {e}")))?;
        }

        let deleted = self
            .policy_repo
            .delete_execution_policies_by_source("config")?;
        // TODO(CFG-24): Remove config-ep-{i} cleanup after v0.1.6 (legacy IDs)
        for i in 0..100 {
            let _ = self
                .policy_repo
                .delete_execution_policy(&format!("config-ep-{i}"));
        }

        for policy in &parsed {
            self.policy_repo.create_execution_policy(policy)?;
        }
        Ok((deleted, parsed.len() as u64))
    }

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

            parsed.push(ResultPolicy {
                id: format!("rp-{i}"),
                database,
                environment,
                retention_days: rp.retention_days,
                delivery_mode,
                access,
                created_at: None,
                updated_at: None,
            });
        }

        let deleted = self
            .policy_repo
            .delete_result_policies_by_source("config")?;
        for policy in &parsed {
            self.policy_repo.create_result_policy(policy)?;
        }
        Ok((deleted, parsed.len() as u64))
    }

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
            parsed.push(NotificationPolicy {
                id: format!("np-{i}"),
                database,
                environment,
                webhooks: np.webhooks.clone(),
                events: np.events.clone(),
            });
        }

        let deleted = self
            .policy_repo
            .delete_notification_policies_by_source("config")?;
        for policy in &parsed {
            self.policy_repo.create_notification_policy(policy)?;
        }
        Ok((deleted, parsed.len() as u64))
    }
}
