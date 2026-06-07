use std::sync::Arc;

use dbward_domain::entities::{Webhook, WebhookFormat, WebhookStatus};
use dbward_domain::policies::{
    ApproverGroup, DeliveryMode, ExecutionPolicy, NotificationPolicy, ResultPolicy, Workflow,
    WorkflowStep, WorkflowStepMode,
};
use dbward_domain::values::{DatabaseName, Environment, Operation, Selector};

use crate::error::AppError;
use crate::ports::{
    Clock, DatabaseRegistry, GroupRepo, IdGenerator, LicenseChecker, Notifier, PolicyRepo,
    RoleBindingRepo, SsrfValidator, UserRepo, WebhookRepo,
};

/// Provides transaction semantics for config sync.
pub trait SyncTransaction: Send + Sync {
    fn begin(&self) -> Result<(), AppError>;
    fn commit(&self) -> Result<(), AppError>;
    fn rollback(&self) -> Result<(), AppError>;
}

/// All dependencies needed for config sync.
pub struct SyncConfig {
    pub policy_repo: Arc<dyn PolicyRepo>,
    pub webhook_repo: Arc<dyn WebhookRepo>,
    pub database_registry: Arc<dyn DatabaseRegistry>,
    pub user_repo: Arc<dyn UserRepo>,
    pub group_repo: Arc<dyn GroupRepo>,
    pub role_binding_repo: Arc<dyn RoleBindingRepo>,
    pub notifier: Arc<dyn Notifier>,
    pub clock: Arc<dyn Clock>,
    pub id_gen: Arc<dyn IdGenerator>,
    pub transaction: Arc<dyn SyncTransaction>,
    pub license_checker: Arc<dyn LicenseChecker>,
    pub ssrf_validator: Arc<dyn SsrfValidator>,
}

// --- Input DTOs ---

pub struct WorkflowInput {
    pub database: String,
    pub environment: String,
    pub operations: Vec<String>,
    pub steps: Vec<WorkflowStepInput>,
    pub require_reason: bool,
    pub allow_self_approve: bool,
    pub allow_same_approver_across_steps: bool,
    pub explain: bool,
    pub pending_ttl_secs: Option<u64>,
    pub statement_timeout_secs: Option<u64>,
}

pub struct WorkflowStepInput {
    pub mode: String,
    pub approvers: Vec<ApproverInput>,
}

pub struct ApproverInput {
    pub selector_type: String,
    pub value: String,
    pub min: u32,
}

pub struct WebhookInput {
    pub id: String,
    pub url: String,
    pub events: Vec<String>,
    pub format: String,
    pub secret: Option<String>,
}

pub struct ExecutionPolicyInput {
    pub database: String,
    pub environment: String,
    pub max_executions: Option<u32>,
    pub execution_window_secs: Option<u64>,
    pub retry_on_failure: Option<bool>,
    pub statement_timeout_secs: Option<u32>,
    pub max_statement_timeout_secs: Option<u32>,
    pub max_rows: Option<u32>,
    pub migration_lease_duration_secs: Option<u32>,
    pub migration_statement_timeout_secs: Option<u32>,
}

pub struct ResultPolicyInput {
    pub database: String,
    pub environment: String,
    pub retention_days: u32,
    pub delivery_mode: String,
    pub access: Vec<String>,
}

pub struct NotificationPolicyInput {
    pub database: String,
    pub environment: String,
    pub webhooks: Vec<String>,
    pub events: Vec<String>,
}

pub struct DatabaseInput {
    pub name: String,
    pub environments: Vec<String>,
}

pub struct UserInput {
    pub id: String,
    pub status: String,
}

pub struct GroupInput {
    pub name: String,
    pub members: Vec<String>,
}

pub struct RoleBindingInput {
    pub role: String,
    pub subjects: Vec<String>,
    pub groups: Vec<String>,
}

pub struct RoleInput {
    pub name: String,
    pub permissions: Vec<String>,
    pub databases: Vec<String>,
    pub environments: Vec<String>,
}

/// Diff summary for audit logging.
#[derive(Debug, Default)]
pub struct SyncSummary {
    pub databases: (u64, u64),
    pub users: (u64, u64),
    pub groups: (u64, u64),
    pub roles: (u64, u64),
    pub role_bindings: (u64, u64),
    pub webhooks: (u64, u64),
    pub workflows: (u64, u64),
    pub execution_policies: (u64, u64),
    pub result_policies: (u64, u64),
    pub notification_policies: (u64, u64),
}

impl SyncConfig {
    /// Sync all config-managed resources in dependency order.
    /// Returns a summary of (deleted, inserted) counts per resource.
    #[allow(clippy::too_many_arguments)]
    pub fn sync_all(
        &self,
        databases: Vec<DatabaseInput>,
        users: Vec<UserInput>,
        groups: Vec<GroupInput>,
        roles: Vec<RoleInput>,
        role_bindings: Vec<RoleBindingInput>,
        webhooks: Vec<WebhookInput>,
        workflows: Vec<WorkflowInput>,
        execution_policies: Vec<ExecutionPolicyInput>,
        result_policies: Vec<ResultPolicyInput>,
        notification_policies: Vec<NotificationPolicyInput>,
    ) -> Result<SyncSummary, AppError> {
        self.transaction.begin()?;

        let result = self.sync_all_inner(
            databases,
            users,
            groups,
            roles,
            role_bindings,
            webhooks,
            workflows,
            execution_policies,
            result_policies,
            notification_policies,
        );

        match &result {
            Ok(_) => self.transaction.commit()?,
            Err(_) => {
                let _ = self.transaction.rollback();
            }
        }

        // Reload webhook dispatcher AFTER commit (outside transaction)
        if result.is_ok()
            && let Err(e) = self.notifier.reload()
        {
            tracing::warn!("failed to reload notifier after config sync: {e}");
        }

        result
    }

    #[allow(clippy::too_many_arguments)]
    fn sync_all_inner(
        &self,
        databases: Vec<DatabaseInput>,
        users: Vec<UserInput>,
        groups: Vec<GroupInput>,
        roles: Vec<RoleInput>,
        role_bindings: Vec<RoleBindingInput>,
        webhooks: Vec<WebhookInput>,
        workflows: Vec<WorkflowInput>,
        execution_policies: Vec<ExecutionPolicyInput>,
        result_policies: Vec<ResultPolicyInput>,
        notification_policies: Vec<NotificationPolicyInput>,
    ) -> Result<SyncSummary, AppError> {
        // Order: databases → users → groups → roles → role_bindings → webhooks → workflows → ep → rp → np
        Ok(SyncSummary {
            databases: self.sync_databases(databases)?,
            users: self.sync_users(users)?,
            groups: self.sync_groups(groups)?,
            roles: {
                let r = self.sync_roles(roles)?;
                // License: check role count after sync
                let total = self.policy_repo.count_roles()?;
                if total > self.license_checker.max_roles() {
                    return Err(AppError::Validation(format!(
                        "role limit exceeded (max {}, have {total})",
                        self.license_checker.max_roles()
                    )));
                }
                r
            },
            role_bindings: self.sync_role_bindings(role_bindings)?,
            webhooks: {
                let w = self.sync_webhooks(webhooks)?;
                let total = self.webhook_repo.list()?.len() as u32;
                if total > self.license_checker.max_webhooks() {
                    return Err(AppError::Validation(format!(
                        "webhook limit exceeded (max {}, have {total})",
                        self.license_checker.max_webhooks()
                    )));
                }
                w
            },
            workflows: {
                let w = self.sync_workflows(workflows)?;
                let total = self.policy_repo.count_workflows()?;
                if total > self.license_checker.max_workflows() {
                    return Err(AppError::Validation(format!(
                        "workflow limit exceeded (max {}, have {total})",
                        self.license_checker.max_workflows()
                    )));
                }
                w
            },
            execution_policies: self.sync_execution_policies(execution_policies)?,
            result_policies: self.sync_result_policies(result_policies)?,
            notification_policies: self.sync_notification_policies(notification_policies)?,
        })
    }

    fn sync_databases(&self, inputs: Vec<DatabaseInput>) -> Result<(u64, u64), AppError> {
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
        // License check after inserting all databases
        let total = self.database_registry.list()?.len() as u32;
        if total > self.license_checker.max_databases() {
            return Err(AppError::Validation(format!(
                "database limit exceeded (max {}, have {total})",
                self.license_checker.max_databases()
            )));
        }
        Ok((deleted, inserted))
    }

    fn sync_users(&self, inputs: Vec<UserInput>) -> Result<(u64, u64), AppError> {
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

    fn sync_groups(&self, inputs: Vec<GroupInput>) -> Result<(u64, u64), AppError> {
        let deleted = self.group_repo.delete_by_source("config")?;
        let mut inserted = 0u64;
        for g in &inputs {
            self.group_repo.create(&g.name, &g.members, "config")?;
            inserted += 1;
        }
        Ok((deleted, inserted))
    }

    fn sync_roles(&self, inputs: Vec<RoleInput>) -> Result<(u64, u64), AppError> {
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

    fn sync_role_bindings(&self, inputs: Vec<RoleBindingInput>) -> Result<(u64, u64), AppError> {
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
            let workflow = Self::parse_workflow(&id, wf)?;
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

    fn sync_result_policies(
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

    fn sync_notification_policies(
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

    fn parse_workflow(id: &str, wf: &WorkflowInput) -> Result<Workflow, AppError> {
        let db = if wf.database == "*" {
            DatabaseName::wildcard()
        } else {
            DatabaseName::new(&wf.database)
                .map_err(|e| AppError::Validation(format!("workflow db: {e}")))?
        };
        let env = if wf.environment == "*" {
            Environment::wildcard()
        } else {
            Environment::new(&wf.environment)
                .map_err(|e| AppError::Validation(format!("workflow env: {e}")))?
        };

        let mut operations: Vec<Operation> = Vec::new();
        for op_str in &wf.operations {
            let op = op_str
                .parse::<Operation>()
                .map_err(|e| AppError::Validation(format!("workflow {id}: {e}")))?;
            operations.push(op);
        }

        let mut steps: Vec<WorkflowStep> = Vec::new();
        for s in &wf.steps {
            let mode = match s.mode.as_str() {
                "any" => WorkflowStepMode::Any,
                "all" => WorkflowStepMode::All,
                other => {
                    return Err(AppError::Validation(format!(
                        "workflow step: unknown mode '{other}' (expected 'any' or 'all')"
                    )));
                }
            };
            let mut approvers = Vec::new();
            for a in &s.approvers {
                let selector = match a.selector_type.as_str() {
                    "role" => Selector::Role(a.value.clone()),
                    "group" => Selector::Group(a.value.clone()),
                    "user" => Selector::User(a.value.clone()),
                    other => {
                        return Err(AppError::Validation(format!(
                            "workflow step: unknown selector_type '{other}'"
                        )));
                    }
                };
                approvers.push(ApproverGroup {
                    selector,
                    min: a.min,
                });
            }
            if approvers.is_empty() {
                return Err(AppError::Validation(format!(
                    "workflow {}/{}: step has no valid approvers",
                    wf.database, wf.environment
                )));
            }
            steps.push(WorkflowStep { approvers, mode });
        }

        Ok(Workflow {
            id: id.to_string(),
            database: db,
            environment: env,
            operations,
            steps,
            require_reason: wf.require_reason,
            allow_self_approve: wf.allow_self_approve,
            allow_same_approver_across_steps: wf.allow_same_approver_across_steps,
            explain: wf.explain,
            pending_ttl_secs: wf.pending_ttl_secs,
            statement_timeout_secs: wf.statement_timeout_secs,
            approval_ttl_secs: None,
            created_at: None,
            updated_at: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AppError;
    use crate::ports::{DatabaseRegistry, GroupRepo, PolicyRepo, RoleBindingRepo, WebhookRepo};
    use crate::test_support::{FixedClock, FixedIdGen};
    use dbward_domain::entities::Webhook;
    use dbward_domain::policies::{ExecutionPolicy, NotificationPolicy, ResultPolicy, Workflow};
    use dbward_domain::values::{DatabaseName, Environment};

    // --- Minimal fakes ---

    struct FakePolicyRepo;
    impl PolicyRepo for FakePolicyRepo {
        fn create_workflow(&self, _: &Workflow) -> Result<(), AppError> {
            Ok(())
        }
        fn get_workflow(&self, _: &str) -> Result<Option<Workflow>, AppError> {
            Ok(None)
        }
        fn list_workflows(&self) -> Result<Vec<Workflow>, AppError> {
            Ok(vec![])
        }
        fn delete_workflow(&self, _: &str) -> Result<bool, AppError> {
            Ok(false)
        }
        fn count_workflows(&self) -> Result<u32, AppError> {
            Ok(0)
        }
        fn create_execution_policy(&self, _: &ExecutionPolicy) -> Result<(), AppError> {
            Ok(())
        }
        fn get_execution_policy(&self, _: &str) -> Result<Option<ExecutionPolicy>, AppError> {
            Ok(None)
        }
        fn list_execution_policies(&self) -> Result<Vec<ExecutionPolicy>, AppError> {
            Ok(vec![])
        }
        fn delete_execution_policy(&self, _: &str) -> Result<bool, AppError> {
            Ok(false)
        }
        fn find_result_policy(
            &self,
            _: &DatabaseName,
            _: &Environment,
        ) -> Result<Option<ResultPolicy>, AppError> {
            Ok(None)
        }
        fn create_result_policy(&self, _: &ResultPolicy) -> Result<(), AppError> {
            Ok(())
        }
        fn get_result_policy(&self, _: &str) -> Result<Option<ResultPolicy>, AppError> {
            Ok(None)
        }
        fn list_result_policies(&self) -> Result<Vec<ResultPolicy>, AppError> {
            Ok(vec![])
        }
        fn update_result_policy(&self, _: &ResultPolicy) -> Result<bool, AppError> {
            Ok(false)
        }
        fn delete_result_policy(&self, _: &str) -> Result<bool, AppError> {
            Ok(false)
        }
        fn create_notification_policy(&self, _: &NotificationPolicy) -> Result<(), AppError> {
            Ok(())
        }
        fn get_notification_policy(&self, _: &str) -> Result<Option<NotificationPolicy>, AppError> {
            Ok(None)
        }
        fn list_notification_policies(&self) -> Result<Vec<NotificationPolicy>, AppError> {
            Ok(vec![])
        }
        fn update_notification_policy(&self, _: &NotificationPolicy) -> Result<bool, AppError> {
            Ok(false)
        }
        fn delete_notification_policy(&self, _: &str) -> Result<bool, AppError> {
            Ok(false)
        }
        fn create_role(&self, _: &dbward_domain::auth::RoleDefinition) -> Result<(), AppError> {
            Ok(())
        }
        fn list_roles(&self) -> Result<Vec<dbward_domain::auth::RoleDefinition>, AppError> {
            Ok(vec![])
        }
        fn get_roles_by_names(
            &self,
            _: &[String],
        ) -> Result<Vec<dbward_domain::auth::RoleDefinition>, AppError> {
            Ok(vec![])
        }
        fn delete_role(&self, _: &str) -> Result<bool, AppError> {
            Ok(false)
        }
        fn count_roles(&self) -> Result<u32, AppError> {
            Ok(0)
        }
    }

    struct FakeWebhookRepo;
    impl WebhookRepo for FakeWebhookRepo {
        fn create(&self, _: &Webhook) -> Result<(), AppError> {
            Ok(())
        }
        fn get(&self, _: &str) -> Result<Option<Webhook>, AppError> {
            Ok(None)
        }
        fn list(&self) -> Result<Vec<Webhook>, AppError> {
            Ok(vec![])
        }
        fn update(&self, _: &Webhook) -> Result<(), AppError> {
            Ok(())
        }
        fn delete(&self, _: &str) -> Result<(), AppError> {
            Ok(())
        }
    }

    struct FakeDatabaseRegistry;
    impl DatabaseRegistry for FakeDatabaseRegistry {
        fn register(&self, _: &DatabaseName, _: &Environment) -> Result<(), AppError> {
            Ok(())
        }
        fn exists(&self, _: &DatabaseName, _: &Environment) -> Result<bool, AppError> {
            Ok(false)
        }
        fn list(&self) -> Result<Vec<(DatabaseName, Environment)>, AppError> {
            Ok(vec![])
        }
    }

    struct FakeUserRepo;
    impl crate::ports::UserRepo for FakeUserRepo {
        fn get(&self, _: &str) -> Result<Option<dbward_domain::entities::User>, AppError> {
            Ok(None)
        }
        fn upsert(&self, _: &dbward_domain::entities::User) -> Result<(), AppError> {
            Ok(())
        }
        fn list(&self) -> Result<Vec<dbward_domain::entities::User>, AppError> {
            Ok(vec![])
        }
        fn suspend(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> {
            Ok(false)
        }
        fn activate(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> {
            Ok(false)
        }
        fn is_suspended(&self, _: &str) -> Result<bool, AppError> {
            Ok(false)
        }
        fn ensure_exists(&self, _: &str) -> Result<(), AppError> {
            Ok(())
        }
    }

    struct FakeGroupRepo;
    impl GroupRepo for FakeGroupRepo {
        fn delete_by_source(&self, _: &str) -> Result<u64, AppError> {
            Ok(0)
        }
        fn create(&self, _: &str, _: &[String], _: &str) -> Result<(), AppError> {
            Ok(())
        }
        fn list(&self) -> Result<Vec<(String, Vec<String>)>, AppError> {
            Ok(vec![])
        }
    }

    struct FakeRoleBindingRepo;
    impl RoleBindingRepo for FakeRoleBindingRepo {
        fn delete_by_source(&self, _: &str) -> Result<u64, AppError> {
            Ok(0)
        }
        fn create(
            &self,
            _: &str,
            _: &str,
            _: &[String],
            _: &[String],
            _: &str,
        ) -> Result<(), AppError> {
            Ok(())
        }
        fn list(&self) -> Result<Vec<crate::ports::RoleBindingEntry>, AppError> {
            Ok(vec![])
        }
    }

    struct FakeNotifier;
    impl crate::ports::Notifier for FakeNotifier {
        fn dispatch(&self, _: crate::ports::WebhookEvent) {}
    }

    struct FakeSyncTransaction;
    impl super::SyncTransaction for FakeSyncTransaction {
        fn begin(&self) -> Result<(), AppError> {
            Ok(())
        }
        fn commit(&self) -> Result<(), AppError> {
            Ok(())
        }
        fn rollback(&self) -> Result<(), AppError> {
            Ok(())
        }
    }

    struct FakeLicenseChecker;
    impl crate::ports::LicenseChecker for FakeLicenseChecker {
        fn max_databases(&self) -> u32 {
            100
        }
        fn max_workflows(&self) -> u32 {
            100
        }
        fn max_webhooks(&self) -> u32 {
            100
        }
        fn max_tokens(&self) -> u32 {
            100
        }
        fn max_roles(&self) -> u32 {
            100
        }
        fn is_enterprise(&self) -> bool {
            false
        }
        fn configured_plan(&self) -> &str {
            "free"
        }
        fn effective_plan(&self) -> &str {
            "free"
        }
        fn is_expired(&self) -> bool {
            false
        }
        fn check_expiry(&self, _: chrono::DateTime<chrono::Utc>) {}
    }

    struct FakeSsrfValidator;
    impl crate::ports::SsrfValidator for FakeSsrfValidator {
        fn validate_url(&self, _: &str) -> Result<(), AppError> {
            Ok(())
        }
    }

    fn make_sync() -> SyncConfig {
        SyncConfig {
            policy_repo: Arc::new(FakePolicyRepo),
            webhook_repo: Arc::new(FakeWebhookRepo),
            database_registry: Arc::new(FakeDatabaseRegistry),
            user_repo: Arc::new(FakeUserRepo),
            group_repo: Arc::new(FakeGroupRepo),
            role_binding_repo: Arc::new(FakeRoleBindingRepo),
            notifier: Arc::new(FakeNotifier),
            clock: Arc::new(FixedClock::now_utc()),
            id_gen: Arc::new(FixedIdGen::new()),
            transaction: Arc::new(FakeSyncTransaction),
            license_checker: Arc::new(FakeLicenseChecker),
            ssrf_validator: Arc::new(FakeSsrfValidator),
        }
    }

    fn valid_workflow_input() -> WorkflowInput {
        WorkflowInput {
            database: "primary".into(),
            environment: "production".into(),
            operations: vec!["execute_select".into()],
            steps: vec![WorkflowStepInput {
                mode: "any".into(),
                approvers: vec![ApproverInput {
                    selector_type: "role".into(),
                    value: "admin".into(),
                    min: 1,
                }],
            }],
            require_reason: false,
            allow_self_approve: false,
            allow_same_approver_across_steps: false,
            explain: true,
            pending_ttl_secs: None,
            statement_timeout_secs: None,
        }
    }

    #[test]
    fn sync_workflows_valid_conversion() {
        let sync = make_sync();
        let result = sync.sync_workflows(vec![valid_workflow_input()]);
        assert!(result.is_ok());
    }

    #[test]
    fn sync_workflows_invalid_mode_returns_err() {
        let sync = make_sync();
        let mut wf = valid_workflow_input();
        wf.steps[0].mode = "invalid".into();
        let err = sync.sync_workflows(vec![wf]).unwrap_err();
        match err {
            AppError::Validation(msg) => assert!(msg.contains("unknown mode 'invalid'")),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn sync_workflows_invalid_selector_type_returns_err() {
        let sync = make_sync();
        let mut wf = valid_workflow_input();
        wf.steps[0].approvers[0].selector_type = "invalid".into();
        let err = sync.sync_workflows(vec![wf]).unwrap_err();
        match err {
            AppError::Validation(msg) => assert!(msg.contains("unknown selector_type 'invalid'")),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn sync_webhooks_invalid_format_returns_err() {
        let sync = make_sync();
        let wh = WebhookInput {
            id: "test-hook".into(),
            url: "https://example.com".into(),
            events: vec!["request_created".into()],
            format: "invalid".into(),
            secret: None,
        };
        let err = sync.sync_webhooks(vec![wh]).unwrap_err();
        match err {
            AppError::Validation(msg) => assert!(msg.contains("unknown format 'invalid'")),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn sync_workflows_invalid_operation_returns_err() {
        let sync = make_sync();
        let mut wf = valid_workflow_input();
        wf.operations = vec!["invalid_op".into()];
        let err = sync.sync_workflows(vec![wf]).unwrap_err();
        match err {
            AppError::Validation(msg) => assert!(msg.contains("invalid_op")),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn sync_workflows_wildcard_db_env() {
        let sync = make_sync();
        let mut wf = valid_workflow_input();
        wf.database = "*".into();
        wf.environment = "*".into();
        let result = sync.sync_workflows(vec![wf]);
        assert!(result.is_ok());
    }
}
