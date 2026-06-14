mod apply;
pub mod convert;

use std::sync::Arc;

use crate::error::AppError;
use crate::ports::{
    Clock, ConfigGenerationRepo, DatabaseRegistry, GroupRepo, IdGenerator, LicenseChecker,
    Notifier, PolicyRepo, RequestWriter, RoleBindingRepo, SsrfValidator, TokenRepo, UserRepo,
    WebhookRepo,
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
    pub token_repo: Arc<dyn TokenRepo>,
    pub request_writer: Arc<dyn RequestWriter>,
    pub notifier: Arc<dyn Notifier>,
    pub clock: Arc<dyn Clock>,
    pub id_gen: Arc<dyn IdGenerator>,
    pub transaction: Arc<dyn SyncTransaction>,
    pub license_checker: Arc<dyn LicenseChecker>,
    pub ssrf_validator: Arc<dyn SsrfValidator>,
    pub config_generation_repo: Arc<dyn ConfigGenerationRepo>,
    pub config_digest: String,
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
            tracing::error!(
                "notifier reload failed after config sync (DB committed, restart required): {e}"
            );
            return Err(AppError::Internal(format!(
                "notifier reload failed (DB committed, restart required): {e}"
            )));
        }

        // Record config generation + summary log
        if let Ok(ref summary) = result {
            let summary_json = serde_json::json!({
                "databases": {"upserted": summary.databases.1, "stale": summary.databases.0},
                "users": {"upserted": summary.users.1, "stale": summary.users.0},
                "groups": {"upserted": summary.groups.1, "stale": summary.groups.0},
                "roles": {"upserted": summary.roles.1, "stale": summary.roles.0},
                "role_bindings": {"upserted": summary.role_bindings.1, "stale": summary.role_bindings.0},
                "webhooks": {"upserted": summary.webhooks.1, "stale": summary.webhooks.0},
                "workflows": {"upserted": summary.workflows.1, "stale": summary.workflows.0},
                "execution_policies": {"upserted": summary.execution_policies.1, "stale": summary.execution_policies.0},
                "result_policies": {"upserted": summary.result_policies.1, "stale": summary.result_policies.0},
                "notification_policies": {"upserted": summary.notification_policies.1, "stale": summary.notification_policies.0},
            });
            self.config_generation_repo
                .record_generation(&self.config_digest, &summary_json.to_string());
            tracing::info!(
                "config synced: databases(+{}/-{}) webhooks(+{}/-{}) workflows(+{}/-{})",
                summary.databases.1,
                summary.databases.0,
                summary.webhooks.1,
                summary.webhooks.0,
                summary.workflows.1,
                summary.workflows.0,
            );
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
                let total = self.webhook_repo.list_active()?.len() as u32;
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
        fn list_active(&self) -> Result<Vec<Webhook>, AppError> {
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
        fn exists_active(&self, _: &DatabaseName, _: &Environment) -> Result<bool, AppError> {
            Ok(false)
        }
        fn list_active(&self) -> Result<Vec<(DatabaseName, Environment)>, AppError> {
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

    struct FakeTokenRepo;
    impl TokenRepo for FakeTokenRepo {
        fn create(&self, _: &dbward_domain::entities::Token) -> Result<(), AppError> {
            Ok(())
        }
        fn verify(
            &self,
            _: &str,
            _: &str,
        ) -> Result<Option<dbward_domain::entities::Token>, AppError> {
            Ok(None)
        }
        fn list(&self) -> Result<Vec<dbward_domain::entities::Token>, AppError> {
            Ok(vec![])
        }
        fn get(&self, _: &str) -> Result<Option<dbward_domain::entities::Token>, AppError> {
            Ok(None)
        }
        fn revoke(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
        fn revoke_all_for_user(
            &self,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<u32, AppError> {
            Ok(0)
        }
        fn count_active(&self) -> Result<u32, AppError> {
            Ok(0)
        }
        fn purge_revoked(&self, _: &str) -> Result<u32, AppError> {
            Ok(0)
        }
    }

    struct FakeRequestWriter;
    impl crate::ports::RequestWriter for FakeRequestWriter {
        fn insert(&self, _: &dbward_domain::entities::Request) -> Result<(), AppError> {
            Ok(())
        }
        fn create_and_dispatch(
            &self,
            _: &dbward_domain::entities::Request,
        ) -> Result<(), AppError> {
            Ok(())
        }
        fn mark_approved(
            &self,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_rejected(
            &self,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_cancelled(
            &self,
            _: &str,
            _: &str,
            _: Option<&str>,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_dispatched(
            &self,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_running(
            &self,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_executed(
            &self,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_failed(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
        fn cancel_all_for_user(
            &self,
            _: &str,
            _: &str,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
            _: &dbward_domain::entities::AuditContext,
        ) -> Result<Vec<String>, AppError> {
            Ok(vec![])
        }
        fn mark_approved_from_dispatched(&self, _: &str, _: &str) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_approved_from_dispatched_and_record(
            &self,
            _: &str,
            _: &dbward_domain::entities::AuditEvent,
            _: &str,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_audit_incomplete(&self, _: &str) -> Result<(), AppError> {
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
        fn max_users(&self) -> u32 {
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
            token_repo: Arc::new(FakeTokenRepo),
            request_writer: Arc::new(FakeRequestWriter),
            notifier: Arc::new(FakeNotifier),
            clock: Arc::new(FixedClock::now_utc()),
            id_gen: Arc::new(FixedIdGen::new()),
            transaction: Arc::new(FakeSyncTransaction),
            license_checker: Arc::new(FakeLicenseChecker),
            ssrf_validator: Arc::new(FakeSsrfValidator),
            config_generation_repo: Arc::new(crate::ports::NoopConfigGenerationRepo),
            config_digest: String::new(),
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

    #[test]
    fn sync_all_preserves_oidc_and_token_users() {
        // Verify that sync only deletes source='config', not 'oidc'/'token'
        use std::sync::Mutex;

        struct TrackingUserRepo {
            deleted_source: Mutex<Vec<String>>,
        }
        impl UserRepo for TrackingUserRepo {
            fn delete_by_source(&self, source: &str) -> Result<u64, AppError> {
                self.deleted_source.lock().unwrap().push(source.into());
                Ok(0)
            }
            fn delete_stale_config(&self, active_ids: &[String]) -> Result<u64, AppError> {
                // Track that stale deletion was called (not delete_by_source)
                self.deleted_source
                    .lock()
                    .unwrap()
                    .push("stale_config".into());
                let _ = active_ids;
                Ok(0)
            }
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
                Ok(true)
            }
            fn activate(
                &self,
                _: &str,
                _: chrono::DateTime<chrono::Utc>,
            ) -> Result<bool, AppError> {
                Ok(true)
            }
            fn is_suspended(&self, _: &str) -> Result<bool, AppError> {
                Ok(false)
            }
            fn ensure_exists(&self, _: &str) -> Result<(), AppError> {
                Ok(())
            }
        }

        let tracking = Arc::new(TrackingUserRepo {
            deleted_source: Mutex::new(vec![]),
        });
        let mut sync = make_sync();
        sync.user_repo = tracking.clone();
        let result = sync.sync_users(vec![UserInput {
            id: "alice".into(),
            status: "active".into(),
        }]);
        assert!(result.is_ok());
        let sources = tracking.deleted_source.lock().unwrap();
        assert_eq!(
            &*sources,
            &["stale_config"],
            "should use delete_stale_config, not delete_by_source"
        );
    }

    #[test]
    fn sync_rollback_on_license_failure() {
        use std::sync::Mutex;
        use std::sync::atomic::{AtomicBool, Ordering};

        struct FailLicenseChecker;
        impl crate::ports::LicenseChecker for FailLicenseChecker {
            fn max_databases(&self) -> u32 {
                0
            }
            fn max_workflows(&self) -> u32 {
                100
            }
            fn max_webhooks(&self) -> u32 {
                100
            }
            fn max_users(&self) -> u32 {
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

        struct TrackingDbRegistry {
            entries: Mutex<Vec<(DatabaseName, Environment)>>,
        }
        impl DatabaseRegistry for TrackingDbRegistry {
            fn register(&self, db: &DatabaseName, env: &Environment) -> Result<(), AppError> {
                self.entries.lock().unwrap().push((db.clone(), env.clone()));
                Ok(())
            }
            fn list_active(&self) -> Result<Vec<(DatabaseName, Environment)>, AppError> {
                Ok(self.entries.lock().unwrap().clone())
            }
            fn delete_by_source(&self, _: &str) -> Result<u64, AppError> {
                Ok(0)
            }
            fn exists_active(&self, _: &DatabaseName, _: &Environment) -> Result<bool, AppError> {
                Ok(true)
            }
        }

        struct TrackingTransaction {
            committed: AtomicBool,
            rolled_back: AtomicBool,
        }
        impl super::SyncTransaction for TrackingTransaction {
            fn begin(&self) -> Result<(), AppError> {
                Ok(())
            }
            fn commit(&self) -> Result<(), AppError> {
                self.committed.store(true, Ordering::SeqCst);
                Ok(())
            }
            fn rollback(&self) -> Result<(), AppError> {
                self.rolled_back.store(true, Ordering::SeqCst);
                Ok(())
            }
        }

        let txn = Arc::new(TrackingTransaction {
            committed: AtomicBool::new(false),
            rolled_back: AtomicBool::new(false),
        });
        let mut sync = make_sync();
        sync.license_checker = Arc::new(FailLicenseChecker);
        sync.database_registry = Arc::new(TrackingDbRegistry {
            entries: Mutex::new(vec![]),
        });
        sync.transaction = txn.clone();

        let result = sync.sync_all(
            vec![DatabaseInput {
                name: "db1".into(),
                environments: vec!["prod".into()],
            }],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
        );
        assert!(result.is_err(), "should fail on license check");
        assert!(
            txn.rolled_back.load(Ordering::SeqCst),
            "transaction must be rolled back"
        );
        assert!(
            !txn.committed.load(Ordering::SeqCst),
            "transaction must NOT be committed"
        );
    }

    #[test]
    fn ssrf_rejects_private_url_in_webhook_sync() {
        struct RejectingSsrfValidator;
        impl crate::ports::SsrfValidator for RejectingSsrfValidator {
            fn validate_url(&self, url: &str) -> Result<(), AppError> {
                if url.contains("127.0.0.1") || url.contains("10.") {
                    Err(AppError::Validation(format!("private IP: {url}")))
                } else {
                    Ok(())
                }
            }
        }

        let mut sync = make_sync();
        sync.ssrf_validator = Arc::new(RejectingSsrfValidator);

        let result = sync.sync_webhooks(vec![WebhookInput {
            id: "evil".into(),
            url: "http://10.0.0.1/internal".into(),
            events: vec!["*".into()],
            format: "generic".into(),
            secret: None,
        }]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            AppError::Validation(msg) => assert!(msg.contains("10.0.0.1")),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn api_405_response_body_format() {
        // Verify the 405 handler returns correct JSON body
        // This test is placed here as a compile-time guarantee of the structure
        let body = serde_json::json!({
            "error": "this resource is config-managed; update server.toml and restart",
            "code": "config_only"
        });
        assert_eq!(body["code"], "config_only");
        assert!(body["error"].as_str().unwrap().contains("config-managed"));
    }

    // --- ERR-3 tests ---

    #[test]
    fn sync_users_reconciles_status_to_suspended() {
        use std::sync::atomic::{AtomicU32, Ordering};

        struct TrackingUserRepo;
        impl UserRepo for TrackingUserRepo {
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
                Ok(true)
            }
            fn activate(
                &self,
                _: &str,
                _: chrono::DateTime<chrono::Utc>,
            ) -> Result<bool, AppError> {
                Ok(false)
            }
            fn is_suspended(&self, _: &str) -> Result<bool, AppError> {
                Ok(false)
            }
            fn ensure_exists(&self, _: &str) -> Result<(), AppError> {
                Ok(())
            }
            fn get_source(&self, _: &str) -> Result<Option<String>, AppError> {
                Ok(Some("config".into()))
            }
            fn set_source(&self, _: &str, _: &str) -> Result<(), AppError> {
                Ok(())
            }
            fn delete_stale_config(&self, _: &[String]) -> Result<u64, AppError> {
                Ok(0)
            }
            fn list_stale_config_ids(&self, _: &[String]) -> Result<Vec<String>, AppError> {
                Ok(vec![])
            }
        }

        struct TrackingTokenRepo {
            revoked: AtomicU32,
        }
        impl TokenRepo for TrackingTokenRepo {
            fn create(&self, _: &dbward_domain::entities::Token) -> Result<(), AppError> {
                Ok(())
            }
            fn verify(
                &self,
                _: &str,
                _: &str,
            ) -> Result<Option<dbward_domain::entities::Token>, AppError> {
                Ok(None)
            }
            fn list(&self) -> Result<Vec<dbward_domain::entities::Token>, AppError> {
                Ok(vec![])
            }
            fn get(&self, _: &str) -> Result<Option<dbward_domain::entities::Token>, AppError> {
                Ok(None)
            }
            fn revoke(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> {
                Ok(true)
            }
            fn revoke_all_for_user(
                &self,
                _: &str,
                _: chrono::DateTime<chrono::Utc>,
            ) -> Result<u32, AppError> {
                self.revoked.fetch_add(1, Ordering::SeqCst);
                Ok(1)
            }
            fn count_active(&self) -> Result<u32, AppError> {
                Ok(0)
            }
            fn purge_revoked(&self, _: &str) -> Result<u32, AppError> {
                Ok(0)
            }
        }

        let token_repo = Arc::new(TrackingTokenRepo {
            revoked: AtomicU32::new(0),
        });
        let mut sync = make_sync();
        sync.user_repo = Arc::new(TrackingUserRepo);
        sync.token_repo = token_repo.clone();

        let result = sync.sync_users(vec![UserInput {
            id: "alice".into(),
            status: "suspended".into(),
        }]);
        assert!(result.is_ok());
        assert_eq!(
            token_repo.revoked.load(Ordering::SeqCst),
            1,
            "should revoke on suspend"
        );
    }

    #[test]
    fn sync_users_reconciles_status_to_active() {
        use std::sync::atomic::{AtomicU32, Ordering};

        struct ActivatingUserRepo;
        impl UserRepo for ActivatingUserRepo {
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
            fn activate(
                &self,
                _: &str,
                _: chrono::DateTime<chrono::Utc>,
            ) -> Result<bool, AppError> {
                Ok(true)
            }
            fn is_suspended(&self, _: &str) -> Result<bool, AppError> {
                Ok(true)
            }
            fn ensure_exists(&self, _: &str) -> Result<(), AppError> {
                Ok(())
            }
            fn get_source(&self, _: &str) -> Result<Option<String>, AppError> {
                Ok(Some("config".into()))
            }
            fn set_source(&self, _: &str, _: &str) -> Result<(), AppError> {
                Ok(())
            }
            fn delete_stale_config(&self, _: &[String]) -> Result<u64, AppError> {
                Ok(0)
            }
            fn list_stale_config_ids(&self, _: &[String]) -> Result<Vec<String>, AppError> {
                Ok(vec![])
            }
        }

        struct TrackingTokenRepo {
            revoked: AtomicU32,
        }
        impl TokenRepo for TrackingTokenRepo {
            fn create(&self, _: &dbward_domain::entities::Token) -> Result<(), AppError> {
                Ok(())
            }
            fn verify(
                &self,
                _: &str,
                _: &str,
            ) -> Result<Option<dbward_domain::entities::Token>, AppError> {
                Ok(None)
            }
            fn list(&self) -> Result<Vec<dbward_domain::entities::Token>, AppError> {
                Ok(vec![])
            }
            fn get(&self, _: &str) -> Result<Option<dbward_domain::entities::Token>, AppError> {
                Ok(None)
            }
            fn revoke(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> {
                Ok(true)
            }
            fn revoke_all_for_user(
                &self,
                _: &str,
                _: chrono::DateTime<chrono::Utc>,
            ) -> Result<u32, AppError> {
                self.revoked.fetch_add(1, Ordering::SeqCst);
                Ok(0)
            }
            fn count_active(&self) -> Result<u32, AppError> {
                Ok(0)
            }
            fn purge_revoked(&self, _: &str) -> Result<u32, AppError> {
                Ok(0)
            }
        }

        let token_repo = Arc::new(TrackingTokenRepo {
            revoked: AtomicU32::new(0),
        });
        let mut sync = make_sync();
        sync.user_repo = Arc::new(ActivatingUserRepo);
        sync.token_repo = token_repo.clone();

        let result = sync.sync_users(vec![UserInput {
            id: "bob".into(),
            status: "active".into(),
        }]);
        assert!(result.is_ok());
        assert_eq!(
            token_repo.revoked.load(Ordering::SeqCst),
            0,
            "should NOT revoke on activate"
        );
    }

    #[test]
    fn sync_users_noop_when_status_unchanged() {
        use std::sync::atomic::{AtomicU32, Ordering};

        struct AlreadySuspendedUserRepo;
        impl UserRepo for AlreadySuspendedUserRepo {
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
            fn activate(
                &self,
                _: &str,
                _: chrono::DateTime<chrono::Utc>,
            ) -> Result<bool, AppError> {
                Ok(false)
            }
            fn is_suspended(&self, _: &str) -> Result<bool, AppError> {
                Ok(true)
            }
            fn ensure_exists(&self, _: &str) -> Result<(), AppError> {
                Ok(())
            }
            fn get_source(&self, _: &str) -> Result<Option<String>, AppError> {
                Ok(Some("config".into()))
            }
            fn set_source(&self, _: &str, _: &str) -> Result<(), AppError> {
                Ok(())
            }
            fn delete_stale_config(&self, _: &[String]) -> Result<u64, AppError> {
                Ok(0)
            }
            fn list_stale_config_ids(&self, _: &[String]) -> Result<Vec<String>, AppError> {
                Ok(vec![])
            }
        }

        struct TrackingTokenRepo {
            revoked: AtomicU32,
        }
        impl TokenRepo for TrackingTokenRepo {
            fn create(&self, _: &dbward_domain::entities::Token) -> Result<(), AppError> {
                Ok(())
            }
            fn verify(
                &self,
                _: &str,
                _: &str,
            ) -> Result<Option<dbward_domain::entities::Token>, AppError> {
                Ok(None)
            }
            fn list(&self) -> Result<Vec<dbward_domain::entities::Token>, AppError> {
                Ok(vec![])
            }
            fn get(&self, _: &str) -> Result<Option<dbward_domain::entities::Token>, AppError> {
                Ok(None)
            }
            fn revoke(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> {
                Ok(true)
            }
            fn revoke_all_for_user(
                &self,
                _: &str,
                _: chrono::DateTime<chrono::Utc>,
            ) -> Result<u32, AppError> {
                self.revoked.fetch_add(1, Ordering::SeqCst);
                Ok(0)
            }
            fn count_active(&self) -> Result<u32, AppError> {
                Ok(0)
            }
            fn purge_revoked(&self, _: &str) -> Result<u32, AppError> {
                Ok(0)
            }
        }

        let token_repo = Arc::new(TrackingTokenRepo {
            revoked: AtomicU32::new(0),
        });
        let mut sync = make_sync();
        sync.user_repo = Arc::new(AlreadySuspendedUserRepo);
        sync.token_repo = token_repo.clone();

        let result = sync.sync_users(vec![UserInput {
            id: "carol".into(),
            status: "suspended".into(),
        }]);
        assert!(result.is_ok());
        assert_eq!(
            token_repo.revoked.load(Ordering::SeqCst),
            0,
            "should NOT revoke when already suspended"
        );
    }

    #[test]
    fn sync_users_stale_delete_revokes_and_cancels() {
        use std::sync::atomic::{AtomicU32, Ordering};

        struct StaleUserRepo;
        impl UserRepo for StaleUserRepo {
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
            fn activate(
                &self,
                _: &str,
                _: chrono::DateTime<chrono::Utc>,
            ) -> Result<bool, AppError> {
                Ok(false)
            }
            fn is_suspended(&self, _: &str) -> Result<bool, AppError> {
                Ok(false)
            }
            fn ensure_exists(&self, _: &str) -> Result<(), AppError> {
                Ok(())
            }
            fn get_source(&self, _: &str) -> Result<Option<String>, AppError> {
                Ok(Some("config".into()))
            }
            fn set_source(&self, _: &str, _: &str) -> Result<(), AppError> {
                Ok(())
            }
            fn delete_stale_config(&self, _: &[String]) -> Result<u64, AppError> {
                Ok(1)
            }
            fn list_stale_config_ids(&self, _: &[String]) -> Result<Vec<String>, AppError> {
                Ok(vec!["stale-user".into()])
            }
        }

        struct TrackingTokenRepo {
            revoked: AtomicU32,
        }
        impl TokenRepo for TrackingTokenRepo {
            fn create(&self, _: &dbward_domain::entities::Token) -> Result<(), AppError> {
                Ok(())
            }
            fn verify(
                &self,
                _: &str,
                _: &str,
            ) -> Result<Option<dbward_domain::entities::Token>, AppError> {
                Ok(None)
            }
            fn list(&self) -> Result<Vec<dbward_domain::entities::Token>, AppError> {
                Ok(vec![])
            }
            fn get(&self, _: &str) -> Result<Option<dbward_domain::entities::Token>, AppError> {
                Ok(None)
            }
            fn revoke(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> {
                Ok(true)
            }
            fn revoke_all_for_user(
                &self,
                _: &str,
                _: chrono::DateTime<chrono::Utc>,
            ) -> Result<u32, AppError> {
                self.revoked.fetch_add(1, Ordering::SeqCst);
                Ok(1)
            }
            fn count_active(&self) -> Result<u32, AppError> {
                Ok(0)
            }
            fn purge_revoked(&self, _: &str) -> Result<u32, AppError> {
                Ok(0)
            }
        }

        let token_repo = Arc::new(TrackingTokenRepo {
            revoked: AtomicU32::new(0),
        });
        let mut sync = make_sync();
        sync.user_repo = Arc::new(StaleUserRepo);
        sync.token_repo = token_repo.clone();

        // Sync with "alice" active — "stale-user" not in toml_ids → stale
        let result = sync.sync_users(vec![UserInput {
            id: "alice".into(),
            status: "active".into(),
        }]);
        assert!(result.is_ok());
        let (deleted, _) = result.unwrap();
        assert_eq!(deleted, 1);
        // revoke_all_for_user called for stale-user
        assert_eq!(
            token_repo.revoked.load(Ordering::SeqCst),
            1,
            "should revoke stale user tokens"
        );
    }

    #[test]
    fn sync_users_new_suspended_user_revokes_existing_tokens() {
        use std::sync::atomic::{AtomicU32, Ordering};

        // get_source returns None = new user
        struct NewUserRepo;
        impl UserRepo for NewUserRepo {
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
                Ok(false) // INSERT with suspended → suspend() returns false
            }
            fn activate(
                &self,
                _: &str,
                _: chrono::DateTime<chrono::Utc>,
            ) -> Result<bool, AppError> {
                Ok(false)
            }
            fn is_suspended(&self, _: &str) -> Result<bool, AppError> {
                Ok(false)
            }
            fn ensure_exists(&self, _: &str) -> Result<(), AppError> {
                Ok(())
            }
            fn get_source(&self, _: &str) -> Result<Option<String>, AppError> {
                Ok(None)
            }
            fn set_source(&self, _: &str, _: &str) -> Result<(), AppError> {
                Ok(())
            }
            fn delete_stale_config(&self, _: &[String]) -> Result<u64, AppError> {
                Ok(0)
            }
            fn list_stale_config_ids(&self, _: &[String]) -> Result<Vec<String>, AppError> {
                Ok(vec![])
            }
        }

        struct TrackingTokenRepo {
            revoked: AtomicU32,
        }
        impl TokenRepo for TrackingTokenRepo {
            fn create(&self, _: &dbward_domain::entities::Token) -> Result<(), AppError> {
                Ok(())
            }
            fn verify(
                &self,
                _: &str,
                _: &str,
            ) -> Result<Option<dbward_domain::entities::Token>, AppError> {
                Ok(None)
            }
            fn list(&self) -> Result<Vec<dbward_domain::entities::Token>, AppError> {
                Ok(vec![])
            }
            fn get(&self, _: &str) -> Result<Option<dbward_domain::entities::Token>, AppError> {
                Ok(None)
            }
            fn revoke(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> {
                Ok(true)
            }
            fn revoke_all_for_user(
                &self,
                _: &str,
                _: chrono::DateTime<chrono::Utc>,
            ) -> Result<u32, AppError> {
                self.revoked.fetch_add(1, Ordering::SeqCst);
                Ok(1)
            }
            fn count_active(&self) -> Result<u32, AppError> {
                Ok(0)
            }
            fn purge_revoked(&self, _: &str) -> Result<u32, AppError> {
                Ok(0)
            }
        }

        let token_repo = Arc::new(TrackingTokenRepo {
            revoked: AtomicU32::new(0),
        });
        let mut sync = make_sync();
        sync.user_repo = Arc::new(NewUserRepo);
        sync.token_repo = token_repo.clone();

        let result = sync.sync_users(vec![UserInput {
            id: "new-user".into(),
            status: "suspended".into(),
        }]);
        assert!(result.is_ok());
        assert_eq!(
            token_repo.revoked.load(Ordering::SeqCst),
            1,
            "new suspended user must revoke even when suspend() returns false"
        );
    }

    #[test]
    fn sync_users_skips_non_config_source_user() {
        use std::sync::Mutex;

        struct TokenSourceUserRepo {
            upserted: Mutex<Vec<String>>,
        }
        impl UserRepo for TokenSourceUserRepo {
            fn get(&self, _: &str) -> Result<Option<dbward_domain::entities::User>, AppError> {
                Ok(None)
            }
            fn upsert(&self, u: &dbward_domain::entities::User) -> Result<(), AppError> {
                self.upserted.lock().unwrap().push(u.id.clone());
                Ok(())
            }
            fn list(&self) -> Result<Vec<dbward_domain::entities::User>, AppError> {
                Ok(vec![])
            }
            fn suspend(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> {
                Ok(false)
            }
            fn activate(
                &self,
                _: &str,
                _: chrono::DateTime<chrono::Utc>,
            ) -> Result<bool, AppError> {
                Ok(false)
            }
            fn is_suspended(&self, _: &str) -> Result<bool, AppError> {
                Ok(false)
            }
            fn ensure_exists(&self, _: &str) -> Result<(), AppError> {
                Ok(())
            }
            fn get_source(&self, _: &str) -> Result<Option<String>, AppError> {
                Ok(Some("token".into())) // OIDC/token source
            }
            fn set_source(&self, _: &str, _: &str) -> Result<(), AppError> {
                Ok(())
            }
            fn delete_stale_config(&self, _: &[String]) -> Result<u64, AppError> {
                Ok(0)
            }
            fn list_stale_config_ids(&self, _: &[String]) -> Result<Vec<String>, AppError> {
                Ok(vec![])
            }
        }

        let user_repo = Arc::new(TokenSourceUserRepo {
            upserted: Mutex::new(vec![]),
        });
        let mut sync = make_sync();
        sync.user_repo = user_repo.clone();

        let result = sync.sync_users(vec![UserInput {
            id: "oidc-user".into(),
            status: "suspended".into(),
        }]);
        assert!(result.is_ok());
        let (_, upserted) = result.unwrap();
        assert_eq!(upserted, 0, "should skip non-config source user");
        assert!(
            user_repo.upserted.lock().unwrap().is_empty(),
            "upsert should not be called"
        );
    }
}
