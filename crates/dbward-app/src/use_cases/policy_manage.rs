use std::sync::Arc;

use dbward_domain::auth::{AuthUser, Permission, RoleDefinition};
use dbward_domain::entities::{AuditContext, AuditEvent};
use dbward_domain::policies::{DeliveryMode, ExecutionPolicy, Workflow, WorkflowStep};
use dbward_domain::values::{DatabaseName, Environment, Operation, Selector};

use crate::error::AppError;
use crate::ports::*;

pub struct PolicyManage {
    pub authorizer: Arc<dyn Authorizer>,
    pub policy_repo: Arc<dyn PolicyRepo>,
    pub license: Arc<dyn LicenseChecker>,
    pub audit: Arc<dyn AuditLogger>,
    pub clock: Arc<dyn Clock>,
    pub id_gen: Arc<dyn IdGenerator>,
}

pub struct CreateWorkflowInput {
    pub database: DatabaseName,
    pub environment: Environment,
    pub operations: Vec<Operation>,
    pub steps: Vec<WorkflowStep>,
    pub require_reason: bool,
}

pub struct CreateResultPolicyInput {
    pub database: DatabaseName,
    pub environment: Environment,
    pub retention_days: u32,
    pub delivery_mode: DeliveryMode,
    pub access: Vec<Selector>,
}

pub struct UpdateResultPolicyInput {
    pub retention_days: Option<u32>,
    pub delivery_mode: Option<DeliveryMode>,
    pub access: Option<Vec<Selector>>,
}

pub struct CreateNotificationPolicyInput {
    pub database: DatabaseName,
    pub environment: Environment,
    pub webhooks: Vec<String>,
    pub events: Vec<String>,
}

pub struct UpdateNotificationPolicyInput {
    pub webhooks: Option<Vec<String>>,
    pub events: Option<Vec<String>>,
}

// --- Workflow ---

impl PolicyManage {
    pub fn create_workflow(
        &self,
        input: CreateWorkflowInput,
        user: &AuthUser,
        ctx: &AuditContext,
    ) -> Result<Workflow, AppError> {
        self.authorizer
            .authorize_global(user, Permission::WorkflowManage)
            .map_err(AppError::Forbidden)?;
        let count = self.policy_repo.count_workflows()?;
        if count >= self.license.max_workflows() {
            return Err(AppError::PlanLimit("workflow limit reached".into()));
        }
        let now = self.clock.now();
        let wf = Workflow {
            id: format!("wf-{}", self.id_gen.generate()),
            database: input.database,
            environment: input.environment,
            operations: input.operations,
            steps: input.steps,
            require_reason: input.require_reason,
            allow_self_approve: false,
            allow_same_approver_across_steps: false,
            explain: true,
            pending_ttl_secs: None,
            statement_timeout_secs: None,
            approval_ttl_secs: None,
            created_at: Some(now),
            updated_at: Some(now),
        };
        self.policy_repo.create_workflow(&wf)?;
        self.audit.record(&AuditEvent::simple(
            "policy_created",
            "policy",
            &user.subject_id,
            Some(&wf.id),
            self.clock.now(),
            ctx,
        ))?;
        Ok(wf)
    }

    pub fn list_workflows(&self, user: &AuthUser) -> Result<Vec<Workflow>, AppError> {
        self.authorizer
            .authorize_global(user, Permission::WorkflowManage)
            .map_err(AppError::Forbidden)?;
        self.policy_repo.list_workflows()
    }

    pub fn delete_workflow(
        &self,
        id: &str,
        user: &AuthUser,
        ctx: &AuditContext,
    ) -> Result<(), AppError> {
        self.authorizer
            .authorize_global(user, Permission::WorkflowManage)
            .map_err(AppError::Forbidden)?;
        let deleted = self.policy_repo.delete_workflow(id)?;
        if !deleted {
            return Err(AppError::NotFound("workflow not found".into()));
        }
        self.audit.record(&AuditEvent::simple(
            "policy_deleted",
            "policy",
            &user.subject_id,
            Some(id),
            self.clock.now(),
            ctx,
        ))?;
        Ok(())
    }

    // --- ExecutionPolicy ---

    pub fn create_execution_policy(
        &self,
        ep: ExecutionPolicy,
        user: &AuthUser,
        ctx: &AuditContext,
    ) -> Result<ExecutionPolicy, AppError> {
        self.authorizer
            .authorize_global(user, Permission::PolicyManage)
            .map_err(AppError::Forbidden)?;
        self.policy_repo.create_execution_policy(&ep)?;
        self.audit.record(&AuditEvent::simple(
            "policy_created",
            "policy",
            &user.subject_id,
            None,
            self.clock.now(),
            ctx,
        ))?;
        Ok(ep)
    }

    pub fn list_execution_policies(
        &self,
        user: &AuthUser,
    ) -> Result<Vec<ExecutionPolicy>, AppError> {
        self.authorizer
            .authorize_global(user, Permission::PolicyManage)
            .map_err(AppError::Forbidden)?;
        self.policy_repo.list_execution_policies()
    }

    pub fn delete_execution_policy(&self, id: &str, user: &AuthUser) -> Result<(), AppError> {
        self.authorizer
            .authorize_global(user, Permission::PolicyManage)
            .map_err(AppError::Forbidden)?;
        let deleted = self.policy_repo.delete_execution_policy(id)?;
        if !deleted {
            return Err(AppError::NotFound("execution policy not found".into()));
        }
        Ok(())
    }

    // --- Role ---

    pub fn create_role(
        &self,
        role: RoleDefinition,
        user: &AuthUser,
        ctx: &AuditContext,
    ) -> Result<RoleDefinition, AppError> {
        self.authorizer
            .authorize_global(user, Permission::RoleManage)
            .map_err(AppError::Forbidden)?;
        if matches!(role.name.as_str(), "admin" | "agent-default") {
            return Err(AppError::Validation("cannot use built-in role name".into()));
        }
        let count = self.policy_repo.count_roles()?;
        if count >= self.license.max_roles() {
            return Err(AppError::PlanLimit("role limit reached".into()));
        }
        self.policy_repo.create_role(&role)?;
        self.audit.record(&AuditEvent::simple(
            "policy_created",
            "policy",
            &user.subject_id,
            Some(&role.name),
            self.clock.now(),
            ctx,
        ))?;
        Ok(role)
    }

    pub fn list_roles(&self, user: &AuthUser) -> Result<Vec<RoleDefinition>, AppError> {
        self.authorizer
            .authorize_global(user, Permission::RoleManage)
            .map_err(AppError::Forbidden)?;
        self.policy_repo.list_roles()
    }

    pub fn delete_role(&self, name: &str, user: &AuthUser) -> Result<(), AppError> {
        self.authorizer
            .authorize_global(user, Permission::RoleManage)
            .map_err(AppError::Forbidden)?;
        if matches!(name, "admin" | "agent-default") {
            return Err(AppError::Validation("cannot delete built-in role".into()));
        }
        let deleted = self.policy_repo.delete_role(name)?;
        if !deleted {
            return Err(AppError::NotFound("role not found".into()));
        }
        Ok(())
    }

    // --- ResultPolicy ---

    pub fn create_result_policy(
        &self,
        input: CreateResultPolicyInput,
        user: &AuthUser,
        ctx: &AuditContext,
    ) -> Result<dbward_domain::policies::ResultPolicy, AppError> {
        self.authorizer
            .authorize_global(user, Permission::PolicyManage)
            .map_err(AppError::Forbidden)?;
        if input.retention_days == 0 || input.retention_days > 3650 {
            return Err(AppError::Validation(
                "retention_days must be 1..=3650".into(),
            ));
        }
        let now = self.clock.now();
        let policy = dbward_domain::policies::ResultPolicy {
            id: format!("rp-{}", self.id_gen.generate()),
            database: input.database,
            environment: input.environment,
            retention_days: input.retention_days,
            delivery_mode: input.delivery_mode,
            access: input.access,
            created_at: Some(now),
            updated_at: Some(now),
        };
        self.policy_repo.create_result_policy(&policy)?;
        self.audit.record(&AuditEvent::simple(
            "policy_created",
            "policy",
            &user.subject_id,
            Some(&policy.id),
            self.clock.now(),
            ctx,
        ))?;
        Ok(policy)
    }

    pub fn get_result_policy(
        &self,
        id: &str,
        user: &AuthUser,
    ) -> Result<dbward_domain::policies::ResultPolicy, AppError> {
        self.authorizer
            .authorize_global(user, Permission::PolicyManage)
            .map_err(AppError::Forbidden)?;
        self.policy_repo
            .get_result_policy(id)?
            .ok_or_else(|| AppError::NotFound("result policy not found".into()))
    }

    pub fn list_result_policies(
        &self,
        user: &AuthUser,
    ) -> Result<Vec<dbward_domain::policies::ResultPolicy>, AppError> {
        self.authorizer
            .authorize_global(user, Permission::PolicyManage)
            .map_err(AppError::Forbidden)?;
        self.policy_repo.list_result_policies()
    }

    pub fn update_result_policy(
        &self,
        id: &str,
        input: UpdateResultPolicyInput,
        user: &AuthUser,
        ctx: &AuditContext,
    ) -> Result<dbward_domain::policies::ResultPolicy, AppError> {
        self.authorizer
            .authorize_global(user, Permission::PolicyManage)
            .map_err(AppError::Forbidden)?;
        let mut policy = self
            .policy_repo
            .get_result_policy(id)?
            .ok_or_else(|| AppError::NotFound("result policy not found".into()))?;
        if let Some(days) = input.retention_days {
            if days == 0 || days > 3650 {
                return Err(AppError::Validation(
                    "retention_days must be 1..=3650".into(),
                ));
            }
            policy.retention_days = days;
        }
        if let Some(mode) = input.delivery_mode {
            policy.delivery_mode = mode;
        }
        if let Some(access) = input.access {
            policy.access = access;
        }
        policy.updated_at = Some(self.clock.now());
        self.policy_repo.update_result_policy(&policy)?;
        self.audit.record(&AuditEvent::simple(
            "policy_updated",
            "policy",
            &user.subject_id,
            Some(id),
            self.clock.now(),
            ctx,
        ))?;
        Ok(policy)
    }

    pub fn delete_result_policy(
        &self,
        id: &str,
        user: &AuthUser,
        ctx: &AuditContext,
    ) -> Result<(), AppError> {
        self.authorizer
            .authorize_global(user, Permission::PolicyManage)
            .map_err(AppError::Forbidden)?;
        let deleted = self.policy_repo.delete_result_policy(id)?;
        if !deleted {
            return Err(AppError::NotFound("result policy not found".into()));
        }
        self.audit.record(&AuditEvent::simple(
            "policy_deleted",
            "policy",
            &user.subject_id,
            Some(id),
            self.clock.now(),
            ctx,
        ))?;
        Ok(())
    }

    // --- NotificationPolicy ---

    pub fn create_notification_policy(
        &self,
        input: CreateNotificationPolicyInput,
        user: &AuthUser,
        ctx: &AuditContext,
    ) -> Result<dbward_domain::policies::NotificationPolicy, AppError> {
        self.authorizer
            .authorize_global(user, Permission::PolicyManage)
            .map_err(AppError::Forbidden)?;
        if input.webhooks.is_empty() {
            return Err(AppError::Validation("webhooks must not be empty".into()));
        }
        for url in &input.webhooks {
            if !url.starts_with("http://") && !url.starts_with("https://") {
                return Err(AppError::Validation(format!("invalid webhook URL: {url}")));
            }
        }
        let policy = dbward_domain::policies::NotificationPolicy {
            id: format!("np-{}", self.id_gen.generate()),
            database: input.database,
            environment: input.environment,
            webhooks: input.webhooks,
            events: input.events,
        };
        self.policy_repo.create_notification_policy(&policy)?;
        self.audit.record(&AuditEvent::simple(
            "policy_created",
            "policy",
            &user.subject_id,
            Some(&policy.id),
            self.clock.now(),
            ctx,
        ))?;
        Ok(policy)
    }

    pub fn get_notification_policy(
        &self,
        id: &str,
        user: &AuthUser,
    ) -> Result<dbward_domain::policies::NotificationPolicy, AppError> {
        self.authorizer
            .authorize_global(user, Permission::PolicyManage)
            .map_err(AppError::Forbidden)?;
        self.policy_repo
            .get_notification_policy(id)?
            .ok_or_else(|| AppError::NotFound("notification policy not found".into()))
    }

    pub fn list_notification_policies(
        &self,
        user: &AuthUser,
    ) -> Result<Vec<dbward_domain::policies::NotificationPolicy>, AppError> {
        self.authorizer
            .authorize_global(user, Permission::PolicyManage)
            .map_err(AppError::Forbidden)?;
        self.policy_repo.list_notification_policies()
    }

    pub fn update_notification_policy(
        &self,
        id: &str,
        input: UpdateNotificationPolicyInput,
        user: &AuthUser,
        ctx: &AuditContext,
    ) -> Result<dbward_domain::policies::NotificationPolicy, AppError> {
        self.authorizer
            .authorize_global(user, Permission::PolicyManage)
            .map_err(AppError::Forbidden)?;
        let mut policy = self
            .policy_repo
            .get_notification_policy(id)?
            .ok_or_else(|| AppError::NotFound("notification policy not found".into()))?;
        if let Some(webhooks) = input.webhooks {
            if webhooks.is_empty() {
                return Err(AppError::Validation("webhooks must not be empty".into()));
            }
            for url in &webhooks {
                if !url.starts_with("http://") && !url.starts_with("https://") {
                    return Err(AppError::Validation(format!("invalid webhook URL: {url}")));
                }
            }
            policy.webhooks = webhooks;
        }
        if let Some(events) = input.events {
            policy.events = events;
        }
        self.policy_repo.update_notification_policy(&policy)?;
        self.audit.record(&AuditEvent::simple(
            "policy_updated",
            "policy",
            &user.subject_id,
            Some(id),
            self.clock.now(),
            ctx,
        ))?;
        Ok(policy)
    }

    pub fn delete_notification_policy(
        &self,
        id: &str,
        user: &AuthUser,
        ctx: &AuditContext,
    ) -> Result<(), AppError> {
        self.authorizer
            .authorize_global(user, Permission::PolicyManage)
            .map_err(AppError::Forbidden)?;
        let deleted = self.policy_repo.delete_notification_policy(id)?;
        if !deleted {
            return Err(AppError::NotFound("notification policy not found".into()));
        }
        self.audit.record(&AuditEvent::simple(
            "policy_deleted",
            "policy",
            &user.subject_id,
            Some(id),
            self.clock.now(),
            ctx,
        ))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AuthzError;
    use dbward_domain::auth::{Permission as P, ResolvedRole, ResourceContext, SubjectType};
    use dbward_domain::entities::AuditContext;
    use dbward_domain::values::{DatabaseName, Environment};
    use std::sync::Mutex;

    struct AllowAll;
    impl Authorizer for AllowAll {
        fn authorize_global(&self, _: &AuthUser, _: Permission) -> Result<(), AuthzError> {
            Ok(())
        }
        fn authorize_scoped(
            &self,
            _: &AuthUser,
            _: Permission,
            _: &DatabaseName,
            _: &Environment,
            _: &ResourceContext,
        ) -> Result<(), AuthzError> {
            Ok(())
        }
    }
    struct DenyAll;
    impl Authorizer for DenyAll {
        fn authorize_global(&self, _: &AuthUser, _: Permission) -> Result<(), AuthzError> {
            Err(AuthzError::Forbidden {
                permission: P::WorkflowManage,
                reason: "denied".into(),
            })
        }
        fn authorize_scoped(
            &self,
            _: &AuthUser,
            _: Permission,
            _: &DatabaseName,
            _: &Environment,
            _: &ResourceContext,
        ) -> Result<(), AuthzError> {
            Err(AuthzError::Forbidden {
                permission: P::WorkflowManage,
                reason: "denied".into(),
            })
        }
    }

    struct FakeLicense;
    impl LicenseChecker for FakeLicense {
        fn max_workflows(&self) -> u32 {
            5
        }
        fn max_databases(&self) -> u32 {
            u32::MAX
        }
        fn max_webhooks(&self) -> u32 {
            3
        }
        fn max_tokens(&self) -> u32 {
            10
        }
        fn max_roles(&self) -> u32 {
            8
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
        fn check_expiry(&self, _now: chrono::DateTime<chrono::Utc>) {}
    }

    struct FakeAudit;
    impl AuditLogger for FakeAudit {
        fn record(&self, _: &AuditEvent) -> Result<(), AppError> {
            Ok(())
        }
    }

    struct FakeClock;
    impl Clock for FakeClock {
        fn now(&self) -> chrono::DateTime<chrono::Utc> {
            chrono::Utc::now()
        }
    }

    struct FakePolicyRepo {
        wf_count: Mutex<u32>,
        role_count: Mutex<u32>,
    }
    impl FakePolicyRepo {
        fn new() -> Self {
            Self {
                wf_count: Mutex::new(0),
                role_count: Mutex::new(0),
            }
        }
    }
    impl PolicyRepo for FakePolicyRepo {
        fn create_workflow(&self, _: &Workflow) -> Result<(), AppError> {
            *self.wf_count.lock().unwrap() += 1;
            Ok(())
        }
        fn get_workflow(&self, _: &str) -> Result<Option<Workflow>, AppError> {
            Ok(None)
        }
        fn list_workflows(&self) -> Result<Vec<Workflow>, AppError> {
            Ok(vec![])
        }
        fn delete_workflow(&self, _: &str) -> Result<bool, AppError> {
            Ok(true)
        }
        fn count_workflows(&self) -> Result<u32, AppError> {
            Ok(*self.wf_count.lock().unwrap())
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
            Ok(true)
        }
        fn find_result_policy(
            &self,
            _: &DatabaseName,
            _: &Environment,
        ) -> Result<Option<dbward_domain::policies::ResultPolicy>, AppError> {
            Ok(None)
        }

        fn create_result_policy(
            &self,
            _: &dbward_domain::policies::ResultPolicy,
        ) -> Result<(), AppError> {
            Ok(())
        }
        fn get_result_policy(
            &self,
            _: &str,
        ) -> Result<Option<dbward_domain::policies::ResultPolicy>, AppError> {
            Ok(None)
        }
        fn list_result_policies(
            &self,
        ) -> Result<Vec<dbward_domain::policies::ResultPolicy>, AppError> {
            Ok(vec![])
        }
        fn update_result_policy(
            &self,
            _: &dbward_domain::policies::ResultPolicy,
        ) -> Result<bool, AppError> {
            Ok(false)
        }
        fn delete_result_policy(&self, _: &str) -> Result<bool, AppError> {
            Ok(false)
        }
        fn create_notification_policy(
            &self,
            _: &dbward_domain::policies::NotificationPolicy,
        ) -> Result<(), AppError> {
            Ok(())
        }
        fn get_notification_policy(
            &self,
            _: &str,
        ) -> Result<Option<dbward_domain::policies::NotificationPolicy>, AppError> {
            Ok(None)
        }
        fn list_notification_policies(
            &self,
        ) -> Result<Vec<dbward_domain::policies::NotificationPolicy>, AppError> {
            Ok(vec![])
        }
        fn update_notification_policy(
            &self,
            _: &dbward_domain::policies::NotificationPolicy,
        ) -> Result<bool, AppError> {
            Ok(false)
        }
        fn delete_notification_policy(&self, _: &str) -> Result<bool, AppError> {
            Ok(false)
        }
        fn create_role(&self, _: &RoleDefinition) -> Result<(), AppError> {
            *self.role_count.lock().unwrap() += 1;
            Ok(())
        }
        fn list_roles(&self) -> Result<Vec<RoleDefinition>, AppError> {
            Ok(vec![])
        }
        fn get_roles_by_names(&self, _: &[String]) -> Result<Vec<RoleDefinition>, AppError> {
            Ok(vec![])
        }
        fn delete_role(&self, _: &str) -> Result<bool, AppError> {
            Ok(true)
        }
        fn count_roles(&self) -> Result<u32, AppError> {
            Ok(*self.role_count.lock().unwrap())
        }
    }

    fn admin_user() -> AuthUser {
        AuthUser {
            subject_id: "admin".into(),
            subject_type: SubjectType::User,
            roles: vec![ResolvedRole {
                name: "admin".into(),
                permissions: [P::WorkflowManage, P::PolicyManage, P::RoleManage]
                    .into_iter()
                    .collect(),
                databases: vec![],
                environments: vec![],
            }],
            groups: vec![],
            token_id: None,
        }
    }

    #[allow(dead_code)]
    fn make_wf(id: &str) -> Workflow {
        Workflow {
            id: id.into(),
            database: DatabaseName::wildcard(),
            environment: Environment::wildcard(),
            operations: vec![],
            steps: vec![],
            require_reason: false,
            allow_self_approve: false,
            allow_same_approver_across_steps: false,
            explain: true,
            pending_ttl_secs: None,
            approval_ttl_secs: None,
            statement_timeout_secs: None,
            created_at: None,
            updated_at: None,
        }
    }

    struct FakeIdGen;
    impl IdGenerator for FakeIdGen {
        fn generate(&self) -> String {
            "test-id".into()
        }
    }

    fn make_uc(authz: Arc<dyn Authorizer>) -> PolicyManage {
        PolicyManage {
            authorizer: authz,
            policy_repo: Arc::new(FakePolicyRepo::new()),
            license: Arc::new(FakeLicense),
            audit: Arc::new(FakeAudit),
            clock: Arc::new(FakeClock),
            id_gen: Arc::new(FakeIdGen),
        }
    }

    #[test]
    fn create_workflow_denied_without_permission() {
        let uc = make_uc(Arc::new(DenyAll));
        assert!(matches!(
            uc.create_workflow(
                CreateWorkflowInput {
                    database: DatabaseName::wildcard(),
                    environment: Environment::wildcard(),
                    operations: vec![],
                    steps: vec![],
                    require_reason: false,
                },
                &admin_user(),
                &AuditContext::System,
            ),
            Err(AppError::Forbidden(_))
        ));
    }

    #[test]
    fn create_workflow_at_limit_returns_plan_limit() {
        let uc = PolicyManage {
            authorizer: Arc::new(AllowAll),
            policy_repo: Arc::new(FakePolicyRepo {
                wf_count: Mutex::new(5),
                role_count: Mutex::new(0),
            }),
            license: Arc::new(FakeLicense),
            audit: Arc::new(FakeAudit),
            clock: Arc::new(FakeClock),
            id_gen: Arc::new(FakeIdGen),
        };
        assert!(matches!(
            uc.create_workflow(
                CreateWorkflowInput {
                    database: DatabaseName::wildcard(),
                    environment: Environment::wildcard(),
                    operations: vec![],
                    steps: vec![],
                    require_reason: false,
                },
                &admin_user(),
                &AuditContext::System,
            ),
            Err(AppError::PlanLimit(_))
        ));
    }

    #[test]
    fn create_role_rejects_builtin_name() {
        let uc = make_uc(Arc::new(AllowAll));
        let role = RoleDefinition {
            name: "admin".into(),
            permissions: vec![],
            databases: vec![],
            environments: vec![],
        };
        assert!(matches!(
            uc.create_role(role, &admin_user(), &AuditContext::System),
            Err(AppError::Validation(_))
        ));
    }

    #[test]
    fn delete_role_rejects_builtin_name() {
        let uc = make_uc(Arc::new(AllowAll));
        assert!(matches!(
            uc.delete_role("agent-default", &admin_user()),
            Err(AppError::Validation(_))
        ));
    }
}
