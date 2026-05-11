use std::sync::Arc;

use dbward_domain::auth::{AuthUser, Permission, ResourceContext};
use dbward_domain::entities::{Request, RequestStatus};
use dbward_domain::services::{status_machine, workflow_matcher};
use dbward_domain::values::{DatabaseName, Environment, Operation};

use crate::error::AppError;
use crate::ports::*;

pub struct CreateRequest {
    pub authorizer: Arc<dyn Authorizer>,
    pub policy: Arc<dyn PolicyEvaluator>,
    pub request_repo: Arc<dyn RequestRepo>,
    pub db_registry: Arc<dyn DatabaseRegistry>,
    pub audit: Arc<dyn AuditLogger>,
    pub notifier: Arc<dyn Notifier>,
    pub clock: Arc<dyn Clock>,
    pub id_gen: Arc<dyn IdGenerator>,
}

#[derive(Clone)]
pub struct CreateRequestInput {
    pub database: DatabaseName,
    pub environment: Environment,
    pub operation: Operation,
    pub detail: String,
    pub reason: Option<String>,
    pub emergency: bool,
    pub idempotency_key: Option<String>,
    pub share_with: Vec<String>,
    pub no_store: bool,
    pub metadata_json: String,
}

pub struct CreateRequestOutput {
    pub id: String,
    pub status: RequestStatus,
    pub operation: Operation,
}

impl CreateRequest {
    pub fn execute(&self, input: CreateRequestInput, user: &AuthUser) -> Result<CreateRequestOutput, AppError> {
        // 1. Permission + DB/env scope check
        let perm = if input.emergency {
            Permission::RequestBreakGlass
        } else {
            Permission::RequestCreate
        };
        self.authorizer
            .authorize_scoped(user, perm, &input.database, &input.environment, &ResourceContext::Global)
            .map_err(AppError::Forbidden)?;

        // 2. DB registered?
        if !self.db_registry.exists(&input.database, &input.environment)? {
            return Err(AppError::Validation("database not registered".into()));
        }

        // 3. Idempotency
        if let Some(key) = &input.idempotency_key {
            if let Some(existing) = self.request_repo.find_by_idempotency_key(key)? {
                return Ok(CreateRequestOutput {
                    id: existing.id,
                    status: existing.status,
                    operation: existing.operation,
                });
            }
        }

        // 4. Workflow evaluation
        let workflow = self.policy.evaluate_workflow(&input.database, &input.environment, input.operation)?;
        let role_names: Vec<String> = user.roles.iter().map(|r| r.name.clone()).collect();
        let decision = workflow_matcher::evaluate(
            workflow.as_ref(),
            &role_names,
            &user.groups,
            &user.subject_id,
            true,
        );

        // 5. Determine initial status via status_machine
        let needs_approval = !matches!(decision, workflow_matcher::ApprovalDecision::AutoApproved);
        let status = status_machine::initial_status(needs_approval, input.emergency);

        // 6. Serialize workflow snapshot for approve/reject
        let workflow_snapshot_json = workflow.as_ref().map(|wf| serde_json::to_string(wf).unwrap());

        // 7. Create request
        let now = self.clock.now();
        let id = self.id_gen.generate();
        let request = Request {
            id: id.clone(),
            requester: user.subject_id.clone(),
            database: input.database,
            environment: input.environment,
            operation: input.operation,
            detail: input.detail,
            status,
            emergency: input.emergency,
            reason: input.reason,
            idempotency_key: input.idempotency_key,
            metadata_json: input.metadata_json,
            share_with: input.share_with,
            no_store: input.no_store,
            workflow_snapshot_json,
            cancel_reason: None,
            cancelled_by: None,
            created_at: now,
            updated_at: now,
            resolved_at: None,
            expires_at: None,
        };
        self.request_repo.insert(&request)?;

        Ok(CreateRequestOutput { id, status, operation: input.operation })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dbward_domain::auth::{ResolvedRole, SubjectType};
    use std::collections::HashSet;

    struct AllowAll;
    impl Authorizer for AllowAll {
        fn authorize_scoped(&self, _: &AuthUser, _: Permission, _: &DatabaseName, _: &Environment, _: &ResourceContext) -> Result<(), crate::error::AuthzError> { Ok(()) }
        fn authorize_global(&self, _: &AuthUser, _: Permission) -> Result<(), crate::error::AuthzError> { Ok(()) }
    }

    struct DenyAll;
    impl Authorizer for DenyAll {
        fn authorize_scoped(&self, _: &AuthUser, p: Permission, _: &DatabaseName, _: &Environment, _: &ResourceContext) -> Result<(), crate::error::AuthzError> {
            Err(crate::error::AuthzError::Forbidden { permission: p, reason: "denied".into() })
        }
        fn authorize_global(&self, _: &AuthUser, p: Permission) -> Result<(), crate::error::AuthzError> {
            Err(crate::error::AuthzError::Forbidden { permission: p, reason: "denied".into() })
        }
    }

    struct FakePolicy;
    impl PolicyEvaluator for FakePolicy {
        fn evaluate_workflow(&self, _: &DatabaseName, _: &Environment, _: Operation) -> Result<Option<dbward_domain::policies::Workflow>, AppError> { Ok(None) }
        fn get_execution_policy(&self, _: &DatabaseName, _: &Environment) -> dbward_domain::policies::ExecutionPolicy { Default::default() }
    }

    struct FakeRequestRepo;
    impl RequestRepo for FakeRequestRepo {
        fn insert(&self, _: &Request) -> Result<(), AppError> { Ok(()) }
        fn get(&self, _: &str) -> Result<Option<Request>, AppError> { Ok(None) }
        fn find_by_idempotency_key(&self, _: &str) -> Result<Option<Request>, AppError> { Ok(None) }
        fn insert_approval(&self, _: &dbward_domain::entities::Approval) -> Result<(), AppError> { Ok(()) }
        fn get_approvals(&self, _: &str) -> Result<Vec<dbward_domain::entities::Approval>, AppError> { Ok(vec![]) }
        fn count_executions(&self, _: &str) -> Result<u32, AppError> { Ok(0) }
        fn mark_approved(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> { Ok(true) }
        fn mark_rejected(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> { Ok(true) }
        fn mark_cancelled(&self, _: &str, _: &str, _: Option<&str>, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> { Ok(true) }
        fn mark_dispatched(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> { Ok(true) }
        fn mark_running(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> { Ok(true) }
        fn mark_executed(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> { Ok(true) }
        fn mark_failed(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> { Ok(true) }
    }

    struct FakeDbRegistry;
    impl DatabaseRegistry for FakeDbRegistry {
        fn exists(&self, _: &DatabaseName, _: &Environment) -> Result<bool, AppError> { Ok(true) }
        fn list(&self) -> Result<Vec<(DatabaseName, Environment)>, AppError> { Ok(vec![]) }
    }

    struct FakeAudit;
    impl AuditLogger for FakeAudit {
        fn record(&self, _: &dbward_domain::entities::AuditEvent) -> Result<(), AppError> { Ok(()) }
    }

    struct FakeNotifier;
    impl Notifier for FakeNotifier {
        fn dispatch(&self, _: crate::ports::WebhookEvent) {}
    }

    struct FakeClock;
    impl Clock for FakeClock {
        fn now(&self) -> chrono::DateTime<chrono::Utc> { chrono::Utc::now() }
    }

    struct FakeIdGen;
    impl IdGenerator for FakeIdGen {
        fn generate(&self) -> String { "test-id-001".into() }
    }

    fn make_uc(authorizer: Arc<dyn Authorizer>) -> CreateRequest {
        CreateRequest {
            authorizer,
            policy: Arc::new(FakePolicy),
            request_repo: Arc::new(FakeRequestRepo),
            db_registry: Arc::new(FakeDbRegistry),
            audit: Arc::new(FakeAudit),
            notifier: Arc::new(FakeNotifier),
            clock: Arc::new(FakeClock),
            id_gen: Arc::new(FakeIdGen),
        }
    }

    fn make_user() -> AuthUser {
        AuthUser {
            subject_id: "alice".into(),
            subject_type: SubjectType::User,
            roles: vec![ResolvedRole {
                name: "app-dev".into(),
                permissions: [Permission::RequestCreate, Permission::RequestView].into_iter().collect(),
                databases: vec![DatabaseName::new("app").unwrap()],
                environments: vec![Environment::new("production").unwrap()],
            }],
            groups: vec![],
            token_id: Some("t1".into()),
        }
    }

    fn make_input() -> CreateRequestInput {
        CreateRequestInput {
            database: DatabaseName::new("app").unwrap(),
            environment: Environment::new("production").unwrap(),
            operation: Operation::ExecuteSelect,
            detail: "SELECT 1".into(),
            reason: None,
            emergency: false,
            idempotency_key: None,
            share_with: vec![],
            no_store: false,
            metadata_json: "{}".into(),
        }
    }

    #[test]
    fn success_creates_pending_request() {
        let uc = make_uc(Arc::new(AllowAll));
        let result = uc.execute(make_input(), &make_user()).unwrap();
        assert_eq!(result.id, "test-id-001");
        assert_eq!(result.status, RequestStatus::Pending);
    }

    #[test]
    fn denied_by_authorizer() {
        let uc = make_uc(Arc::new(DenyAll));
        let result = uc.execute(make_input(), &make_user());
        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
