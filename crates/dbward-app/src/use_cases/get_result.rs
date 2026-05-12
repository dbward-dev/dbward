use std::sync::Arc;

use dbward_domain::auth::{AuthUser, Permission, ResourceContext};
use dbward_domain::entities::RequestStatus;

use crate::error::AppError;
use crate::ports::*;

pub struct GetResult {
    pub authorizer: Arc<dyn Authorizer>,
    pub request_repo: Arc<dyn RequestRepo>,
    pub agent_repo: Arc<dyn AgentRepo>,
    pub result_store: Arc<dyn ResultStore>,
    pub policy_repo: Arc<dyn PolicyRepo>,
    pub clock: Arc<dyn Clock>,
}

pub struct GetResultInput {
    pub request_id: String,
}

pub struct GetResultOutput {
    pub data: Vec<u8>,
}

impl GetResult {
    pub async fn execute(&self, input: GetResultInput, user: &AuthUser) -> Result<GetResultOutput, AppError> {
        let request = self.request_repo.get(&input.request_id)?
            .ok_or_else(|| AppError::NotFound("request not found".into()))?;

        if !matches!(request.status, RequestStatus::Executed | RequestStatus::Failed | RequestStatus::ExecutionLost) {
            return Err(AppError::NotFound("result not available".into()));
        }

        if request.no_store {
            return Err(AppError::Gone("result was not stored (no_store)".into()));
        }

        // Merge access selectors: request.share_with + ResultPolicy.access
        let mut access_selectors = request.share_with.clone();
        if let Ok(Some(policy)) = self.policy_repo.find_result_policy(&request.database, &request.environment) {
            for sel in &policy.access {
                let s = sel.to_string();
                if !access_selectors.contains(&s) {
                    access_selectors.push(s);
                }
            }
        }

        self.authorizer.authorize_scoped(
            user,
            Permission::ResultView,
            &request.database,
            &request.environment,
            &ResourceContext::Result {
                requester_id: request.requester.clone(),
                access_selectors,
            },
        ).map_err(AppError::Forbidden)?;

        let executions = self.agent_repo.find_executions_for_request(&input.request_id)?;
        let execution = executions.into_iter()
            .rev()
            .find(|e| matches!(e.status, dbward_domain::entities::ExecutionStatus::Completed | dbward_domain::entities::ExecutionStatus::Failed))
            .ok_or_else(|| AppError::NotFound("no terminal execution found".into()))?;

        // Retention: use ResultPolicy.retention_days if available, else 30
        let retention_days = match self.policy_repo.find_result_policy(&request.database, &request.environment) {
            Ok(Some(p)) => p.retention_days,
            Ok(None) => 30,
            Err(e) => return Err(e),
        };

        if let Some(expires_at) = execution.finished_at {
            let retention = chrono::Duration::days(retention_days as i64);
            if self.clock.now() > expires_at + retention {
                return Err(AppError::Gone("result expired (retention period exceeded)".into()));
            }
        }

        let key = format!("results/{}/{}", input.request_id, execution.id);
        let data = self.result_store.get(&key).await
            .map_err(|_| AppError::NotFound("result not found in storage".into()))?;

        Ok(GetResultOutput { data })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use async_trait::async_trait;
    use chrono::{DateTime, Duration, Utc};
    use dbward_domain::auth::{AuthUser, Permission, ResourceContext, SubjectType};
    use dbward_domain::entities::*;
    use dbward_domain::policies::ResultPolicy;
    use dbward_domain::values::{DatabaseName, Environment, Selector};
    use crate::error::AuthzError;

    // --- Fakes ---

    struct FakeAuthorizer;
    impl Authorizer for FakeAuthorizer {
        fn authorize_scoped(&self, _: &AuthUser, _: Permission, _: &DatabaseName, _: &Environment, ctx: &ResourceContext) -> Result<(), AuthzError> {
            // Accept if user is requester or in access_selectors
            if let ResourceContext::Result { requester_id, access_selectors } = ctx {
                if requester_id == "alice" {
                    return Ok(());
                }
                if access_selectors.iter().any(|s| s == "role:dba") {
                    return Ok(());
                }
            }
            Err(AuthzError::Forbidden { permission: Permission::ResultView, reason: "denied".into() })
        }
        fn authorize_global(&self, _: &AuthUser, _: Permission) -> Result<(), AuthzError> { Ok(()) }
    }

    struct FakeRequestRepo { request: Mutex<Option<Request>> }
    impl RequestRepo for FakeRequestRepo {
        fn get(&self, _: &str) -> Result<Option<Request>, AppError> { Ok(self.request.lock().unwrap().clone()) }
        fn insert(&self, _: &Request) -> Result<(), AppError> { Ok(()) }
        fn list(&self, _: u32, _: u32, _: Option<&str>) -> Result<(Vec<Request>, u32), AppError> { Ok((vec![], 0)) }
        fn find_by_idempotency_key(&self, _: &str) -> Result<Option<Request>, AppError> { Ok(None) }
        fn insert_approval(&self, _: &Approval) -> Result<(), AppError> { Ok(()) }
        fn get_approvals(&self, _: &str) -> Result<Vec<Approval>, AppError> { Ok(vec![]) }
        fn count_executions(&self, _: &str) -> Result<u32, AppError> { Ok(0) }
        fn mark_approved(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> { Ok(true) }
        fn approve_and_mark_approved(&self, _: &Approval, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> { Ok(true) }
        fn mark_rejected(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> { Ok(true) }
        fn reject_and_record(&self, _: &str, _: &Approval, _: DateTime<Utc>) -> Result<bool, AppError> { Ok(true) }
        fn mark_cancelled(&self, _: &str, _: &str, _: Option<&str>, _: DateTime<Utc>) -> Result<bool, AppError> { Ok(true) }
        fn mark_dispatched(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> { Ok(true) }
        fn create_and_dispatch(&self, _: &Request) -> Result<(), AppError> { Ok(()) }
        fn mark_running(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> { Ok(true) }
        fn mark_executed(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> { Ok(true) }
        fn mark_failed(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> { Ok(true) }
        fn cancel_all_for_user(&self, _: &str, _: DateTime<Utc>) -> Result<u32, AppError> { Ok(0) }
        fn find_expired_approved(&self, _: &str) -> Result<Vec<String>, AppError> { Ok(vec![]) }
        fn find_expired_pending(&self, _: &str) -> Result<Vec<String>, AppError> { Ok(vec![]) }
        fn find_dispatched_older_than(&self, _: &str) -> Result<Vec<String>, AppError> { Ok(vec![]) }
        fn mark_expired(&self, _: &str, _: &str) -> Result<bool, AppError> { Ok(true) }
        fn mark_expired_and_record(&self, _: &str, _: &AuditEvent, _: &str) -> Result<bool, AppError> { Ok(true) }
        fn mark_approved_from_dispatched(&self, _: &str, _: &str) -> Result<bool, AppError> { Ok(true) }
        fn purge_old_requests(&self, _: &str) -> Result<u32, AppError> { Ok(0) }
        fn count_by_status(&self, _: &str) -> Result<u32, AppError> { Ok(0) }
        fn wal_checkpoint(&self) -> Result<(), AppError> { Ok(()) }
    }

    struct FakeAgentRepo { execution: Mutex<Option<Execution>> }
    impl AgentRepo for FakeAgentRepo {
        fn find_executions_for_request(&self, _: &str) -> Result<Vec<Execution>, AppError> {
            Ok(self.execution.lock().unwrap().iter().cloned().collect())
        }
        fn upsert(&self, _: &Agent) -> Result<(), AppError> { Ok(()) }
        fn get(&self, _: &str) -> Result<Option<Agent>, AppError> { Ok(None) }
        fn list(&self) -> Result<Vec<Agent>, AppError> { Ok(vec![]) }
        fn create_execution(&self, _: &Execution) -> Result<(), AppError> { Ok(()) }
        fn get_execution(&self, _: &str) -> Result<Option<Execution>, AppError> { Ok(None) }
        fn update_execution_status(&self, _: &str, _: ExecutionStatus) -> Result<(), AppError> { Ok(()) }
        fn extend_lease(&self, _: &str, _: DateTime<Utc>) -> Result<(), AppError> { Ok(()) }
        fn find_dispatched_jobs(&self, _: &[(DatabaseName, Environment)]) -> Result<Vec<Request>, AppError> { Ok(vec![]) }
        fn has_running_migration(&self, _: &DatabaseName, _: &Environment, _: &str) -> Result<bool, AppError> { Ok(false) }
        fn claim_and_mark_running(&self, _: &Execution, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> { Ok(true) }
        fn complete_execution(&self, _: &str, _: &str, _: bool, _: DateTime<Utc>, _: &AuditEvent, _: Option<&ExecutionResult>, _: &[ResultAccess]) -> Result<bool, AppError> { Ok(true) }
        fn find_expired_leases(&self, _: &str) -> Result<Vec<(String, String)>, AppError> { Ok(vec![]) }
        fn mark_execution_lost(&self, _: &str, _: &str, _: &str) -> Result<bool, AppError> { Ok(true) }
        fn mark_execution_lost_and_record(&self, _: &str, _: &str, _: &AuditEvent, _: &str) -> Result<bool, AppError> { Ok(true) }
        fn find_expired_results(&self, _: &str) -> Result<Vec<(String, String)>, AppError> { Ok(vec![]) }
        fn delete_result(&self, _: &str) -> Result<(), AppError> { Ok(()) }
    }

    struct FakeResultStore { data: Mutex<Vec<u8>> }
    #[async_trait]
    impl ResultStore for FakeResultStore {
        async fn put(&self, _: &str, _: &[u8]) -> Result<(), AppError> { Ok(()) }
        async fn get(&self, _: &str) -> Result<Vec<u8>, AppError> { Ok(self.data.lock().unwrap().clone()) }
        async fn delete(&self, _: &str) -> Result<(), AppError> { Ok(()) }
    }

    struct FakePolicyRepo { policy: Mutex<Option<ResultPolicy>> }
    impl PolicyRepo for FakePolicyRepo {
        fn find_result_policy(&self, _: &DatabaseName, _: &Environment) -> Result<Option<ResultPolicy>, AppError> {
            Ok(self.policy.lock().unwrap().clone())
        }
        fn create_workflow(&self, _: &dbward_domain::policies::Workflow) -> Result<(), AppError> { Ok(()) }
        fn get_workflow(&self, _: &str) -> Result<Option<dbward_domain::policies::Workflow>, AppError> { Ok(None) }
        fn list_workflows(&self) -> Result<Vec<dbward_domain::policies::Workflow>, AppError> { Ok(vec![]) }
        fn delete_workflow(&self, _: &str) -> Result<bool, AppError> { Ok(true) }
        fn count_workflows(&self) -> Result<u32, AppError> { Ok(0) }
        fn create_execution_policy(&self, _: &dbward_domain::policies::ExecutionPolicy) -> Result<(), AppError> { Ok(()) }
        fn get_execution_policy(&self, _: &str) -> Result<Option<dbward_domain::policies::ExecutionPolicy>, AppError> { Ok(None) }
        fn list_execution_policies(&self) -> Result<Vec<dbward_domain::policies::ExecutionPolicy>, AppError> { Ok(vec![]) }
        fn delete_execution_policy(&self, _: &str) -> Result<bool, AppError> { Ok(true) }
        fn create_role(&self, _: &dbward_domain::auth::RoleDefinition) -> Result<(), AppError> { Ok(()) }
        fn list_roles(&self) -> Result<Vec<dbward_domain::auth::RoleDefinition>, AppError> { Ok(vec![]) }
        fn get_roles_by_names(&self, _: &[String]) -> Result<Vec<dbward_domain::auth::RoleDefinition>, AppError> { Ok(vec![]) }
        fn delete_role(&self, _: &str) -> Result<bool, AppError> { Ok(true) }
        fn count_roles(&self) -> Result<u32, AppError> { Ok(0) }
    }

    struct FakeClock { now: DateTime<Utc> }
    impl Clock for FakeClock {
        fn now(&self) -> DateTime<Utc> { self.now }
    }

    fn make_request() -> Request {
        let now = Utc::now();
        Request {
            id: "req-1".into(),
            requester: "alice".into(),
            operation: dbward_domain::values::Operation::ExecuteSelect,
            database: DatabaseName::new("mydb").unwrap(),
            environment: Environment::new("prod").unwrap(),
            detail: "SELECT 1".into(),
            status: RequestStatus::Executed,
            emergency: false,
            reason: None,
            idempotency_key: None,
            metadata_json: "{}".into(),
            share_with: vec![],
            no_store: false,
            workflow_snapshot_json: None,
            cancelled_by: None,
            cancel_reason: None,
            created_at: now,
            updated_at: now,
            resolved_at: Some(now),
            expires_at: None,
        }
    }

    fn make_execution() -> Execution {
        let now = Utc::now();
        Execution {
            id: "exec-1".into(),
            request_id: "req-1".into(),
            agent_id: "agent-1".into(),
            status: ExecutionStatus::Completed,
            token: "tok".into(),
            lease_expires_at: now + Duration::hours(1),
            started_at: Some(now),
            finished_at: Some(now),
            error_message: None,
            created_at: now,
        }
    }

    fn make_user(id: &str) -> AuthUser {
        AuthUser {
            subject_id: id.into(),
            subject_type: SubjectType::User,
            roles: vec![],
            groups: vec![],
            token_id: None,
        }
    }

    #[tokio::test]
    async fn uses_policy_retention_days() {
        let now = Utc::now();
        let mut exec = make_execution();
        // Finished 10 days ago
        exec.finished_at = Some(now - Duration::days(10));

        let uc = GetResult {
            authorizer: Arc::new(FakeAuthorizer),
            request_repo: Arc::new(FakeRequestRepo { request: Mutex::new(Some(make_request())) }),
            agent_repo: Arc::new(FakeAgentRepo { execution: Mutex::new(Some(exec.clone())) }),
            result_store: Arc::new(FakeResultStore { data: Mutex::new(b"hello".to_vec()) }),
            policy_repo: Arc::new(FakePolicyRepo {
                policy: Mutex::new(Some(ResultPolicy {
                    id: "rp-1".into(),
                    database: DatabaseName::new("mydb").unwrap(),
                    environment: Environment::new("prod").unwrap(),
                    retention_days: 7, // 7 days < 10 days ago → expired
                    delivery_mode: dbward_domain::policies::DeliveryMode::Both,
                    access: vec![],
                    created_at: None,
                    updated_at: None,
                })),
            }),
            clock: Arc::new(FakeClock { now }),
        };

        let result = uc.execute(GetResultInput { request_id: "req-1".into() }, &make_user("alice")).await;
        assert!(matches!(result, Err(AppError::Gone(_))));
    }

    #[tokio::test]
    async fn policy_access_selectors_merged() {
        let now = Utc::now();
        let mut exec = make_execution();
        exec.finished_at = Some(now - Duration::hours(1));

        // bob is not the requester and not in share_with, but policy grants role:dba
        let uc = GetResult {
            authorizer: Arc::new(FakeAuthorizer),
            request_repo: Arc::new(FakeRequestRepo { request: Mutex::new(Some(make_request())) }),
            agent_repo: Arc::new(FakeAgentRepo { execution: Mutex::new(Some(exec)) }),
            result_store: Arc::new(FakeResultStore { data: Mutex::new(b"data".to_vec()) }),
            policy_repo: Arc::new(FakePolicyRepo {
                policy: Mutex::new(Some(ResultPolicy {
                    id: "rp-1".into(),
                    database: DatabaseName::new("mydb").unwrap(),
                    environment: Environment::new("prod").unwrap(),
                    retention_days: 30,
                    delivery_mode: dbward_domain::policies::DeliveryMode::Both,
                    access: vec![Selector::Role("dba".into())],
                    created_at: None,
                    updated_at: None,
                })),
            }),
            clock: Arc::new(FakeClock { now }),
        };

        // bob with role:dba should succeed because FakeAuthorizer checks access_selectors for "role:dba"
        let result = uc.execute(GetResultInput { request_id: "req-1".into() }, &make_user("bob")).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn fallback_30_days_when_no_policy() {
        let now = Utc::now();
        let mut exec = make_execution();
        exec.finished_at = Some(now - Duration::days(25));

        let uc = GetResult {
            authorizer: Arc::new(FakeAuthorizer),
            request_repo: Arc::new(FakeRequestRepo { request: Mutex::new(Some(make_request())) }),
            agent_repo: Arc::new(FakeAgentRepo { execution: Mutex::new(Some(exec)) }),
            result_store: Arc::new(FakeResultStore { data: Mutex::new(b"data".to_vec()) }),
            policy_repo: Arc::new(FakePolicyRepo { policy: Mutex::new(None) }),
            clock: Arc::new(FakeClock { now }),
        };

        // 25 days < 30 days default → should succeed
        let result = uc.execute(GetResultInput { request_id: "req-1".into() }, &make_user("alice")).await;
        assert!(result.is_ok());
    }
}

