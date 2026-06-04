use std::sync::Arc;

use dbward_domain::auth::{AuthUser, Permission, ResourceContext};
use dbward_domain::entities::RequestStatus;

use crate::error::AppError;
use crate::ports::*;

pub struct GetResult {
    pub authorizer: Arc<dyn Authorizer>,
    pub request_reader: Arc<dyn RequestReader>,
    pub agent_repo: Arc<dyn AgentRepo>,
    pub result_store: Arc<dyn ResultStore>,
    pub policy_repo: Arc<dyn PolicyRepo>,
    pub clock: Arc<dyn Clock>,
}

pub struct GetResultInput {
    pub request_id: String,
    pub execution_id: Option<String>,
}

pub struct GetResultOutput {
    pub stream: ResultStream,
    pub execution_id: String,
    pub success: bool,
}

impl GetResult {
    pub async fn execute(
        &self,
        input: GetResultInput,
        user: &AuthUser,
    ) -> Result<GetResultOutput, AppError> {
        let request = self
            .request_reader
            .get(&input.request_id)?
            .ok_or_else(|| AppError::NotFound("request not found".into()))?;

        if !matches!(
            request.status,
            RequestStatus::Executed | RequestStatus::Failed | RequestStatus::ExecutionLost
        ) {
            return Err(AppError::NotFound("result not available".into()));
        }

        if request.no_store && request.status != RequestStatus::Failed {
            return Err(AppError::Gone("result was not stored (no_store)".into()));
        }

        // Check if delivery_mode=Stream means result was intentionally not stored
        // Only applies to successful results (failures are always stored)
        if request.status != dbward_domain::entities::RequestStatus::Failed
            && let Ok(Some(policy)) = self
                .policy_repo
                .find_result_policy(&request.database, &request.environment)
            && matches!(
                policy.delivery_mode,
                dbward_domain::policies::DeliveryMode::Stream
            )
        {
            return Err(AppError::Gone(
                "result not stored by policy (stream-only delivery)".into(),
            ));
        }

        // Merge access selectors: request.share_with + ResultPolicy.access
        let mut access_selectors = request.share_with.clone();
        if let Ok(Some(policy)) = self
            .policy_repo
            .find_result_policy(&request.database, &request.environment)
        {
            for sel in &policy.access {
                let s = sel.to_string();
                if !access_selectors.contains(&s) {
                    access_selectors.push(s);
                }
            }
        }

        self.authorizer
            .authorize_scoped(
                user,
                Permission::ResultView,
                &request.database,
                &request.environment,
                &ResourceContext::Result {
                    requester_id: request.requester.clone(),
                    access_selectors,
                },
            )
            .map_err(AppError::Forbidden)?;

        let executions = self
            .agent_repo
            .find_executions_for_request(&input.request_id)?;
        let execution = if let Some(ref eid) = input.execution_id {
            // Specific execution requested
            let exec = executions
                .into_iter()
                .find(|e| e.id == *eid)
                .ok_or_else(|| AppError::NotFound("execution not found".into()))?;
            if !matches!(
                exec.status,
                dbward_domain::entities::ExecutionStatus::Completed
                    | dbward_domain::entities::ExecutionStatus::Failed
            ) {
                return Err(AppError::Conflict("execution still in progress".into()));
            }
            exec
        } else {
            // Latest terminal execution
            executions
                .into_iter()
                .rev()
                .find(|e| {
                    matches!(
                        e.status,
                        dbward_domain::entities::ExecutionStatus::Completed
                            | dbward_domain::entities::ExecutionStatus::Failed
                    )
                })
                .ok_or_else(|| AppError::NotFound("no terminal execution found".into()))?
        };

        // Retention: use ResultPolicy.retention_days if available, else 30
        let retention_days = match self
            .policy_repo
            .find_result_policy(&request.database, &request.environment)
        {
            Ok(Some(p)) => p.retention_days,
            Ok(None) => 30,
            Err(e) => return Err(e),
        };

        if let Some(expires_at) = execution.finished_at {
            let retention = chrono::Duration::days(retention_days as i64);
            if self.clock.now() > expires_at + retention {
                return Err(AppError::Gone(
                    "result expired (retention period exceeded)".into(),
                ));
            }
        }

        let success = execution.status == dbward_domain::entities::ExecutionStatus::Completed;
        let exec_id = execution.id.clone();
        let key = format!("results/{}/{}", input.request_id, execution.id);
        let stream = self
            .result_store
            .get_stream(&key)
            .await
            .map_err(|e| match &e {
                AppError::NotFound(_) => e,
                _ => AppError::Internal(format!("failed to read result from storage: {e}")),
            })?;

        Ok(GetResultOutput {
            stream,
            execution_id: exec_id,
            success,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AuthzError;
    use async_trait::async_trait;
    use chrono::{DateTime, Duration, Utc};
    use dbward_domain::auth::{AuthUser, Permission, ResourceContext, SubjectType};
    use dbward_domain::entities::*;
    use dbward_domain::policies::ResultPolicy;
    use dbward_domain::values::{DatabaseName, Environment, Selector};
    use std::sync::Mutex;

    // --- Fakes ---

    struct FakeAuthorizer;
    impl Authorizer for FakeAuthorizer {
        fn authorize_scoped(
            &self,
            _: &AuthUser,
            _: Permission,
            _: &DatabaseName,
            _: &Environment,
            ctx: &ResourceContext,
        ) -> Result<(), AuthzError> {
            // Accept if user is requester or in access_selectors
            if let ResourceContext::Result {
                requester_id,
                access_selectors,
            } = ctx
            {
                if requester_id == "alice" {
                    return Ok(());
                }
                if access_selectors.iter().any(|s| s == "role:dba") {
                    return Ok(());
                }
            }
            Err(AuthzError::Forbidden {
                permission: Permission::ResultView,
                reason: "denied".into(),
            })
        }
        fn authorize_global(&self, _: &AuthUser, _: Permission) -> Result<(), AuthzError> {
            Ok(())
        }
    }

    struct FakeRequestRepo {
        request: Mutex<Option<Request>>,
    }
    impl RequestReader for FakeRequestRepo {
        fn get(&self, _: &str) -> Result<Option<dbward_domain::entities::Request>, AppError> {
            Ok(self.request.lock().unwrap().clone())
        }
        fn list(
            &self,
            _: u32,
            _: u32,
            _: Option<&str>,
            _: Option<&str>,
        ) -> Result<(Vec<dbward_domain::entities::Request>, u32), AppError> {
            Ok((vec![], 0))
        }
        fn find_by_idempotency_key(
            &self,
            _: &str,
        ) -> Result<Option<dbward_domain::entities::Request>, AppError> {
            Ok(None)
        }
        fn list_visible_to_user(
            &self,
            _: &str,
            _: &[String],
            _: &[String],
            _: Option<&str>,
            _: u32,
            _: u32,
        ) -> Result<(Vec<dbward_domain::entities::Request>, u32), AppError> {
            Ok((vec![], 0))
        }
        fn list_pending_for_user(
            &self,
            _: &str,
            _: &[String],
            _: &[String],
            _: u32,
            _: u32,
        ) -> Result<(Vec<dbward_domain::entities::Request>, u32), AppError> {
            Ok((vec![], 0))
        }
        fn is_pending_approver(
            &self,
            _: &str,
            _: &str,
            _: &[String],
            _: &[String],
        ) -> Result<bool, AppError> {
            Ok(false)
        }
        fn count_executions(&self, _: &str) -> Result<u32, AppError> {
            Ok(0)
        }
        fn count_completed_executions(&self, _: &str) -> Result<u32, AppError> {
            Ok(0)
        }
        fn find_stored_execution_ids(&self, _: &str) -> Result<Vec<String>, AppError> {
            Ok(vec![])
        }
        fn list_results_for_user(
            &self,
            _: &str,
            _: &[String],
            _: &[String],
            _: u32,
        ) -> Result<Vec<crate::ports::repos::StoredResultEntry>, AppError> {
            Ok(vec![])
        }
        fn count_by_status(&self, _: &str) -> Result<u32, AppError> {
            Ok(0)
        }
        fn get_pending_approvers_for_requests(
            &self,
            _: &[&str],
        ) -> Result<std::collections::HashMap<String, (u32, Vec<String>)>, AppError> {
            Ok(std::collections::HashMap::new())
        }
    }

    struct FakeResultStore {
        data: Mutex<Vec<u8>>,
    }
    #[async_trait]
    impl ResultStore for FakeResultStore {
        async fn put(
            &self,
            _: &str,
            _: &[u8],
            _: crate::ports::PutOptions,
        ) -> Result<(), AppError> {
            Ok(())
        }
        async fn get_stream(&self, _: &str) -> Result<crate::ports::ResultStream, AppError> {
            let data = self.data.lock().unwrap().clone();
            let len = data.len() as u64;
            let chunk = bytes::Bytes::from(data);
            let stream: futures_core::stream::BoxStream<'static, Result<bytes::Bytes, AppError>> =
                Box::pin(OnceStream(Some(Ok(chunk))));
            Ok(crate::ports::ResultStream {
                content_length: Some(len),
                stream,
            })
        }
        async fn delete(&self, _: &str) -> Result<(), AppError> {
            Ok(())
        }
        async fn health_check(&self) -> Result<(), AppError> {
            Ok(())
        }
    }

    /// Minimal single-item stream for tests.
    struct OnceStream(Option<Result<bytes::Bytes, AppError>>);
    impl futures_core::Stream for OnceStream {
        type Item = Result<bytes::Bytes, AppError>;
        fn poll_next(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            std::task::Poll::Ready(self.0.take())
        }
    }

    struct FakePolicyRepo {
        policy: Mutex<Option<ResultPolicy>>,
    }
    impl PolicyRepo for FakePolicyRepo {
        fn find_result_policy(
            &self,
            _: &DatabaseName,
            _: &Environment,
        ) -> Result<Option<ResultPolicy>, AppError> {
            Ok(self.policy.lock().unwrap().clone())
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
        fn create_workflow(&self, _: &dbward_domain::policies::Workflow) -> Result<(), AppError> {
            Ok(())
        }
        fn get_workflow(
            &self,
            _: &str,
        ) -> Result<Option<dbward_domain::policies::Workflow>, AppError> {
            Ok(None)
        }
        fn list_workflows(&self) -> Result<Vec<dbward_domain::policies::Workflow>, AppError> {
            Ok(vec![])
        }
        fn delete_workflow(&self, _: &str) -> Result<bool, AppError> {
            Ok(true)
        }
        fn count_workflows(&self) -> Result<u32, AppError> {
            Ok(0)
        }
        fn create_execution_policy(
            &self,
            _: &dbward_domain::policies::ExecutionPolicy,
        ) -> Result<(), AppError> {
            Ok(())
        }
        fn get_execution_policy(
            &self,
            _: &str,
        ) -> Result<Option<dbward_domain::policies::ExecutionPolicy>, AppError> {
            Ok(None)
        }
        fn list_execution_policies(
            &self,
        ) -> Result<Vec<dbward_domain::policies::ExecutionPolicy>, AppError> {
            Ok(vec![])
        }
        fn delete_execution_policy(&self, _: &str) -> Result<bool, AppError> {
            Ok(true)
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
            Ok(true)
        }
        fn count_roles(&self) -> Result<u32, AppError> {
            Ok(0)
        }
    }

    struct FakeClock {
        now: DateTime<Utc>,
    }

    struct FakeAgentRepo {
        execution: Mutex<Option<Execution>>,
    }
    impl AgentRepo for FakeAgentRepo {
        fn upsert(&self, _: &Agent) -> Result<(), AppError> {
            Ok(())
        }
        fn get(&self, _: &str) -> Result<Option<Agent>, AppError> {
            Ok(None)
        }
        fn list(&self) -> Result<Vec<Agent>, AppError> {
            Ok(vec![])
        }
        fn create_execution(&self, _: &Execution) -> Result<(), AppError> {
            Ok(())
        }
        fn get_execution(&self, _: &str) -> Result<Option<Execution>, AppError> {
            Ok(self.execution.lock().unwrap().clone())
        }
        fn update_execution_status(&self, _: &str, _: ExecutionStatus) -> Result<(), AppError> {
            Ok(())
        }
        fn extend_lease(&self, _: &str, _: DateTime<Utc>) -> Result<(), AppError> {
            Ok(())
        }
        fn find_dispatched_jobs(
            &self,
            _: &[(DatabaseName, Environment)],
        ) -> Result<Vec<Request>, AppError> {
            Ok(vec![])
        }
        fn has_running_migration(
            &self,
            _: &DatabaseName,
            _: &Environment,
            _: &str,
        ) -> Result<bool, AppError> {
            Ok(false)
        }
        fn find_executions_for_request(&self, _: &str) -> Result<Vec<Execution>, AppError> {
            Ok(self.execution.lock().unwrap().iter().cloned().collect())
        }
        fn claim_and_mark_running(
            &self,
            _: &Execution,
            _: &str,
            _: DateTime<Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn complete_execution(
            &self,
            _: &str,
            _: &str,
            _: bool,
            _: DateTime<Utc>,
            _: &AuditEvent,
            _: Option<&ExecutionResult>,
            _: &[ResultAccess],
        ) -> Result<crate::ports::CompletionOutcome, AppError> {
            Ok(crate::ports::CompletionOutcome::Normal)
        }
        fn find_expired_leases(&self, _: &str) -> Result<Vec<(String, String)>, AppError> {
            Ok(vec![])
        }
        fn mark_execution_lost(&self, _: &str, _: &str, _: &str) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_execution_lost_and_record(
            &self,
            _: &str,
            _: &str,
            _: &AuditEvent,
            _: &str,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn find_expired_results(&self, _: &str) -> Result<Vec<(String, String)>, AppError> {
            Ok(vec![])
        }
        fn delete_result(&self, _: &str) -> Result<(), AppError> {
            Ok(())
        }
    }
    impl Clock for FakeClock {
        fn now(&self) -> DateTime<Utc> {
            self.now
        }
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
            decision_trace_json: None,
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
            request_reader: Arc::new(FakeRequestRepo {
                request: Mutex::new(Some(make_request())),
            }),
            agent_repo: Arc::new(FakeAgentRepo {
                execution: Mutex::new(Some(exec.clone())),
            }),
            result_store: Arc::new(FakeResultStore {
                data: Mutex::new(b"hello".to_vec()),
            }),
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

        let result = uc
            .execute(
                GetResultInput {
                    request_id: "req-1".into(),
                    execution_id: None,
                },
                &make_user("alice"),
            )
            .await;
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
            request_reader: Arc::new(FakeRequestRepo {
                request: Mutex::new(Some(make_request())),
            }),
            agent_repo: Arc::new(FakeAgentRepo {
                execution: Mutex::new(Some(exec)),
            }),
            result_store: Arc::new(FakeResultStore {
                data: Mutex::new(b"data".to_vec()),
            }),
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
        let result = uc
            .execute(
                GetResultInput {
                    request_id: "req-1".into(),
                    execution_id: None,
                },
                &make_user("bob"),
            )
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn fallback_30_days_when_no_policy() {
        let now = Utc::now();
        let mut exec = make_execution();
        exec.finished_at = Some(now - Duration::days(25));

        let uc = GetResult {
            authorizer: Arc::new(FakeAuthorizer),
            request_reader: Arc::new(FakeRequestRepo {
                request: Mutex::new(Some(make_request())),
            }),
            agent_repo: Arc::new(FakeAgentRepo {
                execution: Mutex::new(Some(exec)),
            }),
            result_store: Arc::new(FakeResultStore {
                data: Mutex::new(b"data".to_vec()),
            }),
            policy_repo: Arc::new(FakePolicyRepo {
                policy: Mutex::new(None),
            }),
            clock: Arc::new(FakeClock { now }),
        };

        // 25 days < 30 days default → should succeed
        let result = uc
            .execute(
                GetResultInput {
                    request_id: "req-1".into(),
                    execution_id: None,
                },
                &make_user("alice"),
            )
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn no_store_failed_request_returns_result() {
        let now = Utc::now();
        let mut req = make_request();
        req.no_store = true;
        req.status = RequestStatus::Failed;

        let mut exec = make_execution();
        exec.status = ExecutionStatus::Failed;
        exec.error_message = Some("timeout".into());

        let uc = GetResult {
            authorizer: Arc::new(FakeAuthorizer),
            request_reader: Arc::new(FakeRequestRepo {
                request: Mutex::new(Some(req)),
            }),
            agent_repo: Arc::new(FakeAgentRepo {
                execution: Mutex::new(Some(exec)),
            }),
            result_store: Arc::new(FakeResultStore {
                data: Mutex::new(b"{\"success\":false,\"error\":\"timeout\"}".to_vec()),
            }),
            policy_repo: Arc::new(FakePolicyRepo {
                policy: Mutex::new(None),
            }),
            clock: Arc::new(FakeClock { now }),
        };

        let result = uc
            .execute(
                GetResultInput {
                    request_id: "req-1".into(),
                    execution_id: None,
                },
                &make_user("alice"),
            )
            .await;
        assert!(result.is_ok());
        let out = result.unwrap();
        assert!(!out.success);
    }

    #[tokio::test]
    async fn no_store_success_returns_gone() {
        let now = Utc::now();
        let mut req = make_request();
        req.no_store = true;
        req.status = RequestStatus::Executed;

        let uc = GetResult {
            authorizer: Arc::new(FakeAuthorizer),
            request_reader: Arc::new(FakeRequestRepo {
                request: Mutex::new(Some(req)),
            }),
            agent_repo: Arc::new(FakeAgentRepo {
                execution: Mutex::new(Some(make_execution())),
            }),
            result_store: Arc::new(FakeResultStore {
                data: Mutex::new(vec![]),
            }),
            policy_repo: Arc::new(FakePolicyRepo {
                policy: Mutex::new(None),
            }),
            clock: Arc::new(FakeClock { now }),
        };

        let result = uc
            .execute(
                GetResultInput {
                    request_id: "req-1".into(),
                    execution_id: None,
                },
                &make_user("alice"),
            )
            .await;
        assert!(matches!(result, Err(AppError::Gone(_))));
    }

    #[tokio::test]
    async fn specific_execution_id_returns_that_execution() {
        let now = Utc::now();
        let uc = GetResult {
            authorizer: Arc::new(FakeAuthorizer),
            request_reader: Arc::new(FakeRequestRepo {
                request: Mutex::new(Some(make_request())),
            }),
            agent_repo: Arc::new(FakeAgentRepo {
                execution: Mutex::new(Some(make_execution())),
            }),
            result_store: Arc::new(FakeResultStore {
                data: Mutex::new(b"test data".to_vec()),
            }),
            policy_repo: Arc::new(FakePolicyRepo {
                policy: Mutex::new(None),
            }),
            clock: Arc::new(FakeClock { now }),
        };

        let result = uc
            .execute(
                GetResultInput {
                    request_id: "req-1".into(),
                    execution_id: Some("exec-1".into()),
                },
                &make_user("alice"),
            )
            .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().execution_id, "exec-1");
    }

    #[tokio::test]
    async fn invalid_execution_id_returns_not_found() {
        let now = Utc::now();
        let uc = GetResult {
            authorizer: Arc::new(FakeAuthorizer),
            request_reader: Arc::new(FakeRequestRepo {
                request: Mutex::new(Some(make_request())),
            }),
            agent_repo: Arc::new(FakeAgentRepo {
                execution: Mutex::new(Some(make_execution())),
            }),
            result_store: Arc::new(FakeResultStore {
                data: Mutex::new(vec![]),
            }),
            policy_repo: Arc::new(FakePolicyRepo {
                policy: Mutex::new(None),
            }),
            clock: Arc::new(FakeClock { now }),
        };

        let result = uc
            .execute(
                GetResultInput {
                    request_id: "req-1".into(),
                    execution_id: Some("nonexistent".into()),
                },
                &make_user("alice"),
            )
            .await;
        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
