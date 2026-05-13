use std::sync::Arc;

use dbward_domain::auth::{AuthUser, Permission, ResourceContext};
use dbward_domain::entities::{
    AuditEvent, ExecutionResult, ExecutionStatus, RequestStatus, ResultAccess, SelectorType,
};
use dbward_domain::services::status_machine::{
    self, EventMetadata, RequestTrigger, TransitionContext,
};
use dbward_domain::values::ResultSummary;

use crate::error::AppError;
use crate::ports::*;

pub struct AgentSubmitResult {
    pub authorizer: Arc<dyn Authorizer>,
    pub agent_repo: Arc<dyn AgentRepo>,
    pub request_repo: Arc<dyn RequestRepo>,
    pub result_store: Arc<dyn ResultStore>,
    pub result_channel: Arc<dyn ResultChannel>,
    pub event_dispatcher: Arc<dyn EventDispatcher>,
    pub clock: Arc<dyn Clock>,
}

pub struct AgentSubmitResultInput {
    pub execution_id: String,
    pub success: bool,
    pub result_data: Option<Vec<u8>>,
    pub error_message: Option<String>,
}

pub struct AgentSubmitResultOutput {
    pub request_id: String,
    pub status: RequestStatus,
}

impl AgentSubmitResult {
    pub async fn execute(
        &self,
        input: AgentSubmitResultInput,
        user: &AuthUser,
    ) -> Result<AgentSubmitResultOutput, AppError> {
        // 1. Authorization (global)
        self.authorizer
            .authorize_global(user, Permission::AgentSubmitResult)
            .map_err(AppError::Forbidden)?;

        // 2. Get execution
        let execution = self
            .agent_repo
            .get_execution(&input.execution_id)?
            .ok_or_else(|| AppError::NotFound("execution not found".into()))?;

        // 3. Resource-level authorization (agent_id match via Authorizer)
        self.authorizer
            .authorize_scoped(
                user,
                Permission::AgentSubmitResult,
                &dbward_domain::values::DatabaseName::wildcard(),
                &dbward_domain::values::Environment::wildcard(),
                &ResourceContext::AgentExecution {
                    agent_id: execution.agent_id.clone(),
                },
            )
            .map_err(AppError::Forbidden)?;

        // 4. Verify execution is still active
        if execution.status != ExecutionStatus::Claimed {
            return Err(AppError::Conflict(format!(
                "execution is {:?}, cannot submit result",
                execution.status
            )));
        }

        // 5. Get request
        let request = self
            .request_repo
            .get(&execution.request_id)?
            .ok_or_else(|| AppError::Internal("request not found for execution".into()))?;

        // 6. Determine final status via status_machine
        // (Cancelled, Complete) → Cancelled is handled by status_machine (ADR-003/004)
        let now = self.clock.now();
        let result = status_machine::transition(
            request.status,
            &RequestTrigger::Complete {
                success: input.success,
            },
            TransitionContext {
                request_id: request.id.clone(),
                actor_id: user.subject_id.clone(),
                actor_type: user.subject_type,
                database: request.database.clone(),
                environment: request.environment.clone(),
                operation: request.operation,
                timestamp: now,
                metadata: EventMetadata::Completed {
                    success: input.success,
                    execution_id: execution.id.clone(),
                },
                requester_id: request.requester.clone(),
            },
        )
        .map_err(|e| AppError::Conflict(e.to_string()))?;

        let new_request_status = result.status();

        // 7. Store result to external storage
        let mut result_manifest: Option<ExecutionResult> = None;
        let data_len: u64;
        if input.success && !request.no_store {
            if let Some(data) = &input.result_data {
                let storage_key = format!("results/{}/{}", execution.request_id, execution.id);
                self.result_store.put(&storage_key, data).await?;
                data_len = data.len() as u64;
                let stored_at = self.clock.now();
                result_manifest = Some(ExecutionResult {
                    id: format!("res-{}", execution.id),
                    request_id: execution.request_id.clone(),
                    execution_id: execution.id.clone(),
                    storage_backend: "local".to_string(),
                    storage_key,
                    content_length: data_len,
                    checksum_sha256: String::new(),
                    retention_days: 30,
                    status: dbward_domain::entities::ResultStatus::Stored,
                    truncated: false,
                    truncation_reason: None,
                    stored_at,
                    expires_at: stored_at + chrono::Duration::days(30),
                });
            }
        } else if !input.success {
            // Store failure info
            let err_json = serde_json::json!({
                "success": false,
                "error": input.error_message.as_deref().unwrap_or("unknown error"),
            });
            let storage_key = format!("results/{}/{}", execution.request_id, execution.id);
            self.result_store
                .put(&storage_key, err_json.to_string().as_bytes())
                .await?;
        }

        // Build share_with ResultAccess records
        let share_with_records: Vec<ResultAccess> = if let Some(ref rm) = result_manifest {
            request
                .share_with
                .iter()
                .enumerate()
                .map(|(i, sel)| {
                    let (st, sv) = parse_selector_for_access(sel);
                    ResultAccess {
                        id: format!("{}-ra-{}", rm.id, i),
                        result_id: rm.id.clone(),
                        selector_type: st,
                        selector_value: sv,
                    }
                })
                .collect()
        } else {
            vec![]
        };

        // 8. Atomically update execution + request status + audit + result manifest
        let now = self.clock.now();
        let mut audit_event = AuditEvent::simple(
            if input.success {
                "execution.completed"
            } else {
                "execution.failed"
            },
            "execution",
            &user.subject_id,
            Some(&execution.id),
        );
        audit_event.database_name = Some(request.database.to_string());
        audit_event.environment = Some(request.environment.to_string());
        audit_event.operation = Some(request.operation.as_str().to_string());
        let request_updated = match self.agent_repo.complete_execution(
            &execution.id,
            &execution.request_id,
            input.success,
            now,
            &audit_event,
            result_manifest.as_ref(),
            &share_with_records,
        ) {
            Ok(v) => v,
            Err(e) => {
                // Compensate: delete orphaned storage object
                if let Some(ref rm) = result_manifest {
                    if let Err(del_err) = self.result_store.delete(&rm.storage_key).await {
                        tracing::error!(key = %rm.storage_key, error = %del_err, "compensation delete failed for stored result");
                    }
                } else if !input.success {
                    let storage_key = format!("results/{}/{}", execution.request_id, execution.id);
                    if let Err(del_err) = self.result_store.delete(&storage_key).await {
                        tracing::error!(key = %storage_key, error = %del_err, "compensation delete failed for error result");
                    }
                }
                return Err(e);
            }
        };

        // 9. Publish result to long-poll channel
        let summary = ResultSummary {
            execution_id: execution.id.clone(),
            success: input.success,
            rows_affected: None,
            truncated: false,
            error_message: input.error_message.clone(),
            result_data: if input.success {
                input
                    .result_data
                    .as_ref()
                    .map(|d| String::from_utf8_lossy(d).into_owned())
            } else {
                None
            },
        };
        self.result_channel
            .publish(&execution.request_id, summary)
            .await;

        // If request was cancelled, new_request_status reflects that
        let final_status = if !request_updated && new_request_status != RequestStatus::Cancelled {
            return Err(AppError::Conflict("concurrent status change".into()));
        } else {
            new_request_status
        };

        result.commit(&*self.event_dispatcher);

        Ok(AgentSubmitResultOutput {
            request_id: execution.request_id,
            status: final_status,
        })
    }
}

fn parse_selector_for_access(sel: &str) -> (SelectorType, String) {
    if let Some(val) = sel.strip_prefix("role:") {
        (SelectorType::Role, val.to_string())
    } else if let Some(val) = sel.strip_prefix("group:") {
        (SelectorType::Group, val.to_string())
    } else if let Some(val) = sel.strip_prefix("user:") {
        (SelectorType::User, val.to_string())
    } else {
        (SelectorType::User, sel.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AuthzError;
    use async_trait::async_trait;
    use chrono::{DateTime, Utc};
    use dbward_domain::auth::{Permission as P, ResolvedRole, ResourceContext, SubjectType};
    use dbward_domain::entities::{
        Agent, Approval, AuditEvent, Execution, ExecutionStatus, Request as DomainRequest,
        RequestStatus,
    };
    use dbward_domain::services::status_machine::{EventDispatcher, TransitionEvent};
    use dbward_domain::values::{DatabaseName, Environment, Operation, ResultSummary};
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

    struct FakeClock;
    impl Clock for FakeClock {
        fn now(&self) -> DateTime<Utc> {
            Utc::now()
        }
    }

    struct NoopDispatcher;
    impl EventDispatcher for NoopDispatcher {
        fn dispatch(&self, _: TransitionEvent) {}
    }

    struct FakeAgentRepo {
        execution: Mutex<Option<Execution>>,
    }
    impl AgentRepo for FakeAgentRepo {
        fn get_execution(&self, _: &str) -> Result<Option<Execution>, AppError> {
            Ok(self.execution.lock().unwrap().clone())
        }
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
        fn update_execution_status(&self, _: &str, _: ExecutionStatus) -> Result<(), AppError> {
            Ok(())
        }
        fn extend_lease(&self, _: &str, _: DateTime<Utc>) -> Result<(), AppError> {
            Ok(())
        }
        fn find_dispatched_jobs(
            &self,
            _: &[(DatabaseName, Environment)],
        ) -> Result<Vec<DomainRequest>, AppError> {
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
            Ok(vec![])
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
        ) -> Result<bool, AppError> {
            Ok(true)
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

    struct FakeRequestRepo {
        request: Mutex<Option<DomainRequest>>,
    }
    impl RequestRepo for FakeRequestRepo {
        fn get(&self, _: &str) -> Result<Option<DomainRequest>, AppError> {
            Ok(self.request.lock().unwrap().clone())
        }
        fn insert(&self, _: &DomainRequest) -> Result<(), AppError> {
            Ok(())
        }
        fn list(
            &self,
            _: u32,
            _: u32,
            _: Option<&str>,
            _: Option<&str>,
        ) -> Result<(Vec<DomainRequest>, u32), AppError> {
            Ok((vec![], 0))
        }
        fn find_by_idempotency_key(&self, _: &str) -> Result<Option<DomainRequest>, AppError> {
            Ok(None)
        }
        fn list_pending_for_user(
            &self,
            _: &str,
            _: &[String],
            _: &[String],
            _: u32,
            _: u32,
        ) -> Result<(Vec<DomainRequest>, u32), AppError> {
            Ok((vec![], 0))
        }
        fn insert_approval(&self, _: &Approval) -> Result<(), AppError> {
            Ok(())
        }
        fn get_approvals(&self, _: &str) -> Result<Vec<Approval>, AppError> {
            Ok(vec![])
        }
        fn count_executions(&self, _: &str) -> Result<u32, AppError> {
            Ok(0)
        }
        fn mark_approved(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
        fn approve_and_mark_approved(
            &self,
            _: &Approval,
            _: &str,
            _: DateTime<Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_rejected(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
        fn reject_and_record(
            &self,
            _: &str,
            _: &Approval,
            _: DateTime<Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_cancelled(
            &self,
            _: &str,
            _: &str,
            _: Option<&str>,
            _: DateTime<Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_dispatched(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
        fn create_and_dispatch(&self, _: &DomainRequest) -> Result<(), AppError> {
            Ok(())
        }
        fn mark_running(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_executed(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_failed(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
        fn cancel_all_for_user(&self, _: &str, _: DateTime<Utc>) -> Result<u32, AppError> {
            Ok(0)
        }
        fn find_expired_approved(&self, _: &str) -> Result<Vec<String>, AppError> {
            Ok(vec![])
        }
        fn find_expired_pending(&self, _: &str) -> Result<Vec<String>, AppError> {
            Ok(vec![])
        }
        fn find_dispatched_older_than(&self, _: &str) -> Result<Vec<String>, AppError> {
            Ok(vec![])
        }
        fn mark_expired(&self, _: &str, _: &str) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_expired_and_record(
            &self,
            _: &str,
            _: &AuditEvent,
            _: &str,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_approved_from_dispatched(&self, _: &str, _: &str) -> Result<bool, AppError> {
            Ok(true)
        }
        fn purge_old_requests(&self, _: &str) -> Result<u32, AppError> {
            Ok(0)
        }
        fn count_by_status(&self, _: &str) -> Result<u32, AppError> {
            Ok(0)
        }
        fn wal_checkpoint(&self) -> Result<(), AppError> {
            Ok(())
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
    }

    struct FakeResultStore {
        stored: Mutex<Vec<String>>,
    }
    #[async_trait]
    impl ResultStore for FakeResultStore {
        async fn put(&self, key: &str, _: &[u8]) -> Result<(), AppError> {
            self.stored.lock().unwrap().push(key.into());
            Ok(())
        }
        async fn get(&self, _: &str) -> Result<Vec<u8>, AppError> {
            Ok(vec![])
        }
        async fn delete(&self, _: &str) -> Result<(), AppError> {
            Ok(())
        }
    }

    struct FakeResultChannel;
    #[async_trait]
    impl ResultChannel for FakeResultChannel {
        fn create_slot(&self, _: &str) {}
        async fn publish(&self, _: &str, _: ResultSummary) {}
        async fn subscribe(&self, _: &str, _: u64) -> Result<Option<ResultSummary>, AppError> {
            Ok(None)
        }
        async fn notify_all(&self) {}
    }

    fn agent_user() -> AuthUser {
        AuthUser {
            subject_id: "agent-1".into(),
            subject_type: SubjectType::Agent,
            roles: vec![ResolvedRole {
                name: "agent-default".into(),
                permissions: [P::AgentSubmitResult].into_iter().collect(),
                databases: vec![],
                environments: vec![],
            }],
            groups: vec![],
            token_id: None,
        }
    }

    fn make_execution(status: ExecutionStatus) -> Execution {
        Execution {
            id: "exec-1".into(),
            request_id: "req-1".into(),
            agent_id: "agent-1".into(),
            status,
            token: "tok".into(),
            lease_expires_at: Utc::now() + chrono::Duration::minutes(5),
            started_at: Some(Utc::now()),
            finished_at: None,
            error_message: None,
            created_at: Utc::now(),
        }
    }

    fn make_request(status: RequestStatus) -> DomainRequest {
        DomainRequest {
            id: "req-1".into(),
            requester: "alice".into(),
            database: DatabaseName::new("app").unwrap(),
            environment: Environment::new("production").unwrap(),
            operation: Operation::ExecuteDml,
            detail: "UPDATE t SET x=1".into(),
            status,
            emergency: false,
            reason: None,
            idempotency_key: None,
            metadata_json: "{}".into(),
            share_with: vec![],
            no_store: false,
            workflow_snapshot_json: None,
            cancel_reason: None,
            cancelled_by: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            resolved_at: None,
            expires_at: None,
        }
    }

    fn make_uc(exec_status: ExecutionStatus, req_status: RequestStatus) -> AgentSubmitResult {
        AgentSubmitResult {
            authorizer: Arc::new(AllowAll),
            agent_repo: Arc::new(FakeAgentRepo {
                execution: Mutex::new(Some(make_execution(exec_status))),
            }),
            request_repo: Arc::new(FakeRequestRepo {
                request: Mutex::new(Some(make_request(req_status))),
            }),
            result_store: Arc::new(FakeResultStore {
                stored: Mutex::new(vec![]),
            }),
            result_channel: Arc::new(FakeResultChannel),
            event_dispatcher: Arc::new(NoopDispatcher),
            clock: Arc::new(FakeClock),
        }
    }

    #[tokio::test]
    async fn execution_not_found_returns_error() {
        let uc = AgentSubmitResult {
            authorizer: Arc::new(AllowAll),
            agent_repo: Arc::new(FakeAgentRepo {
                execution: Mutex::new(None),
            }),
            request_repo: Arc::new(FakeRequestRepo {
                request: Mutex::new(None),
            }),
            result_store: Arc::new(FakeResultStore {
                stored: Mutex::new(vec![]),
            }),
            result_channel: Arc::new(FakeResultChannel),
            event_dispatcher: Arc::new(NoopDispatcher),
            clock: Arc::new(FakeClock),
        };
        let input = AgentSubmitResultInput {
            execution_id: "nope".into(),
            success: true,
            result_data: None,
            error_message: None,
        };
        assert!(matches!(
            uc.execute(input, &agent_user()).await,
            Err(AppError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn not_claimed_returns_conflict() {
        let uc = make_uc(ExecutionStatus::Completed, RequestStatus::Running);
        let input = AgentSubmitResultInput {
            execution_id: "exec-1".into(),
            success: true,
            result_data: None,
            error_message: None,
        };
        assert!(matches!(
            uc.execute(input, &agent_user()).await,
            Err(AppError::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn success_submit_returns_executed() {
        let uc = make_uc(ExecutionStatus::Claimed, RequestStatus::Running);
        let input = AgentSubmitResultInput {
            execution_id: "exec-1".into(),
            success: true,
            result_data: Some(b"rows".to_vec()),
            error_message: None,
        };
        let out = uc.execute(input, &agent_user()).await.unwrap();
        assert_eq!(out.status, RequestStatus::Executed);
    }

    #[tokio::test]
    async fn failure_submit_returns_failed() {
        let uc = make_uc(ExecutionStatus::Claimed, RequestStatus::Running);
        let input = AgentSubmitResultInput {
            execution_id: "exec-1".into(),
            success: false,
            result_data: None,
            error_message: Some("timeout".into()),
        };
        let out = uc.execute(input, &agent_user()).await.unwrap();
        assert_eq!(out.status, RequestStatus::Failed);
    }

    #[tokio::test]
    async fn cancelled_request_stays_cancelled() {
        let uc = make_uc(ExecutionStatus::Claimed, RequestStatus::Cancelled);
        let input = AgentSubmitResultInput {
            execution_id: "exec-1".into(),
            success: true,
            result_data: None,
            error_message: None,
        };
        let out = uc.execute(input, &agent_user()).await.unwrap();
        assert_eq!(out.status, RequestStatus::Cancelled);
    }
}
