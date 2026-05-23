use std::sync::Arc;

use dbward_domain::auth::{AuthUser, Permission, ResourceContext};
use dbward_domain::entities::ExecutionStatus;

use crate::error::AppError;
use crate::ports::*;

pub struct AgentHeartbeat {
    pub authorizer: Arc<dyn Authorizer>,
    pub agent_repo: Arc<dyn AgentRepo>,
    pub request_reader: Arc<dyn RequestReader>,
    pub policy: Arc<dyn PolicyEvaluator>,
    pub event_dispatcher: Arc<dyn EventDispatcher>,
    pub clock: Arc<dyn Clock>,
}

pub struct AgentHeartbeatInput {
    pub execution_id: String,
}

pub struct AgentHeartbeatOutput {
    pub cancelled: bool,
}

impl AgentHeartbeat {
    pub fn execute(
        &self,
        input: AgentHeartbeatInput,
        user: &AuthUser,
    ) -> Result<AgentHeartbeatOutput, AppError> {
        // 1. Authorization (global)
        self.authorizer
            .authorize_global(user, Permission::AgentHeartbeat)
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
                Permission::AgentHeartbeat,
                &dbward_domain::values::DatabaseName::wildcard(),
                &dbward_domain::values::Environment::wildcard(),
                &ResourceContext::AgentExecution {
                    agent_id: execution.agent_id.clone(),
                },
            )
            .map_err(AppError::Forbidden)?;

        // 4. Verify execution is still active (Claimed = in progress)
        if execution.status != ExecutionStatus::Claimed {
            return Err(AppError::Conflict(format!(
                "execution is {:?}, cannot heartbeat",
                execution.status
            )));
        }

        // 5. Extend lease using execution policy
        let request = self.request_reader.get(&execution.request_id)?;
        let req = request.as_ref();
        let exec_policy = req
            .map(|r| {
                self.policy
                    .get_execution_policy(&r.database, &r.environment)
            })
            .unwrap_or_default();
        let new_expiry =
            self.clock.now() + chrono::Duration::seconds(exec_policy.lease_duration_secs());
        self.agent_repo.extend_lease(&execution.id, new_expiry)?;

        // 6. Check if request was cancelled
        let cancelled = req
            .map(|r| r.status == dbward_domain::entities::RequestStatus::Cancelled)
            .unwrap_or(false);

        Ok(AgentHeartbeatOutput { cancelled })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use chrono::{DateTime, Utc};

    use dbward_domain::auth::{AuthUser, Permission, ResourceContext, SubjectType};
    use dbward_domain::entities::*;
    use dbward_domain::values::{DatabaseName, Environment, Operation};

    use crate::error::{AppError, AuthzError};
    use crate::ports::*;
    use crate::test_support::*;

    use super::*;

    // --- Local fakes ---

    struct FakeAgentRepo {
        execution: Mutex<Option<Execution>>,
        extended: Mutex<Vec<(String, DateTime<Utc>)>>,
    }

    impl FakeAgentRepo {
        fn with_execution(exec: Option<Execution>) -> Self {
            Self {
                execution: Mutex::new(exec),
                extended: Mutex::new(vec![]),
            }
        }
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
        fn extend_lease(&self, id: &str, expiry: DateTime<Utc>) -> Result<(), AppError> {
            self.extended.lock().unwrap().push((id.to_string(), expiry));
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

    /// Allows global but denies scoped authorization.
    struct AllowGlobalDenyScoped;
    impl Authorizer for AllowGlobalDenyScoped {
        fn authorize_global(&self, _: &AuthUser, _: Permission) -> Result<(), AuthzError> {
            Ok(())
        }
        fn authorize_scoped(
            &self,
            _: &AuthUser,
            p: Permission,
            _: &DatabaseName,
            _: &Environment,
            _: &ResourceContext,
        ) -> Result<(), AuthzError> {
            Err(AuthzError::Forbidden {
                permission: p,
                reason: "agent_id mismatch".into(),
            })
        }
    }

    fn make_user() -> AuthUser {
        AuthUser {
            subject_id: "agent-1".into(),
            subject_type: SubjectType::Agent,
            roles: vec![],
            groups: vec![],
            token_id: None,
        }
    }

    fn make_execution(status: ExecutionStatus) -> Execution {
        let now = Utc::now();
        Execution {
            id: "exec-001".into(),
            request_id: "req-001".into(),
            agent_id: "agent-1".into(),
            status,
            token: "tok".into(),
            lease_expires_at: now + chrono::Duration::seconds(60),
            started_at: Some(now),
            finished_at: None,
            error_message: None,
            created_at: now,
        }
    }

    fn make_request(status: RequestStatus) -> Request {
        let now = Utc::now();
        Request {
            id: "req-001".into(),
            requester: "alice".into(),
            database: DatabaseName::new("app").unwrap(),
            environment: Environment::new("production").unwrap(),
            operation: Operation::ExecuteSelect,
            detail: "SELECT 1".into(),
            status,
            emergency: false,
            reason: None,
            idempotency_key: None,
            metadata_json: "{}".into(),
            share_with: vec![],
            no_store: false,
            workflow_snapshot_json: None,
            decision_trace_json: None,
            cancel_reason: None,
            cancelled_by: None,
            created_at: now,
            updated_at: now,
            resolved_at: None,
            expires_at: None,
        }
    }

    fn build_uc(
        authorizer: Arc<dyn Authorizer>,
        agent_repo: Arc<dyn AgentRepo>,
        request_reader: Arc<dyn RequestReader>,
    ) -> AgentHeartbeat {
        AgentHeartbeat {
            authorizer,
            agent_repo,
            request_reader,
            policy: Arc::new(FakePolicyEvaluator),
            event_dispatcher: Arc::new(NoopDispatcher),
            clock: Arc::new(FixedClock::now_utc()),
        }
    }

    #[test]
    fn authz_denied_returns_forbidden() {
        let uc = build_uc(
            Arc::new(DenyAll),
            Arc::new(FakeAgentRepo::with_execution(Some(make_execution(
                ExecutionStatus::Claimed,
            )))),
            Arc::new(FakeRequestReader::new()),
        );
        let result = uc.execute(
            AgentHeartbeatInput {
                execution_id: "exec-001".into(),
            },
            &make_user(),
        );
        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    #[test]
    fn execution_not_found_returns_not_found() {
        let uc = build_uc(
            Arc::new(AllowAll),
            Arc::new(FakeAgentRepo::with_execution(None)),
            Arc::new(FakeRequestReader::new()),
        );
        let result = uc.execute(
            AgentHeartbeatInput {
                execution_id: "exec-999".into(),
            },
            &make_user(),
        );
        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    #[test]
    fn wrong_agent_id_returns_forbidden() {
        let uc = build_uc(
            Arc::new(AllowGlobalDenyScoped),
            Arc::new(FakeAgentRepo::with_execution(Some(make_execution(
                ExecutionStatus::Claimed,
            )))),
            Arc::new(FakeRequestReader::new()),
        );
        let result = uc.execute(
            AgentHeartbeatInput {
                execution_id: "exec-001".into(),
            },
            &make_user(),
        );
        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    #[test]
    fn non_claimed_status_returns_conflict() {
        let uc = build_uc(
            Arc::new(AllowAll),
            Arc::new(FakeAgentRepo::with_execution(Some(make_execution(
                ExecutionStatus::Completed,
            )))),
            Arc::new(FakeRequestReader::new()),
        );
        let result = uc.execute(
            AgentHeartbeatInput {
                execution_id: "exec-001".into(),
            },
            &make_user(),
        );
        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    #[test]
    fn extends_lease_and_not_cancelled() {
        let repo = Arc::new(FakeAgentRepo::with_execution(Some(make_execution(
            ExecutionStatus::Claimed,
        ))));
        let reader = Arc::new(FakeRequestReader::with_request(make_request(
            RequestStatus::Running,
        )));
        let uc = build_uc(Arc::new(AllowAll), repo.clone(), reader);
        let output = uc
            .execute(
                AgentHeartbeatInput {
                    execution_id: "exec-001".into(),
                },
                &make_user(),
            )
            .unwrap();
        assert!(!output.cancelled);
        let extended = repo.extended.lock().unwrap();
        assert_eq!(extended.len(), 1);
        assert_eq!(extended[0].0, "exec-001");
    }

    #[test]
    fn detects_cancelled_request() {
        let repo = Arc::new(FakeAgentRepo::with_execution(Some(make_execution(
            ExecutionStatus::Claimed,
        ))));
        let reader = Arc::new(FakeRequestReader::with_request(make_request(
            RequestStatus::Cancelled,
        )));
        let uc = build_uc(Arc::new(AllowAll), repo, reader);
        let output = uc
            .execute(
                AgentHeartbeatInput {
                    execution_id: "exec-001".into(),
                },
                &make_user(),
            )
            .unwrap();
        assert!(output.cancelled);
    }

    #[test]
    fn request_not_found_defaults_to_not_cancelled() {
        let repo = Arc::new(FakeAgentRepo::with_execution(Some(make_execution(
            ExecutionStatus::Claimed,
        ))));
        let reader = Arc::new(FakeRequestReader::new()); // returns None
        let uc = build_uc(Arc::new(AllowAll), repo, reader);
        let output = uc
            .execute(
                AgentHeartbeatInput {
                    execution_id: "exec-001".into(),
                },
                &make_user(),
            )
            .unwrap();
        assert!(!output.cancelled);
    }
}
