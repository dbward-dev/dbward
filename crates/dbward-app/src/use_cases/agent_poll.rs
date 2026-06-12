use std::sync::Arc;

use dbward_domain::auth::{AuthUser, Permission};
use dbward_domain::entities::{ActiveJobEntry, Agent, AgentStatus, AuditEvent, DatabaseCapability};
use dbward_domain::values::{DatabaseName, Environment, Operation};

use crate::error::AppError;
use crate::ports::*;

pub struct AgentPoll {
    pub authorizer: Arc<dyn Authorizer>,
    pub agent_repo: Arc<dyn AgentRepo>,
    pub audit_logger: Arc<dyn AuditLogger>,
    pub clock: Arc<dyn Clock>,
}

pub struct AgentPollInput {
    pub capabilities: Vec<DatabaseCapability>,
    pub operations: Vec<Operation>,
    pub limit: Option<u32>,
    pub in_flight: u32,
    pub max_concurrent: u32,
    pub draining: bool,
    pub uptime_secs: u64,
    pub active_jobs: Vec<ActiveJobEntry>,
}

pub struct AgentPollOutput {
    pub jobs: Vec<PollJob>,
}

pub struct PollJob {
    pub id: String,
    pub created_by: String,
    pub operation: Operation,
    pub environment: Environment,
    pub database: DatabaseName,
    pub detail: String,
}

impl AgentPoll {
    pub fn execute(
        &self,
        input: AgentPollInput,
        user: &AuthUser,
    ) -> Result<AgentPollOutput, AppError> {
        // 1. Authorization
        self.authorizer
            .authorize_global(user, Permission::AgentOperate)
            .map_err(AppError::Forbidden)?;

        // 2. Check if this is a new agent registration
        let existing = self.agent_repo.get(&user.subject_id)?;
        let is_new = existing.is_none();

        // 3. Upsert agent (register/update last_seen + status)
        let now = self.clock.now();
        let agent = Agent {
            id: user.subject_id.clone(),
            token_id: user.token_id.clone().unwrap_or_default(),
            databases: input.capabilities.clone(),
            status: if input.draining {
                AgentStatus::Draining
            } else {
                AgentStatus::Active
            },
            max_concurrent: input.max_concurrent,
            in_flight: input.in_flight,
            uptime_secs: input.uptime_secs,
            active_jobs: input.active_jobs,
            last_seen: Some(now),
            created_at: now,
            lease_duration_secs: None,
        };
        self.agent_repo.upsert(&agent)?;

        // 3b. Emit audit event for new agent registration
        if is_new
            && let Err(e) = self.audit_logger.record(&AuditEvent::simple(
                "agent_registered",
                "agent",
                &user.subject_id,
                Some(&user.subject_id),
                self.clock.now(),
                &dbward_domain::entities::AuditContext::System,
            ))
        {
            tracing::error!(error = %e, "failed to record agent_registered audit event");
        }

        // 4. Find dispatched jobs matching capabilities
        let pairs: Vec<(DatabaseName, Environment)> = input
            .capabilities
            .iter()
            .map(|c| (c.database.clone(), c.environment.clone()))
            .collect();
        let mut jobs = self.agent_repo.find_dispatched_jobs(&pairs)?;

        // 5. Filter by operations (if specified)
        if !input.operations.is_empty() {
            jobs.retain(|r| input.operations.contains(&r.operation));
        }

        // 6. Apply limit
        let limit = input.limit.unwrap_or(10).min(20) as usize;
        jobs.truncate(limit);

        // 7. Map to output
        let poll_jobs = jobs
            .into_iter()
            .map(|r| PollJob {
                id: r.id,
                created_by: r.requester,
                operation: r.operation,
                environment: r.environment,
                database: r.database,
                detail: r.detail,
            })
            .collect();

        Ok(AgentPollOutput { jobs: poll_jobs })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use chrono::Utc;

    use dbward_domain::auth::{AuthUser, SubjectType};
    use dbward_domain::entities::*;
    use dbward_domain::values::{DatabaseName, Environment, Operation};

    use crate::error::AppError;
    use crate::ports::*;
    use crate::test_support::*;

    use super::*;

    // --- Local fakes ---

    struct FakeAgentRepo {
        existing: Option<Agent>,
        jobs: Vec<Request>,
    }

    impl FakeAgentRepo {
        fn new() -> Self {
            Self {
                existing: None,
                jobs: vec![],
            }
        }
        fn with_existing(mut self) -> Self {
            self.existing = Some(Agent {
                id: "agent-1".into(),
                token_id: "t1".into(),
                databases: vec![],
                status: AgentStatus::Active,
                max_concurrent: 4,
                in_flight: 0,
                uptime_secs: 100,
                active_jobs: vec![],
                lease_duration_secs: None,
                last_seen: Some(Utc::now()),
                created_at: Utc::now(),
            });
            self
        }
        fn with_jobs(mut self, jobs: Vec<Request>) -> Self {
            self.jobs = jobs;
            self
        }
    }

    impl AgentRepo for FakeAgentRepo {
        fn upsert(&self, _: &Agent) -> Result<(), AppError> {
            Ok(())
        }
        fn get(&self, _: &str) -> Result<Option<Agent>, AppError> {
            Ok(self.existing.clone())
        }
        fn list(&self) -> Result<Vec<Agent>, AppError> {
            Ok(vec![])
        }
        fn create_execution(&self, _: &Execution) -> Result<(), AppError> {
            Ok(())
        }
        fn get_execution(&self, _: &str) -> Result<Option<Execution>, AppError> {
            Ok(None)
        }
        fn update_execution_status(&self, _: &str, _: ExecutionStatus) -> Result<(), AppError> {
            Ok(())
        }
        fn extend_lease(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<(), AppError> {
            Ok(())
        }
        fn find_dispatched_jobs(
            &self,
            _: &[(DatabaseName, Environment)],
        ) -> Result<Vec<Request>, AppError> {
            Ok(self.jobs.clone())
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
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn complete_execution(
            &self,
            _: &str,
            _: &str,
            _: bool,
            _: chrono::DateTime<chrono::Utc>,
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

    struct FakeAuditLogger {
        called: Mutex<bool>,
    }
    impl FakeAuditLogger {
        fn new() -> Self {
            Self {
                called: Mutex::new(false),
            }
        }
        fn was_called(&self) -> bool {
            *self.called.lock().unwrap()
        }
    }
    impl AuditLogger for FakeAuditLogger {
        fn record(&self, _: &AuditEvent) -> Result<(), AppError> {
            *self.called.lock().unwrap() = true;
            Ok(())
        }
    }

    // --- Helpers ---

    fn make_user() -> AuthUser {
        AuthUser {
            subject_id: "agent-1".into(),
            subject_type: SubjectType::Agent,
            roles: vec![],
            groups: vec![],
            token_id: Some("tok-1".into()),
        }
    }

    fn make_input() -> AgentPollInput {
        AgentPollInput {
            capabilities: vec![DatabaseCapability {
                database: DatabaseName::new("app").unwrap(),
                environment: Environment::new("production").unwrap(),
            }],
            operations: vec![],
            limit: None,
            in_flight: 0,
            max_concurrent: 4,
            draining: false,
            uptime_secs: 100,
            active_jobs: vec![],
        }
    }

    fn make_request_with(id: &str, op: Operation, db: &str, env: &str) -> Request {
        let now = Utc::now();
        Request {
            id: id.into(),
            requester: "alice".into(),
            database: DatabaseName::new(db).unwrap(),
            environment: Environment::new(env).unwrap(),
            operation: op,
            detail: "SELECT 1".into(),
            status: RequestStatus::Dispatched,
            emergency: false,
            reason: None,
            idempotency_key: None,
            metadata_json: "{}".into(),
            share_with: vec![],
            no_store: false,
            workflow_snapshot_json: None,
            decision_trace_json: None,
            execution_plan_json: None,
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
        audit_logger: Arc<dyn AuditLogger>,
    ) -> AgentPoll {
        AgentPoll {
            authorizer,
            agent_repo,
            audit_logger,
            clock: Arc::new(FixedClock::now_utc()),
        }
    }

    // --- Tests ---

    #[test]
    fn authz_denied_returns_forbidden() {
        let uc = build_uc(
            Arc::new(DenyAll),
            Arc::new(FakeAgentRepo::new()),
            Arc::new(NoopAuditLogger),
        );
        let result = uc.execute(make_input(), &make_user());
        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    #[test]
    fn new_agent_emits_audit_event() {
        let logger = Arc::new(FakeAuditLogger::new());
        let uc = build_uc(
            Arc::new(AllowAll),
            Arc::new(FakeAgentRepo::new()), // existing=None → new agent
            logger.clone(),
        );
        let result = uc.execute(make_input(), &make_user());
        assert!(result.is_ok());
        assert!(logger.was_called());
    }

    #[test]
    fn draining_sets_status_but_returns_jobs() {
        let jobs = vec![make_request_with(
            "r1",
            Operation::ExecuteSelect,
            "app",
            "production",
        )];
        let repo = FakeAgentRepo::new().with_existing().with_jobs(jobs);
        let uc = build_uc(
            Arc::new(AllowAll),
            Arc::new(repo),
            Arc::new(NoopAuditLogger),
        );

        let mut input = make_input();
        input.draining = true;

        let output = uc.execute(input, &make_user()).unwrap();
        assert_eq!(output.jobs.len(), 1);
    }

    #[test]
    fn operations_filter_excludes_non_matching() {
        let jobs = vec![
            make_request_with("r1", Operation::ExecuteSelect, "app", "production"),
            make_request_with("r2", Operation::ExecuteDml, "app", "production"),
        ];
        let repo = FakeAgentRepo::new().with_existing().with_jobs(jobs);
        let uc = build_uc(
            Arc::new(AllowAll),
            Arc::new(repo),
            Arc::new(NoopAuditLogger),
        );

        let mut input = make_input();
        input.operations = vec![Operation::ExecuteSelect];

        let output = uc.execute(input, &make_user()).unwrap();
        assert_eq!(output.jobs.len(), 1);
        assert_eq!(output.jobs[0].operation, Operation::ExecuteSelect);
    }

    #[test]
    fn limit_caps_at_20() {
        let jobs: Vec<Request> = (0..25)
            .map(|i| {
                make_request_with(
                    &format!("r{i}"),
                    Operation::ExecuteSelect,
                    "app",
                    "production",
                )
            })
            .collect();
        let repo = FakeAgentRepo::new().with_existing().with_jobs(jobs);
        let uc = build_uc(
            Arc::new(AllowAll),
            Arc::new(repo),
            Arc::new(NoopAuditLogger),
        );

        let mut input = make_input();
        input.limit = Some(50);

        let output = uc.execute(input, &make_user()).unwrap();
        assert_eq!(output.jobs.len(), 20);
    }

    #[test]
    fn capability_matching_filters_jobs() {
        // find_dispatched_jobs is called with capability pairs from input,
        // so the repo only returns jobs matching those pairs.
        let matching_jobs = vec![make_request_with(
            "r1",
            Operation::ExecuteSelect,
            "app",
            "production",
        )];
        let repo = FakeAgentRepo::new()
            .with_existing()
            .with_jobs(matching_jobs);
        let uc = build_uc(
            Arc::new(AllowAll),
            Arc::new(repo),
            Arc::new(NoopAuditLogger),
        );

        let output = uc.execute(make_input(), &make_user()).unwrap();
        assert_eq!(output.jobs.len(), 1);
        assert_eq!(output.jobs[0].id, "r1");
    }
}
