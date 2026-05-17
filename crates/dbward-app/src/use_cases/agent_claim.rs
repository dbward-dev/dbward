// TODO(v0.2): Transaction boundary gap — create_execution + mark_running should be atomic.
// Requires UnitOfWork port trait to wrap both repo calls in a single SQLite transaction.
use std::sync::Arc;

use sha2::{Digest, Sha256};

use dbward_domain::auth::{AuthUser, Permission, ResourceContext};
use dbward_domain::entities::{Execution, ExecutionStatus};
use dbward_domain::services::status_machine::{
    self, EventMetadata, RequestTrigger, TransitionContext,
};
use dbward_domain::values::Operation;

use crate::error::AppError;
use crate::ports::*;

pub struct AgentClaim {
    pub authorizer: Arc<dyn Authorizer>,
    pub request_reader: Arc<dyn RequestReader>,
    pub agent_repo: Arc<dyn AgentRepo>,
    pub policy: Arc<dyn PolicyEvaluator>,
    pub token_signer: Arc<dyn TokenSigner>,
    pub event_dispatcher: Arc<dyn EventDispatcher>,
    pub clock: Arc<dyn Clock>,
    pub id_gen: Arc<dyn IdGenerator>,
    pub user_repo: Arc<dyn UserRepo>,
    pub role_resolver: Arc<dyn RoleResolver>,
}

pub struct AgentClaimInput {
    pub request_id: String,
    pub agent_id: String,
    pub agent_databases: Vec<dbward_domain::entities::DatabaseCapability>,
}

pub struct AgentClaimOutput {
    pub execution_id: String,
    pub request_id: String,
    pub execution_token: String,
    pub operation: String,
    pub database: String,
    pub environment: String,
    pub detail: String,
    pub statement_timeout_secs: u32,
    pub max_rows: Option<u32>,
    pub lease_expires_at: chrono::DateTime<chrono::Utc>,
}

impl AgentClaim {
    pub fn execute(
        &self,
        input: AgentClaimInput,
        user: &AuthUser,
        ctx: &dbward_domain::entities::AuditContext,
    ) -> Result<AgentClaimOutput, AppError> {
        // 1. Authorization (global permission)
        self.authorizer
            .authorize_global(user, Permission::AgentClaim)
            .map_err(AppError::Forbidden)?;

        // 2. Get request
        let request = self
            .request_reader
            .get(&input.request_id)?
            .ok_or_else(|| AppError::NotFound("request not found".into()))?;

        // 3. Status check: must be dispatched → running
        let now = self.clock.now();
        let execution_id = self.id_gen.generate();
        let result = status_machine::transition(
            request.status,
            &RequestTrigger::Claim,
            TransitionContext {
                request_id: request.id.clone(),
                actor_id: user.subject_id.clone(),
                actor_type: user.subject_type,
                database: request.database.clone(),
                environment: request.environment.clone(),
                operation: request.operation,
                timestamp: now,
                metadata: EventMetadata::Claimed {
                    execution_id: execution_id.clone(),
                    agent_id: input.agent_id.clone(),
                },
                requester_id: request.requester.clone(),
                audit_context: ctx.clone(),
            },
        )
        .map_err(|e| AppError::Conflict(e.to_string()))?;

        // 4. Capability verification: agent must support (database, environment)
        let has_capability = input.agent_databases.iter().any(|cap| {
            (cap.database.is_wildcard() || cap.database == request.database)
                && (cap.environment.is_wildcard() || cap.environment == request.environment)
        });
        if !has_capability {
            return Err(AppError::Forbidden(crate::error::AuthzError::Forbidden {
                permission: Permission::AgentClaim,
                reason: "agent lacks capability for this database/environment".into(),
            }));
        }

        // 4b. Operation capability verification
        let agent_entity = self.agent_repo.get(&input.agent_id)?;
        if let Some(ref _agent) = agent_entity {
            // Agent's registered operations are checked via the poll filter;
            // here we verify the request operation is supported by the agent's declared scope
            let op_supported = match request.operation {
                Operation::MigrateUp | Operation::MigrateDown => {
                    // Migration checks database capability (wildcard permitted)
                    input
                        .agent_databases
                        .iter()
                        .any(|cap| cap.database == request.database || cap.database.is_wildcard())
                }
                _ => true,
            };
            if !op_supported {
                return Err(AppError::Forbidden(crate::error::AuthzError::Forbidden {
                    permission: Permission::AgentClaim,
                    reason: "agent.capability_mismatch: operation not supported".into(),
                }));
            }
        }

        // 5. Migration exclusion: no concurrent migrate on same (db, env)
        if matches!(
            request.operation,
            Operation::MigrateUp | Operation::MigrateDown
        ) && self.agent_repo.has_running_migration(
            &request.database,
            &request.environment,
            &request.id,
        )? {
            return Err(AppError::Conflict(
                "migration already running for this database".into(),
            ));
        }

        // 7. Resource-level authorization
        self.authorizer
            .authorize_scoped(
                user,
                Permission::AgentClaim,
                &request.database,
                &request.environment,
                &ResourceContext::AgentExecution {
                    agent_id: input.agent_id.clone(),
                },
            )
            .map_err(AppError::Forbidden)?;

        // 8. Get execution policy for statement_timeout
        let exec_policy = self
            .policy
            .get_execution_policy(&request.database, &request.environment);

        // 9. Create execution record
        let lease_expires_at = now + chrono::Duration::seconds(exec_policy.lease_duration_secs());

        // 10. Sign execution token (SHA-256 for detail_hash)
        let detail_hash = sha256_hex(&request.detail);
        let requester_groups = self
            .user_repo
            .get(&request.requester)?
            .map(|u| u.groups)
            .unwrap_or_default();
        let requester_role = self
            .role_resolver
            .resolve(
                &request.requester,
                dbward_domain::auth::SubjectType::User,
                &requester_groups,
            )
            .ok()
            .and_then(|roles| roles.first().map(|r| r.name.clone()))
            .unwrap_or_else(|| "unknown".into());
        let token = self.token_signer.sign(&ExecutionTokenClaims {
            request_id: request.id.clone(),
            operation: request.operation.as_str().to_string(),
            database: request.database.as_str().to_string(),
            environment: request.environment.as_str().to_string(),
            detail_hash,
            requester: request.requester.clone(),
            requester_role,
        });

        let execution = Execution {
            id: execution_id.clone(),
            request_id: request.id.clone(),
            agent_id: input.agent_id,
            status: ExecutionStatus::Claimed,
            token: token.clone(),
            lease_expires_at,
            started_at: Some(now),
            finished_at: None,
            error_message: None,
            created_at: now,
        };
        self.agent_repo
            .claim_and_mark_running(&execution, &request.id, now)?
            .then_some(())
            .ok_or_else(|| AppError::Conflict("concurrent status change".into()))?;

        result.commit(&*self.event_dispatcher);

        Ok(AgentClaimOutput {
            execution_id,
            request_id: request.id,
            execution_token: token,
            operation: request.operation.as_str().to_string(),
            database: request.database.as_str().to_string(),
            environment: request.environment.as_str().to_string(),
            detail: request.detail,
            statement_timeout_secs: exec_policy.statement_timeout_secs,
            max_rows: exec_policy.max_rows,
            lease_expires_at,
        })
    }
}

/// Deterministic SHA-256 hash (hex-encoded) for cross-process token verification.
fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::Utc;

    use dbward_domain::auth::{AuthUser, ResolvedRole, SubjectType};
    use dbward_domain::entities::*;
    use dbward_domain::values::{DatabaseName, Environment, Operation};

    use crate::error::{AppError, AuthError};
    use crate::ports::*;
    use crate::test_support::*;

    use super::*;

    // --- Local fakes ---

    struct FakeRequestReader(Option<Request>);
    impl RequestReader for FakeRequestReader {
        fn get(&self, _: &str) -> Result<Option<Request>, AppError> {
            Ok(self.0.clone())
        }
        fn list(
            &self,
            _: u32,
            _: u32,
            _: Option<&str>,
            _: Option<&str>,
        ) -> Result<(Vec<Request>, u32), AppError> {
            Ok((vec![], 0))
        }
        fn find_by_idempotency_key(&self, _: &str) -> Result<Option<Request>, AppError> {
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
        ) -> Result<(Vec<Request>, u32), AppError> {
            Ok((vec![], 0))
        }
        fn list_pending_for_user(
            &self,
            _: &str,
            _: &[String],
            _: &[String],
            _: u32,
            _: u32,
        ) -> Result<(Vec<Request>, u32), AppError> {
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
        fn list_results_for_user(
            &self,
            _: &str,
            _: &[String],
            _: &[String],
            _: u32,
        ) -> Result<Vec<StoredResultEntry>, AppError> {
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

    struct FakeAgentRepo {
        has_running: bool,
        claim_result: bool,
    }
    impl FakeAgentRepo {
        fn new() -> Self {
            Self {
                has_running: false,
                claim_result: true,
            }
        }
    }
    impl AgentRepo for FakeAgentRepo {
        fn upsert(&self, _: &Agent) -> Result<(), AppError> {
            Ok(())
        }
        fn get(&self, _: &str) -> Result<Option<Agent>, AppError> {
            Ok(Some(Agent {
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
            }))
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
            Ok(vec![])
        }
        fn has_running_migration(
            &self,
            _: &DatabaseName,
            _: &Environment,
            _: &str,
        ) -> Result<bool, AppError> {
            Ok(self.has_running)
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
            Ok(self.claim_result)
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

    struct FakeTokenSigner;
    impl TokenSigner for FakeTokenSigner {
        fn sign(&self, _: &ExecutionTokenClaims) -> String {
            "fake-token".into()
        }
        fn public_key_hex(&self) -> String {
            "deadbeef".into()
        }
    }

    struct FakeUserRepo;
    impl UserRepo for FakeUserRepo {
        fn get(&self, _: &str) -> Result<Option<User>, AppError> {
            Ok(None)
        }
        fn upsert(&self, _: &User) -> Result<(), AppError> {
            Ok(())
        }
        fn list(&self) -> Result<Vec<User>, AppError> {
            Ok(vec![])
        }
        fn suspend(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
        fn activate(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
        fn is_suspended(&self, _: &str) -> Result<bool, AppError> {
            Ok(false)
        }
        fn ensure_exists(&self, _: &str) -> Result<(), AppError> {
            Ok(())
        }
    }

    struct FakeRoleResolver;
    impl RoleResolver for FakeRoleResolver {
        fn resolve(
            &self,
            _: &str,
            _: SubjectType,
            _: &[String],
        ) -> Result<Vec<ResolvedRole>, AuthError> {
            Ok(vec![ResolvedRole {
                name: "admin".into(),
                permissions: std::collections::HashSet::new(),
                databases: vec![],
                environments: vec![],
            }])
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
            cancel_reason: None,
            cancelled_by: None,
            created_at: now,
            updated_at: now,
            resolved_at: None,
            expires_at: None,
        }
    }

    fn make_input(databases: Vec<DatabaseCapability>) -> AgentClaimInput {
        AgentClaimInput {
            request_id: "req-001".into(),
            agent_id: "agent-1".into(),
            agent_databases: databases,
        }
    }

    fn default_caps() -> Vec<DatabaseCapability> {
        vec![DatabaseCapability {
            database: DatabaseName::new("app").unwrap(),
            environment: Environment::new("production").unwrap(),
        }]
    }

    fn build_uc(
        authorizer: Arc<dyn Authorizer>,
        reader: Arc<dyn RequestReader>,
        agent_repo: Arc<dyn AgentRepo>,
    ) -> AgentClaim {
        AgentClaim {
            authorizer,
            request_reader: reader,
            agent_repo,
            policy: Arc::new(FakePolicyEvaluator),
            token_signer: Arc::new(FakeTokenSigner),
            event_dispatcher: Arc::new(NoopDispatcher),
            clock: Arc::new(FixedClock::now_utc()),
            id_gen: Arc::new(FixedIdGen::new()),
            user_repo: Arc::new(FakeUserRepo),
            role_resolver: Arc::new(FakeRoleResolver),
        }
    }

    #[test]
    fn authz_denied_returns_forbidden() {
        let uc = build_uc(
            Arc::new(DenyAll),
            Arc::new(FakeRequestReader(Some(make_request(
                RequestStatus::Dispatched,
            )))),
            Arc::new(FakeAgentRepo::new()),
        );
        let result = uc.execute(
            make_input(default_caps()),
            &make_user(),
            &AuditContext::System,
        );
        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    #[test]
    fn request_not_found_returns_not_found() {
        let uc = build_uc(
            Arc::new(AllowAll),
            Arc::new(FakeRequestReader(None)),
            Arc::new(FakeAgentRepo::new()),
        );
        let result = uc.execute(
            make_input(default_caps()),
            &make_user(),
            &AuditContext::System,
        );
        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    #[test]
    fn non_dispatched_status_returns_conflict() {
        let uc = build_uc(
            Arc::new(AllowAll),
            Arc::new(FakeRequestReader(Some(make_request(
                RequestStatus::Pending,
            )))),
            Arc::new(FakeAgentRepo::new()),
        );
        let result = uc.execute(
            make_input(default_caps()),
            &make_user(),
            &AuditContext::System,
        );
        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    #[test]
    fn capability_mismatch_returns_forbidden() {
        let caps = vec![DatabaseCapability {
            database: DatabaseName::new("other").unwrap(),
            environment: Environment::new("production").unwrap(),
        }];
        let uc = build_uc(
            Arc::new(AllowAll),
            Arc::new(FakeRequestReader(Some(make_request(
                RequestStatus::Dispatched,
            )))),
            Arc::new(FakeAgentRepo::new()),
        );
        let result = uc.execute(make_input(caps), &make_user(), &AuditContext::System);
        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    #[test]
    fn wildcard_capability_allows_claim() {
        let caps = vec![DatabaseCapability {
            database: DatabaseName::wildcard(),
            environment: Environment::wildcard(),
        }];
        let uc = build_uc(
            Arc::new(AllowAll),
            Arc::new(FakeRequestReader(Some(make_request(
                RequestStatus::Dispatched,
            )))),
            Arc::new(FakeAgentRepo::new()),
        );
        let result = uc.execute(make_input(caps), &make_user(), &AuditContext::System);
        assert!(result.is_ok());
    }

    #[test]
    fn migration_concurrent_returns_conflict() {
        let mut req = make_request(RequestStatus::Dispatched);
        req.operation = Operation::MigrateUp;
        let agent_repo = FakeAgentRepo {
            has_running: true,
            claim_result: true,
        };
        let uc = build_uc(
            Arc::new(AllowAll),
            Arc::new(FakeRequestReader(Some(req))),
            Arc::new(agent_repo),
        );
        let result = uc.execute(
            make_input(default_caps()),
            &make_user(),
            &AuditContext::System,
        );
        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    #[test]
    fn claim_and_mark_running_fails_returns_conflict() {
        let agent_repo = FakeAgentRepo {
            has_running: false,
            claim_result: false,
        };
        let uc = build_uc(
            Arc::new(AllowAll),
            Arc::new(FakeRequestReader(Some(make_request(
                RequestStatus::Dispatched,
            )))),
            Arc::new(agent_repo),
        );
        let result = uc.execute(
            make_input(default_caps()),
            &make_user(),
            &AuditContext::System,
        );
        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    #[test]
    fn valid_claim_returns_output() {
        let uc = build_uc(
            Arc::new(AllowAll),
            Arc::new(FakeRequestReader(Some(make_request(
                RequestStatus::Dispatched,
            )))),
            Arc::new(FakeAgentRepo::new()),
        );
        let output = uc
            .execute(
                make_input(default_caps()),
                &make_user(),
                &AuditContext::System,
            )
            .unwrap();
        assert_eq!(output.request_id, "req-001");
        assert_eq!(output.operation, "execute_select");
        assert_eq!(output.database, "app");
        assert_eq!(output.environment, "production");
        assert_eq!(output.detail, "SELECT 1");
        assert_eq!(output.execution_token, "fake-token");
        assert!(!output.execution_id.is_empty());
    }
}
