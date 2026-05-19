use std::sync::Arc;

use dbward_domain::auth::{AuthUser, Permission, ResourceContext};
use dbward_domain::entities::{Request, RequestStatus};
use dbward_domain::services::classification::{ClassifyError, Dialect};
use dbward_domain::services::sql_classifier;
use dbward_domain::services::status_machine::{
    self, EventMetadata, RequestTrigger, TransitionContext,
};
use dbward_domain::services::workflow_matcher;
use dbward_domain::values::{DatabaseName, Environment, Operation};

use crate::error::AppError;
use crate::ports::*;

pub struct CreateRequest {
    pub authorizer: Arc<dyn Authorizer>,
    pub policy: Arc<dyn PolicyEvaluator>,
    pub request_reader: Arc<dyn RequestReader>,
    pub request_writer: Arc<dyn RequestWriter>,
    pub db_registry: Arc<dyn DatabaseRegistry>,
    pub event_dispatcher: Arc<dyn EventDispatcher>,
    pub clock: Arc<dyn Clock>,
    pub id_gen: Arc<dyn IdGenerator>,
    pub default_approval_ttl_secs: Option<u64>,
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
    pub channel: RequestChannel,
}

/// The channel through which the request was submitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestChannel {
    Cli,
    Api,
    Mcp,
}

#[derive(Debug)]
pub struct CreateRequestOutput {
    pub id: String,
    pub status: RequestStatus,
    pub operation: Operation,
    pub is_existing: bool,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub approvers: Vec<String>,
}

impl CreateRequest {
    pub fn execute(
        &self,
        input: CreateRequestInput,
        user: &AuthUser,
        ctx: &dbward_domain::entities::AuditContext,
    ) -> Result<CreateRequestOutput, AppError> {
        if input.detail.len() > 100_000 {
            return Err(AppError::Validation("query too long (max 100KB)".into()));
        }
        if let Some(ref reason) = input.reason {
            if reason.len() > 1024 {
                return Err(AppError::Validation("reason too long (max 1KB)".into()));
            }
        }

        // 1. Determine operation: migration types are explicit, others classified from SQL
        let operation = match input.operation {
            Operation::MigrateUp | Operation::MigrateDown | Operation::MigrateStatus => {
                input.operation
            }
            _ => {
                let classification = sql_classifier::classify(&input.detail, Dialect::PostgreSql)
                    .map_err(|e| match e {
                    ClassifyError::Empty => AppError::Validation("empty query".into()),
                    ClassifyError::Rejected { reason } => AppError::Validation(reason),
                })?;
                classification.operation
            }
        };

        // 1b. Permission + DB/env scope check
        let perm = if input.emergency {
            Permission::RequestBreakGlass
        } else if operation == Operation::ExecuteSelect {
            Permission::RequestCreateSelect
        } else {
            Permission::RequestCreate
        };
        self.authorizer
            .authorize_scoped(
                user,
                perm,
                &input.database,
                &input.environment,
                &ResourceContext::Global,
            )
            .map_err(AppError::Forbidden)?;

        // 1b. Validate share_with selectors
        for sel in &input.share_with {
            dbward_domain::values::Selector::parse(sel).map_err(|e| {
                AppError::Validation(format!("invalid share_with selector '{sel}': {e}"))
            })?;
        }

        // 1c. Emergency requires reason
        if input.emergency && input.reason.is_none() {
            return Err(AppError::Validation(
                "reason is required for emergency requests".into(),
            ));
        }

        // 1c. MCP channel cannot use break_glass
        if input.emergency && input.channel == RequestChannel::Mcp {
            return Err(AppError::Validation(
                "emergency requests are not allowed via MCP".into(),
            ));
        }

        // 2. DB registered?
        if !self
            .db_registry
            .exists(&input.database, &input.environment)?
        {
            return Err(AppError::Validation("database not registered".into()));
        }

        // 3. Idempotency
        if let Some(key) = &input.idempotency_key {
            if let Some(existing) = self.request_reader.find_by_idempotency_key(key)? {
                return Ok(CreateRequestOutput {
                    id: existing.id,
                    status: existing.status,
                    operation: existing.operation,
                    is_existing: true,
                    expires_at: existing.expires_at,
                    approvers: if existing.status == dbward_domain::entities::RequestStatus::Pending
                    {
                        existing
                            .workflow_snapshot_json
                            .as_ref()
                            .and_then(|json| {
                                serde_json::from_str::<serde_json::Value>(json)
                                    .ok()
                                    .and_then(|v| {
                                        v["steps"][0]["approvers"].as_array().map(|arr| {
                                            arr.iter()
                                                .filter_map(|a| {
                                                    a["selector"].as_str().map(String::from)
                                                })
                                                .collect()
                                        })
                                    })
                            })
                            .unwrap_or_default()
                    } else {
                        vec![]
                    },
                });
            }
        }

        // 4. Workflow evaluation
        let workflow =
            self.policy
                .evaluate_workflow(&input.database, &input.environment, operation)?;
        let role_names: Vec<String> = user.roles.iter().map(|r| r.name.clone()).collect();
        // Fail-closed: no workflow configured = reject (unless break-glass)
        let decision = if workflow.is_none() {
            if input.emergency {
                workflow_matcher::ApprovalDecision::AutoApproved {
                    reason: workflow_matcher::AutoApproveReason::EmptySteps,
                }
            } else {
                return Err(AppError::Validation(format!(
                    "no workflow configured for {}/{}",
                    input.database, input.environment
                )));
            }
        } else {
            workflow_matcher::evaluate(
                workflow.as_ref(),
                &role_names,
                &user.groups,
                &user.subject_id,
                true,
                None, // risk_level: not evaluated yet in v0.1.3 Phase 0
                &workflow_matcher::AutoApproveConfig::disabled(),
            )
        };

        // 5. Determine initial status
        let needs_approval = decision.needs_approval();
        let status = status_machine::initial_status(needs_approval, input.emergency);

        // 5b. Workflow require_reason check
        if let Some(ref wf) = workflow {
            if wf.require_reason && input.reason.is_none() {
                return Err(AppError::Validation(
                    "reason is required by workflow policy".into(),
                ));
            }
        }

        // 6. Serialize workflow snapshot for approve/reject
        let workflow_snapshot_json = workflow
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| AppError::Internal(format!("serialize workflow: {e}")))?;

        // 7. Create request
        let now = self.clock.now();
        let id = self.id_gen.generate();
        let expires_at = if status == RequestStatus::Pending {
            workflow
                .as_ref()
                .and_then(|wf| wf.pending_ttl_secs)
                .or(self.default_approval_ttl_secs)
                .map(|secs| now + chrono::Duration::seconds(secs as i64))
        } else {
            None
        };
        let request = Request {
            id: id.clone(),
            requester: user.subject_id.clone(),
            database: input.database.clone(),
            environment: input.environment.clone(),
            operation,
            detail: input.detail.clone(),
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
            expires_at,
        };
        // 8. Persist request — atomic create+dispatch for auto-dispatch path
        let final_status = if matches!(
            status,
            RequestStatus::AutoApproved | RequestStatus::BreakGlass
        ) {
            self.request_writer.create_and_dispatch(&request)?;

            // Emit creation event
            let create_result = status_machine::create_event(
                status,
                TransitionContext {
                    request_id: id.clone(),
                    actor_id: user.subject_id.clone(),
                    actor_type: user.subject_type,
                    database: input.database.clone(),
                    environment: input.environment.clone(),
                    operation,
                    timestamp: now,
                    metadata: EventMetadata::Created {
                        detail: input.detail,
                        emergency: input.emergency,
                    },
                    requester_id: user.subject_id.clone(),
                    audit_context: ctx.clone(),
                },
            );
            create_result.commit(&*self.event_dispatcher);

            let dispatch_result = status_machine::transition(
                status,
                &RequestTrigger::Dispatch,
                TransitionContext {
                    request_id: id.clone(),
                    actor_id: user.subject_id.clone(),
                    actor_type: user.subject_type,
                    database: input.database,
                    environment: input.environment,
                    operation,
                    timestamp: now,
                    metadata: EventMetadata::Dispatched,
                    requester_id: user.subject_id.clone(),
                    audit_context: ctx.clone(),
                },
            )
            .map_err(|e| AppError::Internal(e.to_string()))?;
            let s = dispatch_result.status();
            dispatch_result.commit(&*self.event_dispatcher);
            s
        } else {
            self.request_writer.insert(&request)?;

            let create_result = status_machine::create_event(
                status,
                TransitionContext {
                    request_id: id.clone(),
                    actor_id: user.subject_id.clone(),
                    actor_type: user.subject_type,
                    database: input.database,
                    environment: input.environment,
                    operation,
                    timestamp: now,
                    metadata: EventMetadata::Created {
                        detail: input.detail,
                        emergency: input.emergency,
                    },
                    requester_id: user.subject_id.clone(),
                    audit_context: ctx.clone(),
                },
            );
            create_result.commit(&*self.event_dispatcher);
            status
        };

        Ok(CreateRequestOutput {
            id,
            status: final_status,
            operation,
            is_existing: false,
            expires_at,
            approvers: if final_status == RequestStatus::Pending {
                workflow
                    .as_ref()
                    .and_then(|wf| wf.steps.first())
                    .map(|step| {
                        step.approvers
                            .iter()
                            .map(|a| a.selector.to_string())
                            .collect()
                    })
                    .unwrap_or_default()
            } else {
                vec![]
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use dbward_domain::auth::{ResolvedRole, SubjectType};

    fn make_uc(authorizer: Arc<dyn Authorizer>) -> CreateRequest {
        CreateRequest {
            authorizer,
            policy: Arc::new(FakePolicyEvaluator),
            request_reader: Arc::new(FakeRequestReader::new()),
            request_writer: Arc::new(FakeRequestWriter::new()),
            db_registry: Arc::new(FakeDatabaseRegistry),
            event_dispatcher: Arc::new(NoopDispatcher),
            clock: Arc::new(FixedClock::now_utc()),
            id_gen: Arc::new(FixedIdGen::new()),
            default_approval_ttl_secs: None,
        }
    }

    fn make_user() -> AuthUser {
        AuthUser {
            subject_id: "alice".into(),
            subject_type: SubjectType::User,
            roles: vec![ResolvedRole {
                name: "app-dev".into(),
                permissions: [Permission::RequestCreate, Permission::RequestView]
                    .into_iter()
                    .collect(),
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
            channel: RequestChannel::Cli,
        }
    }

    #[test]
    fn success_creates_auto_approved_request() {
        let uc = make_uc(Arc::new(AllowAll));
        let result = uc
            .execute(
                make_input(),
                &make_user(),
                &dbward_domain::entities::AuditContext::System,
            )
            .unwrap();
        assert_eq!(result.id, "test-id-001");
        // Workflow with empty steps → auto-approved → dispatched
        assert_eq!(result.status, RequestStatus::Dispatched);
    }

    #[test]
    fn denied_by_authorizer() {
        let uc = make_uc(Arc::new(DenyAll));
        let result = uc.execute(
            make_input(),
            &make_user(),
            &dbward_domain::entities::AuditContext::System,
        );
        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    #[test]
    fn migrate_up_uses_input_operation_directly() {
        let uc = make_uc(Arc::new(AllowAll));
        let mut input = make_input();
        input.operation = Operation::MigrateUp;
        input.detail = "migrations/001_init.sql".into();
        let result = uc
            .execute(
                input,
                &make_user(),
                &dbward_domain::entities::AuditContext::System,
            )
            .unwrap();
        assert_eq!(result.operation, Operation::MigrateUp);
    }

    #[test]
    fn migrate_down_uses_input_operation_directly() {
        let uc = make_uc(Arc::new(AllowAll));
        let mut input = make_input();
        input.operation = Operation::MigrateDown;
        input.detail = "migrations/001_init.sql".into();
        let result = uc
            .execute(
                input,
                &make_user(),
                &dbward_domain::entities::AuditContext::System,
            )
            .unwrap();
        assert_eq!(result.operation, Operation::MigrateDown);
    }

    #[test]
    fn execute_select_still_classifies_from_sql() {
        let uc = make_uc(Arc::new(AllowAll));
        let mut input = make_input();
        input.operation = Operation::ExecuteSelect;
        input.detail = "INSERT INTO t VALUES (1)".into();
        let result = uc
            .execute(
                input,
                &make_user(),
                &dbward_domain::entities::AuditContext::System,
            )
            .unwrap();
        // SQL classifier overrides: INSERT → ExecuteDml
        assert_eq!(result.operation, Operation::ExecuteDml);
    }

    // --- Error path tests ---

    struct FakeDatabaseRegistryNotFound;
    impl DatabaseRegistry for FakeDatabaseRegistryNotFound {
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

    struct RequireReasonPolicyEvaluator;
    impl PolicyEvaluator for RequireReasonPolicyEvaluator {
        fn evaluate_workflow(
            &self,
            _: &DatabaseName,
            _: &Environment,
            _: Operation,
        ) -> Result<Option<dbward_domain::policies::Workflow>, AppError> {
            Ok(Some(dbward_domain::policies::Workflow {
                id: "test-wf".into(),
                database: DatabaseName::wildcard(),
                environment: Environment::wildcard(),
                operations: vec![],
                steps: vec![],
                skip_approval_for: vec![],
                require_reason: true,
                allow_self_approve: false,
                allow_same_approver_across_steps: false,
            require_approval: false,
                pending_ttl_secs: None,
                statement_timeout_secs: None,
                approval_ttl_secs: None,
                created_at: None,
                updated_at: None,
            }))
        }
        fn get_execution_policy(
            &self,
            _: &DatabaseName,
            _: &Environment,
        ) -> dbward_domain::policies::ExecutionPolicy {
            Default::default()
        }
    }

    #[test]
    fn detail_too_long_returns_validation() {
        let uc = make_uc(Arc::new(AllowAll));
        let mut input = make_input();
        input.detail = "x".repeat(100_001);
        let err = uc
            .execute(
                input,
                &make_user(),
                &dbward_domain::entities::AuditContext::System,
            )
            .unwrap_err();
        assert!(matches!(err, AppError::Validation(ref m) if m.contains("query too long")));
    }

    #[test]
    fn reason_too_long_returns_validation() {
        let uc = make_uc(Arc::new(AllowAll));
        let mut input = make_input();
        input.reason = Some("r".repeat(1025));
        let err = uc
            .execute(
                input,
                &make_user(),
                &dbward_domain::entities::AuditContext::System,
            )
            .unwrap_err();
        assert!(matches!(err, AppError::Validation(ref m) if m.contains("reason too long")));
    }

    #[test]
    fn ddl_rejected_returns_validation() {
        let uc = make_uc(Arc::new(AllowAll));
        let mut input = make_input();
        input.detail = "CREATE TABLE foo (id INT)".into();
        let err = uc
            .execute(
                input,
                &make_user(),
                &dbward_domain::entities::AuditContext::System,
            )
            .unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[test]
    fn unregistered_db_returns_validation() {
        let uc = CreateRequest {
            authorizer: Arc::new(AllowAll),
            policy: Arc::new(FakePolicyEvaluator),
            request_reader: Arc::new(FakeRequestReader::new()),
            request_writer: Arc::new(FakeRequestWriter::new()),
            db_registry: Arc::new(FakeDatabaseRegistryNotFound),
            event_dispatcher: Arc::new(NoopDispatcher),
            clock: Arc::new(FixedClock::now_utc()),
            id_gen: Arc::new(FixedIdGen::new()),
            default_approval_ttl_secs: None,
        };
        let err = uc
            .execute(
                make_input(),
                &make_user(),
                &dbward_domain::entities::AuditContext::System,
            )
            .unwrap_err();
        assert!(
            matches!(err, AppError::Validation(ref m) if m.contains("database not registered"))
        );
    }

    #[test]
    fn require_reason_enforced() {
        let uc = CreateRequest {
            authorizer: Arc::new(AllowAll),
            policy: Arc::new(RequireReasonPolicyEvaluator),
            request_reader: Arc::new(FakeRequestReader::new()),
            request_writer: Arc::new(FakeRequestWriter::new()),
            db_registry: Arc::new(FakeDatabaseRegistry),
            event_dispatcher: Arc::new(NoopDispatcher),
            clock: Arc::new(FixedClock::now_utc()),
            id_gen: Arc::new(FixedIdGen::new()),
            default_approval_ttl_secs: None,
        };
        let mut input = make_input();
        input.reason = None;
        let err = uc
            .execute(
                input,
                &make_user(),
                &dbward_domain::entities::AuditContext::System,
            )
            .unwrap_err();
        assert!(
            matches!(err, AppError::Validation(ref m) if m.contains("reason is required by workflow policy"))
        );
    }

    #[test]
    fn mcp_emergency_rejected() {
        let uc = make_uc(Arc::new(AllowAll));
        let mut input = make_input();
        input.channel = RequestChannel::Mcp;
        input.emergency = true;
        input.reason = Some("incident".into());
        let err = uc
            .execute(
                input,
                &make_user(),
                &dbward_domain::entities::AuditContext::System,
            )
            .unwrap_err();
        assert!(
            matches!(err, AppError::Validation(ref m) if m.contains("emergency requests are not allowed via MCP"))
        );
    }
}
