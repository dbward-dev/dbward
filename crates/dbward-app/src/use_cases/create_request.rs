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
    pub request_repo: Arc<dyn RequestRepo>,
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
            if let Some(existing) = self.request_repo.find_by_idempotency_key(key)? {
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
                workflow_matcher::ApprovalDecision::AutoApproved
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
            )
        };

        // 5. Determine initial status
        let needs_approval = !matches!(decision, workflow_matcher::ApprovalDecision::AutoApproved);
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
            self.request_repo.create_and_dispatch(&request)?;

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
            self.request_repo.insert(&request)?;

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
    use dbward_domain::auth::{ResolvedRole, SubjectType};

    struct AllowAll;
    impl Authorizer for AllowAll {
        fn authorize_scoped(
            &self,
            _: &AuthUser,
            _: Permission,
            _: &DatabaseName,
            _: &Environment,
            _: &ResourceContext,
        ) -> Result<(), crate::error::AuthzError> {
            Ok(())
        }
        fn authorize_global(
            &self,
            _: &AuthUser,
            _: Permission,
        ) -> Result<(), crate::error::AuthzError> {
            Ok(())
        }
    }

    struct DenyAll;
    impl Authorizer for DenyAll {
        fn authorize_scoped(
            &self,
            _: &AuthUser,
            p: Permission,
            _: &DatabaseName,
            _: &Environment,
            _: &ResourceContext,
        ) -> Result<(), crate::error::AuthzError> {
            Err(crate::error::AuthzError::Forbidden {
                permission: p,
                reason: "denied".into(),
            })
        }
        fn authorize_global(
            &self,
            _: &AuthUser,
            p: Permission,
        ) -> Result<(), crate::error::AuthzError> {
            Err(crate::error::AuthzError::Forbidden {
                permission: p,
                reason: "denied".into(),
            })
        }
    }

    struct FakePolicy;
    impl PolicyEvaluator for FakePolicy {
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
                require_reason: false,
                allow_self_approve: false,
                allow_same_approver_across_steps: false,
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

    struct FakeRequestRepo;
    impl RequestRepo for FakeRequestRepo {
        fn insert(&self, _: &Request) -> Result<(), AppError> {
            Ok(())
        }
        fn get(&self, _: &str) -> Result<Option<Request>, AppError> {
            Ok(None)
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
        fn insert_approval(&self, _: &dbward_domain::entities::Approval) -> Result<(), AppError> {
            Ok(())
        }
        fn get_approvals(
            &self,
            _: &str,
        ) -> Result<Vec<dbward_domain::entities::Approval>, AppError> {
            Ok(vec![])
        }
        fn count_executions(&self, _: &str) -> Result<u32, AppError> {
            Ok(0)
        }
        fn mark_approved(
            &self,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn approve_and_mark_approved(
            &self,
            _: &dbward_domain::entities::Approval,
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
        fn reject_and_record(
            &self,
            _: &str,
            _: &dbward_domain::entities::Approval,
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
        fn create_and_dispatch(&self, _: &Request) -> Result<(), AppError> {
            Ok(())
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
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<u32, AppError> {
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
            _: &dbward_domain::entities::AuditEvent,
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
        fn is_pending_approver(
            &self,
            _: &str,
            _: &str,
            _: &[String],
            _: &[String],
        ) -> Result<bool, AppError> {
            Ok(false)
        }
    }

    struct FakeDbRegistry;
    impl DatabaseRegistry for FakeDbRegistry {
        fn register(&self, _: &DatabaseName, _: &Environment) -> Result<(), AppError> {
            Ok(())
        }
        fn exists(&self, _: &DatabaseName, _: &Environment) -> Result<bool, AppError> {
            Ok(true)
        }
        fn list(&self) -> Result<Vec<(DatabaseName, Environment)>, AppError> {
            Ok(vec![])
        }
    }

    struct NoopDispatcher;
    impl EventDispatcher for NoopDispatcher {
        fn dispatch(&self, _: dbward_domain::services::status_machine::TransitionEvent) {}
    }

    struct FakeClock;
    impl Clock for FakeClock {
        fn now(&self) -> chrono::DateTime<chrono::Utc> {
            chrono::Utc::now()
        }
    }

    struct FakeIdGen;
    impl IdGenerator for FakeIdGen {
        fn generate(&self) -> String {
            "test-id-001".into()
        }
    }

    fn make_uc(authorizer: Arc<dyn Authorizer>) -> CreateRequest {
        CreateRequest {
            authorizer,
            policy: Arc::new(FakePolicy),
            request_repo: Arc::new(FakeRequestRepo),
            db_registry: Arc::new(FakeDbRegistry),
            event_dispatcher: Arc::new(NoopDispatcher),
            clock: Arc::new(FakeClock),
            id_gen: Arc::new(FakeIdGen),
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
}
