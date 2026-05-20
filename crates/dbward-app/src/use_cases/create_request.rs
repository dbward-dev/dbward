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
    pub schema_repo: Arc<dyn SchemaRepo>,
    pub dry_run_repo: Arc<dyn DryRunRepo>,
    pub context_repo: Arc<dyn ContextRepo>,
    pub event_dispatcher: Arc<dyn EventDispatcher>,
    pub audit_logger: Arc<dyn AuditLogger>,
    pub clock: Arc<dyn Clock>,
    pub id_gen: Arc<dyn IdGenerator>,
    pub default_approval_ttl_secs: Option<u64>,
    pub review_rules: dbward_domain::services::sql_reviewer::ReviewRules,
    pub auto_approve_config: workflow_matcher::AutoApproveConfig,
}

const MAX_QUERY_BYTES: usize = 100_000;
const MAX_REASON_BYTES: usize = 1024;

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
        if input.detail.len() > MAX_QUERY_BYTES {
            return Err(AppError::Validation("query too long (max 100KB)".into()));
        }
        if let Some(ref reason) = input.reason {
            if reason.len() > MAX_REASON_BYTES {
                return Err(AppError::Validation("reason too long (max 1KB)".into()));
            }
        }

        // Resolve dialect once (used for classify, parse, review, risk)
        let dialect_str = self
            .schema_repo
            .get_dialect(input.database.as_str(), input.environment.as_str())
            .unwrap_or(None);
        let dialect = match dialect_str.as_deref() {
            Some(d) if d == dbward_domain::services::status_constants::dialect::MYSQL => {
                Dialect::MySql
            }
            _ => Dialect::PostgreSql,
        };

        // 1. Determine operation: migration types are explicit, others classified from SQL
        let operation = match input.operation {
            Operation::MigrateUp | Operation::MigrateDown | Operation::MigrateStatus => {
                input.operation
            }
            _ => {
                let classification =
                    sql_classifier::classify(&input.detail, dialect).map_err(|e| match e {
                        ClassifyError::Empty => AppError::Validation("empty query".into()),
                        ClassifyError::Rejected { reason } => AppError::Validation(reason),
                    })?;
                classification.operation
            }
        };

        // 1a. SQL Review + Risk assessment (best-effort, never blocks request creation)
        let (risk_level, review_json, risk_json, parsed_stmts, tables_json, schema_collected_at) = {
            use dbward_domain::services::{risk_scorer, sql_parser, sql_reviewer, table_extractor};
            let parse_result = sql_parser::parse_statements(&input.detail, dialect);
            if let Ok(stmts) = parse_result {
                let review =
                    sql_reviewer::review_statements(&stmts, Some(dialect), &self.review_rules);
                if review.blocked {
                    let reasons: Vec<&str> = review
                        .findings
                        .iter()
                        .filter(|f| f.action == sql_reviewer::RuleAction::Block)
                        .map(|f| f.message.as_str())
                        .collect();
                    // Audit: record blocked request
                    let mut audit_event = dbward_domain::entities::AuditEvent::simple(
                        "request_blocked_by_review",
                        "request",
                        &user.subject_id,
                        None,
                        self.clock.now(),
                        ctx,
                    );
                    audit_event.database_name = Some(input.database.to_string());
                    audit_event.environment = Some(input.environment.to_string());
                    audit_event.metadata_json = serde_json::json!({
                        "blocked_rules": reasons,
                    })
                    .to_string();
                    let _ = self.audit_logger.record(&audit_event);
                    return Err(AppError::Validation(format!(
                        "SQL blocked by review: {}",
                        reasons.join("; ")
                    )));
                }
                let tables = table_extractor::extract_tables(&stmts);
                let t_json = serde_json::to_string(
                    &tables
                        .iter()
                        .map(|t| {
                            if let Some(ref s) = t.schema {
                                format!("{}.{}", s, t.name)
                            } else {
                                t.name.clone()
                            }
                        })
                        .collect::<Vec<_>>(),
                )
                .ok();
                let (schema_status, schema_collected_at) = match self
                    .schema_repo
                    .get_snapshot(input.database.as_str(), input.environment.as_str())
                {
                    Ok(Some(s))
                        if s.status == dbward_domain::services::status_constants::schema::READY =>
                    {
                        (risk_scorer::SchemaStatus::Ready, Some(s.collected_at))
                    }
                    Ok(Some(s)) => (risk_scorer::SchemaStatus::Failed, Some(s.collected_at)),
                    _ => (risk_scorer::SchemaStatus::NotSynced, None),
                };
                let allow_read_only = operation == Operation::ExecuteSelect
                    && self.auto_approve_config.allow_read_only;
                let safe_ddl = self.auto_approve_config.allow_safe_ddl
                    && stmts.len() == 1
                    && stmts
                        .iter()
                        .all(|s| sql_classifier::is_safe_ddl_statement(s, Some(dialect)))
                    && review.findings.is_empty();
                let table_risk_info: Vec<risk_scorer::TableRiskInfo> = self
                    .schema_repo
                    .get_tables_for(input.database.as_str(), input.environment.as_str(), &tables)
                    .unwrap_or(None)
                    .and_then(|json| serde_json::from_str::<Vec<serde_json::Value>>(&json).ok())
                    .map(|arr| {
                        arr.iter()
                            .map(|t| {
                                let has_cascade = t
                                    .get("constraints")
                                    .and_then(|c| c.as_array())
                                    .map(|cs| {
                                        cs.iter().any(|c| {
                                            c.get("on_delete")
                                                .and_then(|d| d.as_str())
                                                .map(|d| d == "CASCADE")
                                                .unwrap_or(false)
                                        })
                                    })
                                    .unwrap_or(false);
                                risk_scorer::TableRiskInfo {
                                    name: t
                                        .get("name")
                                        .and_then(|n| n.as_str())
                                        .unwrap_or("")
                                        .to_string(),
                                    estimated_rows: t
                                        .get("estimated_rows")
                                        .and_then(|r| r.as_i64())
                                        .unwrap_or(0),
                                    has_cascade_fk: has_cascade,
                                    cascade_targets: t
                                        .get("constraints")
                                        .and_then(|c| c.as_array())
                                        .map(|cs| {
                                            cs.iter()
                                                .filter(|c| {
                                                    c.get("on_delete").and_then(|d| d.as_str())
                                                        == Some("CASCADE")
                                                })
                                                .filter_map(|c| {
                                                    c.get("referenced_table")
                                                        .and_then(|t| t.as_str())
                                                        .map(String::from)
                                                })
                                                .collect()
                                        })
                                        .unwrap_or_default(),
                                }
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let assessment = risk_scorer::evaluate(&risk_scorer::RiskInput {
                    operation,
                    findings: &review.findings,
                    schema_status,
                    tables: &table_risk_info,
                    statement_count: stmts.len(),
                    has_dml: matches!(operation, Operation::ExecuteDml),
                    allow_read_only,
                    safe_ddl,
                    max_estimated_rows: self.auto_approve_config.max_estimated_rows as i64,
                });
                let r_json = serde_json::json!({
                    "level": format!("{:?}", assessment.level),
                    "factors": assessment.factors.iter().map(|f| format!("{:?}", f)).collect::<Vec<_>>(),
                });
                let rev_json = serde_json::json!({
                    "findings": review.findings.iter().map(|f| {
                        serde_json::json!({"rule": format!("{:?}", f.rule), "message": &f.message})
                    }).collect::<Vec<_>>(),
                    "blocked": review.blocked,
                });
                (
                    Some(assessment.level),
                    Some(rev_json.to_string()),
                    Some(r_json.to_string()),
                    Some(stmts),
                    t_json,
                    schema_collected_at,
                )
            } else {
                (None, None, None, None, None, None)
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
                risk_level,
                &self.auto_approve_config,
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

        // 9. Create dry-run EXPLAIN jobs (best-effort, never blocks request)
        if matches!(operation, Operation::ExecuteSelect | Operation::ExecuteDml)
            && !request.no_store
        {
            let now_str = now.to_rfc3339();
            // Per-statement jobs (or single job if parse failed)
            let sql_texts: Vec<String> = if let Some(ref stmts) = parsed_stmts {
                stmts.iter().map(|s| s.to_string()).collect()
            } else {
                vec![request.detail.clone()]
            };
            let jobs: Vec<DryRunJobRecord> = sql_texts
                .iter()
                .map(|sql| DryRunJobRecord {
                    id: self.id_gen.generate(),
                    request_id: id.clone(),
                    database_name: request.database.as_str().to_string(),
                    environment: request.environment.as_str().to_string(),
                    sql_text: sql.clone(),
                    status: "pending".into(),
                    claimed_by: None,
                    claimed_at: None,
                    claim_token: None,
                    result_json: None,
                    error_message: None,
                    created_at: now_str.clone(),
                    completed_at: None,
                })
                .collect();
            if let Err(e) = self.dry_run_repo.create_jobs(&jobs) {
                tracing::warn!(%e, "failed to create dry-run jobs");
            }
        }

        // 10. Create request_context record (best-effort)
        if !request.no_store {
            let now_str = now.to_rfc3339();
            let has_dry_run = matches!(operation, Operation::ExecuteSelect | Operation::ExecuteDml);
            let ctx_status = if has_dry_run {
                dbward_domain::services::status_constants::context::COLLECTING
            } else {
                dbward_domain::services::status_constants::context::READY
            };
            let ctx_record = RequestContextRecord {
                request_id: id.clone(),
                status: ctx_status.into(),
                schema_snapshot_collected_at: schema_collected_at,
                tables_json,
                sql_review_json: review_json,
                risk_json,
                explain_json: None,
                created_at: now_str.clone(),
                updated_at: now_str,
            };
            if let Err(e) = self.context_repo.create(&ctx_record) {
                tracing::warn!(%e, "failed to create request context");
            }
        }

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
            schema_repo: Arc::new(FakeSchemaRepo),
            dry_run_repo: Arc::new(FakeDryRunRepo),
            context_repo: Arc::new(FakeContextRepo),
            event_dispatcher: Arc::new(NoopDispatcher),
            audit_logger: Arc::new(NoopAuditLogger),
            clock: Arc::new(FixedClock::now_utc()),
            id_gen: Arc::new(FixedIdGen::new()),
            default_approval_ttl_secs: None,
            review_rules: dbward_domain::services::sql_reviewer::ReviewRules::default(),
            auto_approve_config:
                dbward_domain::services::workflow_matcher::AutoApproveConfig::disabled(),
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
        input.detail = "GRANT ALL ON users TO admin".into();
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
            schema_repo: Arc::new(FakeSchemaRepo),
            dry_run_repo: Arc::new(FakeDryRunRepo),
            context_repo: Arc::new(FakeContextRepo),
            event_dispatcher: Arc::new(NoopDispatcher),
            audit_logger: Arc::new(NoopAuditLogger),
            clock: Arc::new(FixedClock::now_utc()),
            id_gen: Arc::new(FixedIdGen::new()),
            default_approval_ttl_secs: None,
            review_rules: dbward_domain::services::sql_reviewer::ReviewRules::default(),
            auto_approve_config:
                dbward_domain::services::workflow_matcher::AutoApproveConfig::disabled(),
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
            schema_repo: Arc::new(FakeSchemaRepo),
            dry_run_repo: Arc::new(FakeDryRunRepo),
            context_repo: Arc::new(FakeContextRepo),
            event_dispatcher: Arc::new(NoopDispatcher),
            audit_logger: Arc::new(NoopAuditLogger),
            clock: Arc::new(FixedClock::now_utc()),
            id_gen: Arc::new(FixedIdGen::new()),
            default_approval_ttl_secs: None,
            review_rules: dbward_domain::services::sql_reviewer::ReviewRules::default(),
            auto_approve_config:
                dbward_domain::services::workflow_matcher::AutoApproveConfig::disabled(),
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

    #[test]
    fn risk_level_computed_for_dml() {
        // Verify CreateRequest computes risk_level and passes it to workflow_matcher
        // With auto-approve disabled, it doesn't change the outcome but the code path runs
        let uc = make_uc(Arc::new(AllowAll));
        let mut input = make_input();
        input.detail = "DELETE FROM users".into(); // no WHERE → risk_scorer should find this risky
        let result = uc
            .execute(
                input,
                &make_user(),
                &dbward_domain::entities::AuditContext::System,
            )
            .unwrap();
        // With empty steps workflow → auto-approved (risk doesn't block because config disabled)
        assert_eq!(result.status, RequestStatus::Dispatched);
    }
}
