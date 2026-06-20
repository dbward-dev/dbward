use std::sync::Arc;

use dbward_domain::auth::{AuthUser, Permission, ResourceContext};
use dbward_domain::entities::{Request, RequestStatus};
use dbward_domain::services::classification::{Classification, ClassifyError, Dialect, DmlReason};
use dbward_domain::services::risk_scorer;
use dbward_domain::services::sql_classifier;
use dbward_domain::services::status_machine::{
    self, EventMetadata, RequestTrigger, TransitionContext,
};
use dbward_domain::services::workflow_matcher;
use dbward_domain::values::{DatabaseName, Environment, Operation};

use crate::error::AppError;
use crate::ports::*;
use crate::use_cases::decision_trace::{self as dt};

/// Structured denial reasons for break-glass DDL bypass.
enum BreakGlassDenial {
    RequiresEmergency,
    RestrictedChannel,
    MissingAllowDdl { original_reason: String },
    NonBypassableStatement { reason: String },
    NonBypassableReviewRule { reasons: Vec<String> },
}

impl BreakGlassDenial {
    fn into_app_error(self) -> AppError {
        match self {
            Self::RequiresEmergency => {
                AppError::Validation("--allow-ddl requires --emergency".into())
            }
            Self::RestrictedChannel => {
                AppError::Validation("--allow-ddl is not allowed via MCP/Slack".into())
            }
            Self::MissingAllowDdl { original_reason } => AppError::Validation(format!(
                "{original_reason}. Hint: add --allow-ddl to bypass in emergency mode"
            )),
            Self::NonBypassableStatement { reason } => AppError::Validation(reason),
            Self::NonBypassableReviewRule { reasons } => AppError::Validation(format!(
                "SQL blocked by review (not bypassable): {}",
                reasons.join("; ")
            )),
        }
    }
}

pub struct CreateRequest {
    pub authorizer: Arc<dyn Authorizer>,
    pub policy: Arc<dyn PolicyEvaluator>,
    pub request_reader: Arc<dyn RequestReader>,
    pub request_writer: Arc<dyn RequestWriter>,
    pub db_registry: Arc<dyn DatabaseRegistry>,
    pub schema_repo: Arc<dyn SchemaRepo>,
    pub dry_run_repo: Arc<dyn DryRunRepo>,
    pub context_repo: Arc<dyn ContextRepo>,
    pub uow: Arc<dyn UnitOfWork>,
    pub notifier: Arc<dyn Notifier>,
    pub audit_logger: Arc<dyn AuditLogger>,
    pub break_glass_metrics: Arc<dyn BreakGlassMetrics>,
    pub clock: Arc<dyn Clock>,
    pub id_gen: Arc<dyn IdGenerator>,
    pub default_approval_ttl_secs: Option<u64>,
    pub review_rules: dbward_domain::services::sql_reviewer::ReviewRules,
    pub auto_approve_entries: Vec<workflow_matcher::AutoApproveEntry>,
}

const MAX_QUERY_BYTES: usize = 100_000;
const MAX_REASON_BYTES: usize = 1024;

/// Result of SQL classification, review, and risk assessment.
struct AssessmentResult {
    risk_level: Option<risk_scorer::RiskLevel>,
    review_json: Option<String>,
    risk_json: Option<String>,
    parsed_stmt_texts: Option<Vec<String>>,
    tables_json: Option<String>,
    schema_collected_at: Option<String>,
    trace_findings_count: usize,
    trace_risk_factors: Vec<String>,
    trace_schema_status: dt::SchemaStatus,
}

#[derive(Clone)]
pub struct CreateRequestInput {
    pub database: DatabaseName,
    pub environment: Environment,
    pub operation: Operation,
    pub detail: String,
    pub reason: Option<String>,
    pub emergency: bool,
    pub allow_ddl: bool,
    pub idempotency_key: Option<String>,
    pub share_with: Vec<String>,
    pub no_result_store: bool,
    pub metadata_json: String,
    pub channel: RequestChannel,
}

/// The channel through which the request was submitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestChannel {
    Cli,
    Api,
    Mcp,
    Slack,
}

impl RequestChannel {
    /// Channels that restrict emergency/DDL bypass (non-CLI, non-API).
    pub fn is_restricted(&self) -> bool {
        matches!(self, Self::Mcp | Self::Slack)
    }
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
        if let Some(ref reason) = input.reason
            && reason.len() > MAX_REASON_BYTES
        {
            return Err(AppError::Validation("reason too long (max 1KB)".into()));
        }

        // Early validation: --allow-ddl flags
        if input.allow_ddl && !input.emergency {
            return Err(BreakGlassDenial::RequiresEmergency.into_app_error());
        }
        if input.allow_ddl && input.channel.is_restricted() {
            return Err(BreakGlassDenial::RestrictedChannel.into_app_error());
        }

        // Record metric for all DDL bypass attempts (both classifier and reviewer paths)
        if input.emergency && input.allow_ddl {
            self.break_glass_metrics.record_ddl_attempted();
        }

        // Resolve dialect once (used for classify, parse, review, risk)
        let dialect_str = self
            .schema_repo
            .get_dialect(input.database.as_str(), input.environment.as_str())?;
        let dialect = match dialect_str.as_deref() {
            Some(d) if d == dbward_domain::services::status_constants::dialect::MYSQL => {
                Dialect::MySql
            }
            _ => Dialect::PostgreSql,
        };

        // 1. Determine operation: migration types are explicit, others classified from SQL
        let mut classifier_bypassed = false;
        let mut reviewer_bypassed = false;
        let (operation, classification, parsed_stmts) = match input.operation {
            Operation::MigrateUp
            | Operation::MigrateDown
            | Operation::MigrateStatus
            | Operation::MigrateRepair => (input.operation, None, None),
            _ => {
                let result = sql_classifier::classify_full(&input.detail, dialect);
                match result.classification {
                    Ok(c) => {
                        let op = c.operation;
                        (op, Some(c), result.parsed_statements)
                    }
                    Err(ClassifyError::Empty) => {
                        return Err(AppError::Validation("empty query".into()));
                    }
                    Err(ClassifyError::Rejected { reason }) => {
                        if input.emergency && input.allow_ddl {
                            // Break-glass DDL bypass attempt
                            match result.parsed_statements {
                                Some(ref stmts)
                                    if !stmts.is_empty()
                                        && stmts.iter().all(|s| {
                                            sql_classifier::categorize_statement(s)
                                                .is_break_glass_eligible()
                                        }) =>
                                {
                                    let stmt_strings: Vec<String> =
                                        stmts.iter().map(|s| s.to_string()).collect();
                                    let c = Classification {
                                        operation: Operation::ExecuteDml,
                                        dml_reason: Some(DmlReason::Ddl),
                                        statement_count: stmts.len(),
                                        statements: stmt_strings,
                                        is_ddl_only: true,
                                    };
                                    classifier_bypassed = true;
                                    (c.operation, Some(c), result.parsed_statements)
                                }
                                _ => {
                                    self.break_glass_metrics.record_ddl_denied();
                                    return Err(BreakGlassDenial::NonBypassableStatement {
                                        reason,
                                    }
                                    .into_app_error());
                                }
                            }
                        } else if input.emergency && !input.allow_ddl {
                            return Err(BreakGlassDenial::MissingAllowDdl {
                                original_reason: reason,
                            }
                            .into_app_error());
                        } else {
                            return Err(AppError::Validation(reason));
                        }
                    }
                }
            }
        };

        // 1a. SQL Review + Risk assessment (best-effort, never blocks request creation)
        let assessment = {
            use dbward_domain::services::{risk_scorer, sql_parser, sql_reviewer, table_extractor};
            let parse_result = sql_parser::parse_statements(&input.detail, dialect);
            if let Ok(stmts) = parse_result {
                let review =
                    sql_reviewer::review_statements(&stmts, Some(dialect), &self.review_rules);
                if review.blocked {
                    if input.emergency && input.allow_ddl {
                        // Break-glass reviewer bypass
                        let bypass_ok = match parsed_stmts.as_deref() {
                            Some(ps) if !ps.is_empty() => ps.iter().all(|s| {
                                sql_classifier::categorize_statement(s).is_break_glass_eligible()
                            }),
                            _ => false,
                        };
                        let non_bypassable: Vec<&str> = review
                            .findings
                            .iter()
                            .filter(|f| {
                                f.action == sql_reviewer::RuleAction::Block
                                    && !f.rule.is_break_glass_bypassable()
                            })
                            .map(|f| f.message.as_str())
                            .collect();
                        if !bypass_ok || !non_bypassable.is_empty() {
                            let reasons: Vec<&str> = review
                                .findings
                                .iter()
                                .filter(|f| f.action == sql_reviewer::RuleAction::Block)
                                .map(|f| f.message.as_str())
                                .collect();
                            let mut audit_event = dbward_domain::entities::AuditEvent::simple(
                                "request.blocked_by_review",
                                "request",
                                &user.subject_id,
                                None,
                                self.clock.now(),
                                ctx,
                            );
                            audit_event.metadata_json = serde_json::json!({
                                "blocked_rules": reasons,
                                "break_glass_attempted": true,
                            })
                            .to_string();
                            if let Err(e) = self.audit_logger.record(&audit_event) {
                                tracing::warn!(
                                    "audit write failed for blocked break-glass attempt: {e}"
                                );
                            }
                            self.break_glass_metrics.record_ddl_denied();
                            return Err(BreakGlassDenial::NonBypassableReviewRule {
                                reasons: reasons.iter().map(|s| s.to_string()).collect(),
                            }
                            .into_app_error());
                        }
                        // All blocks are bypassable DDL rules → proceed
                        reviewer_bypassed = true;
                    } else {
                        let reasons: Vec<&str> = review
                            .findings
                            .iter()
                            .filter(|f| f.action == sql_reviewer::RuleAction::Block)
                            .map(|f| f.message.as_str())
                            .collect();
                        // Audit: record blocked request
                        let mut audit_event = dbward_domain::entities::AuditEvent::simple(
                            "request.blocked_by_review",
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
                        if let Err(e) = self.audit_logger.record(&audit_event) {
                            tracing::error!(error = %e, "failed to record request_blocked_by_review audit event");
                        }
                        return Err(AppError::Validation(format!(
                            "SQL blocked by review: {}",
                            reasons.join("; ")
                        )));
                    }
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
                let auto_entry = workflow_matcher::find_auto_approve(
                    &self.auto_approve_entries,
                    &input.database,
                    &input.environment,
                );
                let allow_read_only = operation == Operation::ExecuteSelect
                    && auto_entry.map(|e| e.allow_read_only).unwrap_or(true);
                let safe_ddl = auto_entry.map(|e| e.allow_safe_ddl).unwrap_or(true)
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
                    max_estimated_rows: auto_entry
                        .map(|e| e.max_estimated_rows as i64)
                        .unwrap_or(1000),
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
                let trace_factors: Vec<String> = assessment
                    .factors
                    .iter()
                    .map(|f| format!("{:?}", f))
                    .collect();
                let trace_ss = match schema_status {
                    risk_scorer::SchemaStatus::Ready => dt::SchemaStatus::Ready,
                    risk_scorer::SchemaStatus::Failed => dt::SchemaStatus::Failed,
                    risk_scorer::SchemaStatus::NotSynced => dt::SchemaStatus::NotSynced,
                };
                AssessmentResult {
                    risk_level: Some(assessment.level),
                    review_json: Some(rev_json.to_string()),
                    risk_json: Some(r_json.to_string()),
                    parsed_stmt_texts: Some(stmts.iter().map(|s| s.to_string()).collect()),
                    tables_json: t_json,
                    schema_collected_at,
                    trace_findings_count: review.findings.len(),
                    trace_risk_factors: trace_factors,
                    trace_schema_status: trace_ss,
                }
            } else {
                AssessmentResult {
                    risk_level: None,
                    review_json: None,
                    risk_json: None,
                    parsed_stmt_texts: None,
                    tables_json: None,
                    schema_collected_at: None,
                    trace_findings_count: 0,
                    trace_risk_factors: vec![],
                    trace_schema_status: dt::SchemaStatus::Unavailable,
                }
            }
        };

        // 1b. Permission + DB/env scope check
        let perm = if input.emergency {
            Permission::RequestBreakGlass
        } else if operation == Operation::ExecuteSelect {
            Permission::RequestQuery
        } else {
            Permission::RequestExecute
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

        // Additional permission gate for DDL bypass
        if input.allow_ddl {
            self.authorizer
                .authorize_scoped(
                    user,
                    Permission::RequestBreakGlassDdl,
                    &input.database,
                    &input.environment,
                    &ResourceContext::Global,
                )
                .map_err(AppError::Forbidden)?;
        }

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

        // 1c-2. MigrateRepair always requires emergency (break-glass)
        if operation == Operation::MigrateRepair && !input.emergency {
            return Err(AppError::Validation(
                "migrate_repair requires emergency flag (break-glass)".into(),
            ));
        }

        // 1c. MCP channel cannot use break_glass
        if input.emergency && input.channel.is_restricted() {
            return Err(AppError::Validation(
                "emergency requests are not allowed via MCP/Slack".into(),
            ));
        }

        // 2. DB registered?
        if !self
            .db_registry
            .exists_active(&input.database, &input.environment)?
        {
            let mut msg = format!(
                "database '{}' not registered in environment '{}'",
                input.database, input.environment
            );
            // Show available environments for this database if <=5
            if let Ok(pairs) = self.db_registry.list_active() {
                let envs: Vec<&str> = pairs
                    .iter()
                    .filter(|(db, _)| db == &input.database)
                    .map(|(_, env)| env.as_str())
                    .collect();
                if !envs.is_empty() && envs.len() <= 5 {
                    msg.push_str(&format!(
                        ". Available environments: {}. Use --environment to specify",
                        envs.join(", ")
                    ));
                } else if envs.is_empty() {
                    msg.push_str(". Register it with: dbward database register");
                } else {
                    msg.push_str(". Use --environment to specify the correct environment");
                }
            }
            return Err(AppError::Validation(msg));
        }

        // 3. Idempotency (requester-scoped + fingerprint verification)
        if let Some(key) = &input.idempotency_key
            && let Some(existing) = self
                .request_reader
                .find_by_idempotency_key(&user.subject_id, key)?
        {
            // Verify fingerprint: same key + different detail = conflict
            let fingerprint = sha256_hex(input.detail.as_bytes());
            if let Some(ref existing_fp) = existing.idempotency_fingerprint
                && *existing_fp != fingerprint
            {
                return Err(AppError::Conflict(
                    "idempotency key conflict: same key used with different SQL".into(),
                ));
            }
            let approvers = extract_approvers(&existing);
            return Ok(CreateRequestOutput {
                id: existing.id,
                status: existing.status,
                operation: existing.operation,
                is_existing: true,
                expires_at: existing.expires_at,
                approvers,
            });
        }

        // 4. Workflow evaluation
        let workflow =
            self.policy
                .evaluate_workflow(&input.database, &input.environment, operation)?;
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
            let auto_approve_entry = workflow_matcher::find_auto_approve(
                &self.auto_approve_entries,
                &input.database,
                &input.environment,
            );
            workflow_matcher::evaluate(workflow.as_ref(), assessment.risk_level, auto_approve_entry)
        };

        // 5. Determine initial status
        let needs_approval = decision.needs_approval();
        let status = status_machine::initial_status(needs_approval, input.emergency);

        // 5b. Workflow require_reason check
        if let Some(ref wf) = workflow
            && wf.require_reason
            && input.reason.is_none()
        {
            return Err(AppError::Validation("reason_required".into()));
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
        // 6b. Build decision trace
        let parse_failed = assessment.parsed_stmt_texts.is_none();
        let auto_approve_entry_for_trace = workflow_matcher::find_auto_approve(
            &self.auto_approve_entries,
            &input.database,
            &input.environment,
        );
        let trace_risk_level = assessment
            .risk_level
            .unwrap_or(risk_scorer::RiskLevel::Unavailable);
        let trace_reasons = match &decision {
            workflow_matcher::ApprovalDecision::AutoApproved { reason } => match reason {
                workflow_matcher::AutoApproveReason::EmptySteps => {
                    vec![dt::DecisionReason::EmptySteps]
                }
                workflow_matcher::AutoApproveReason::RiskBased => {
                    vec![dt::DecisionReason::RiskBelowThreshold]
                }
            },
            workflow_matcher::ApprovalDecision::NeedsApproval => {
                if auto_approve_entry_for_trace.is_none() {
                    vec![dt::DecisionReason::NoAutoApproveRule]
                } else if auto_approve_entry_for_trace
                    .and_then(|e| e.max_risk_level)
                    .is_none()
                {
                    vec![dt::DecisionReason::AutoApproveDisabled]
                } else if assessment.risk_level.is_none() {
                    vec![dt::DecisionReason::RiskUnavailable]
                } else {
                    vec![dt::DecisionReason::RiskAboveThreshold]
                }
            }
            workflow_matcher::ApprovalDecision::Pending => {
                vec![]
            }
        };
        let trace_outcome = if !needs_approval {
            dt::Outcome::AutoApproved
        } else {
            dt::Outcome::NeedsApproval
        };
        // Override for break-glass: status_machine forces BreakGlass when emergency=true
        let (trace_outcome, trace_reasons) = if input.emergency {
            (
                dt::Outcome::AutoApproved,
                vec![dt::DecisionReason::BreakGlass],
            )
        } else {
            (trace_outcome, trace_reasons)
        };
        let trace_threshold = auto_approve_entry_for_trace.and_then(|e| e.max_risk_level);
        let decision_trace = dt::DecisionTrace {
            version: 1,
            classification: dt::Classification {
                resolved_operation: operation.into(),
            },
            sql_review: dt::SqlReview {
                findings_count: assessment.trace_findings_count,
                parse_failed,
            },
            risk: dt::Risk {
                level: trace_risk_level,
                factors: if parse_failed {
                    vec![]
                } else {
                    assessment.trace_risk_factors
                },
                schema_status: if parse_failed {
                    dt::SchemaStatus::Unavailable
                } else {
                    assessment.trace_schema_status
                },
            },
            workflow: dt::WorkflowMatch {
                matched: workflow.as_ref().map(|wf| dt::WorkflowRef {
                    id: wf.id.clone(),
                    database: wf.database.to_string(),
                    environment: wf.environment.to_string(),
                    step_count: wf.steps.len(),
                }),
            },
            decision: dt::Decision {
                outcome: trace_outcome,
                reasons: trace_reasons,
                auto_approve_threshold: trace_threshold,
            },
        };
        let decision_trace_json = serde_json::to_string(&decision_trace)
            .map_err(|e| AppError::Internal(format!("serialize decision_trace: {e}")))?;

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
            idempotency_key: input.idempotency_key.clone(),
            idempotency_fingerprint: input
                .idempotency_key
                .as_ref()
                .map(|_| sha256_hex(input.detail.as_bytes())),
            metadata_json: input.metadata_json,
            share_with: input.share_with,
            no_result_store: input.no_result_store,
            workflow_snapshot_json,
            decision_trace_json: Some(decision_trace_json),
            execution_plan_json: classification.as_ref().and_then(|c| {
                if c.dml_reason == Some(DmlReason::ParseFailure) {
                    None
                } else {
                    match serde_json::to_string(&c.statements) {
                        Ok(s) => Some(s),
                        Err(e) => {
                            tracing::error!(error = %e, "failed to serialize execution plan");
                            None
                        }
                    }
                }
            }),
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
            // For DDL bypass: use atomic create+dispatch+audit (fail-closed)
            if classifier_bypassed || reviewer_bypassed {
                // Build all 3 audit events: request.created + request.dispatched + ddl.break_glass_bypass
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
                            detail: input.detail.clone(),
                            emergency: input.emergency,
                        },
                        requester_id: user.subject_id.clone(),
                        audit_context: ctx.clone(),
                    },
                );
                let create_event = create_result.into_event();
                let dispatch_result = status_machine::transition(
                    status,
                    &RequestTrigger::Dispatch,
                    TransitionContext {
                        request_id: id.clone(),
                        actor_id: user.subject_id.clone(),
                        actor_type: user.subject_type,
                        database: input.database.clone(),
                        environment: input.environment.clone(),
                        operation,
                        timestamp: now,
                        metadata: EventMetadata::Dispatched,
                        requester_id: user.subject_id.clone(),
                        audit_context: ctx.clone(),
                    },
                )
                .map_err(|e| AppError::Internal(e.to_string()))?;
                let dispatch_event = dispatch_result.into_event();

                let create_audit = crate::services::audit_event_builder::build_audit_event(
                    &create_event,
                    now,
                    crate::services::audit_event_builder::RedactionMode::default(),
                    crate::services::audit_event_builder::noop_redact,
                );
                let dispatch_audit = crate::services::audit_event_builder::build_audit_event(
                    &dispatch_event,
                    now,
                    crate::services::audit_event_builder::RedactionMode::default(),
                    crate::services::audit_event_builder::noop_redact,
                );

                let mut ddl_event = dbward_domain::entities::AuditEvent::simple(
                    "ddl.break_glass_bypass",
                    "request",
                    &user.subject_id,
                    Some(&id),
                    self.clock.now(),
                    ctx,
                );
                ddl_event.database_name = Some(request.database.as_str().to_string());
                ddl_event.environment = Some(request.environment.as_str().to_string());
                ddl_event.metadata_json = serde_json::json!({
                    "request_id": &id,
                    "sql_redacted": sql_classifier::redact_literals(&request.detail),
                    "statement_count": classification.as_ref().map(|c| c.statement_count).unwrap_or(0),
                    "reason": request.reason.as_deref().unwrap_or(""),
                    "classifier_bypassed": classifier_bypassed,
                    "reviewer_bypassed": reviewer_bypassed,
                })
                .to_string();

                match self.uow.execute(Box::new({
                    let request = request.clone();
                    let ddl_event = ddl_event.clone();
                    let id = id.clone();
                    move |tx| {
                        tx.insert_request(&request)?;
                        tx.mark_dispatched(&id, now)?;
                        tx.record(&create_audit)?;
                        tx.record(&dispatch_audit)?;
                        tx.record(&ddl_event)?;
                        Ok(())
                    }
                })) {
                    Ok(()) => {}
                    Err(AppError::Conflict(ref msg))
                        if msg.contains("idempotency_key") || msg.contains("UNIQUE constraint") =>
                    {
                        if let Some(ref key) = request.idempotency_key
                            && let Some(existing) = self
                                .request_reader
                                .find_by_idempotency_key(&user.subject_id, key)?
                        {
                            let approvers = extract_approvers(&existing);
                            return Ok(CreateRequestOutput {
                                id: existing.id,
                                status: existing.status,
                                operation: existing.operation,
                                is_existing: true,
                                expires_at: existing.expires_at,
                                approvers,
                            });
                        }
                        return Err(AppError::Conflict("idempotency_key".into()));
                    }
                    Err(e) => {
                        tracing::error!(
                            request_id = %id,
                            actor = %user.subject_id,
                            database = %request.database,
                            environment = %request.environment,
                            classifier_bypassed,
                            reviewer_bypassed,
                            "break-glass DDL dispatch blocked (fail-closed): {e}"
                        );
                        self.break_glass_metrics.record_audit_failure();
                        return Err(e);
                    }
                }
                self.break_glass_metrics.record_ddl_allowed();

                // DDL break-glass committed — post-commit notifications
                self.notifier
                    .dispatch(crate::services::audit_event_builder::build_webhook_event(
                        &create_event,
                    ));
                self.notifier
                    .dispatch(crate::services::audit_event_builder::build_webhook_event(
                        &dispatch_event,
                    ));

                return Ok(CreateRequestOutput {
                    id,
                    status: RequestStatus::Dispatched,
                    operation,
                    is_existing: false,
                    expires_at,
                    approvers: vec![],
                });
            } else {
                // handled below in unified UoW block
            }

            // Emit creation + dispatch audit events (atomic)
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
            let create_event = create_result.into_event();

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
            let dispatch_event = dispatch_result.into_event();

            // Write audit events atomically
            let create_audit = crate::services::audit_event_builder::build_audit_event(
                &create_event,
                now,
                crate::services::audit_event_builder::RedactionMode::default(),
                crate::services::audit_event_builder::noop_redact,
            );
            let dispatch_audit = crate::services::audit_event_builder::build_audit_event(
                &dispatch_event,
                now,
                crate::services::audit_event_builder::RedactionMode::default(),
                crate::services::audit_event_builder::noop_redact,
            );
            let request_for_uow = request.clone();
            let req_id = id.clone();
            match self.uow.execute(Box::new(move |tx| {
                tx.insert_request(&request_for_uow)?;
                tx.mark_dispatched(&req_id, now)?;
                tx.record(&create_audit)?;
                tx.record(&dispatch_audit)?;
                Ok(())
            })) {
                Ok(()) => {}
                Err(AppError::Conflict(ref msg))
                    if msg.contains("idempotency_key") || msg.contains("UNIQUE constraint") =>
                {
                    if let Some(ref key) = request.idempotency_key
                        && let Some(existing) = self
                            .request_reader
                            .find_by_idempotency_key(&user.subject_id, key)?
                    {
                        let approvers = extract_approvers(&existing);
                        return Ok(CreateRequestOutput {
                            id: existing.id,
                            status: existing.status,
                            operation: existing.operation,
                            is_existing: true,
                            expires_at: existing.expires_at,
                            approvers,
                        });
                    }
                    return Err(AppError::Conflict("idempotency_key".into()));
                }
                Err(e) => return Err(e),
            }

            // Post-commit notifications
            self.notifier
                .dispatch(crate::services::audit_event_builder::build_webhook_event(
                    &create_event,
                ));
            self.notifier
                .dispatch(crate::services::audit_event_builder::build_webhook_event(
                    &dispatch_event,
                ));
            s
        } else {
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
            let create_event = create_result.into_event();
            let create_audit = crate::services::audit_event_builder::build_audit_event(
                &create_event,
                now,
                crate::services::audit_event_builder::RedactionMode::default(),
                crate::services::audit_event_builder::noop_redact,
            );
            let request_for_uow = request.clone();
            match self.uow.execute(Box::new(move |tx| {
                tx.insert_request(&request_for_uow)?;
                tx.record(&create_audit)?;
                Ok(())
            })) {
                Ok(()) => {}
                Err(AppError::Conflict(ref msg))
                    if msg.contains("idempotency_key") || msg.contains("UNIQUE constraint") =>
                {
                    if let Some(ref key) = request.idempotency_key
                        && let Some(existing) = self
                            .request_reader
                            .find_by_idempotency_key(&user.subject_id, key)?
                    {
                        let approvers = extract_approvers(&existing);
                        return Ok(CreateRequestOutput {
                            id: existing.id,
                            status: existing.status,
                            operation: existing.operation,
                            is_existing: true,
                            expires_at: existing.expires_at,
                            approvers,
                        });
                    }
                    return Err(AppError::Conflict("idempotency_key".into()));
                }
                Err(e) => return Err(e),
            }
            self.notifier
                .dispatch(crate::services::audit_event_builder::build_webhook_event(
                    &create_event,
                ));
            status
        };

        // 9. Create dry-run EXPLAIN jobs (best-effort, never blocks request)
        let should_explain = workflow.as_ref().map(|w| w.explain).unwrap_or(true);
        if should_explain
            && matches!(operation, Operation::ExecuteSelect | Operation::ExecuteDml)
            && !request.no_result_store
        {
            let now_str = now.to_rfc3339();
            // Per-statement jobs (or single job if parse failed)
            let sql_texts: Vec<String> = if let Some(ref stmts) = assessment.parsed_stmt_texts {
                stmts.clone()
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
        if !request.no_result_store {
            let now_str = now.to_rfc3339();
            let has_dry_run = should_explain
                && matches!(operation, Operation::ExecuteSelect | Operation::ExecuteDml);
            let ctx_status = if has_dry_run {
                dbward_domain::services::status_constants::context::COLLECTING
            } else {
                dbward_domain::services::status_constants::context::READY
            };
            let ctx_record = RequestContextRecord {
                request_id: id.clone(),
                status: ctx_status.into(),
                schema_snapshot_collected_at: assessment.schema_collected_at,
                tables_json: assessment.tables_json,
                sql_review_json: assessment.review_json,
                risk_json: assessment.risk_json,
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

fn extract_approvers(req: &dbward_domain::entities::Request) -> Vec<String> {
    if req.status == dbward_domain::entities::RequestStatus::Pending {
        req.workflow_snapshot_json
            .as_ref()
            .and_then(|json| {
                serde_json::from_str::<serde_json::Value>(json)
                    .inspect_err(|e| {
                        tracing::warn!(
                            error = %e,
                            request_id = %req.id,
                            "corrupt workflow_snapshot_json in extract_approvers"
                        );
                    })
                    .ok()
                    .and_then(|v| {
                        v["steps"][0]["approvers"].as_array().map(|arr| {
                            arr.iter()
                                .filter_map(|a| a["selector"].as_str().map(String::from))
                                .collect()
                        })
                    })
            })
            .unwrap_or_default()
    } else {
        vec![]
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
            uow: Arc::new(NoopUnitOfWork),
            notifier: Arc::new(NoopNotifier),
            audit_logger: Arc::new(NoopAuditLogger),
            break_glass_metrics: Arc::new(NoopBreakGlassMetrics),
            clock: Arc::new(FixedClock::now_utc()),
            id_gen: Arc::new(FixedIdGen::new()),
            default_approval_ttl_secs: None,
            review_rules: dbward_domain::services::sql_reviewer::ReviewRules::default(),
            auto_approve_entries: vec![],
        }
    }

    fn make_user() -> AuthUser {
        AuthUser {
            subject_id: "alice".into(),
            subject_type: SubjectType::User,
            roles: vec![ResolvedRole {
                name: "app-dev".into(),
                permissions: [Permission::RequestExecute, Permission::RequestView]
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
            allow_ddl: false,
            idempotency_key: None,
            share_with: vec![],
            no_result_store: false,
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
        fn exists_active(&self, _: &DatabaseName, _: &Environment) -> Result<bool, AppError> {
            Ok(false)
        }
        fn list_active(&self) -> Result<Vec<(DatabaseName, Environment)>, AppError> {
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
                require_reason: true,
                allow_self_approve: false,
                allow_same_approver_across_steps: false,
                explain: true,
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
        ) -> Result<dbward_domain::policies::ExecutionPolicy, AppError> {
            Ok(Default::default())
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
            uow: Arc::new(NoopUnitOfWork),
            notifier: Arc::new(NoopNotifier),
            audit_logger: Arc::new(NoopAuditLogger),
            break_glass_metrics: Arc::new(NoopBreakGlassMetrics),
            clock: Arc::new(FixedClock::now_utc()),
            id_gen: Arc::new(FixedIdGen::new()),
            default_approval_ttl_secs: None,
            review_rules: dbward_domain::services::sql_reviewer::ReviewRules::default(),
            auto_approve_entries: vec![],
        };
        let err = uc
            .execute(
                make_input(),
                &make_user(),
                &dbward_domain::entities::AuditContext::System,
            )
            .unwrap_err();
        assert!(
            matches!(err, AppError::Validation(ref m) if m.contains("not registered in environment"))
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
            uow: Arc::new(NoopUnitOfWork),
            notifier: Arc::new(NoopNotifier),
            audit_logger: Arc::new(NoopAuditLogger),
            break_glass_metrics: Arc::new(NoopBreakGlassMetrics),
            clock: Arc::new(FixedClock::now_utc()),
            id_gen: Arc::new(FixedIdGen::new()),
            default_approval_ttl_secs: None,
            review_rules: dbward_domain::services::sql_reviewer::ReviewRules::default(),
            auto_approve_entries: vec![],
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
        assert!(matches!(err, AppError::Validation(ref m) if m == "reason_required"));
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
            matches!(err, AppError::Validation(ref m) if m.contains("emergency requests are not allowed via MCP/Slack"))
        );
    }

    #[test]
    fn risk_level_computed_for_dml() {
        // Verify CreateRequest computes risk_level and passes it to workflow_matcher
        // With auto-approve disabled, it doesn't change the outcome but the code path runs
        let uc = make_uc(Arc::new(AllowAll));
        let mut input = make_input();
        input.detail = "DELETE FROM users WHERE id = 1".into(); // DML → risk_scorer computes risk
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

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}
