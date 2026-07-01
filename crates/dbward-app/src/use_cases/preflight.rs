use std::sync::Arc;

use dbward_domain::auth::Permission;
use dbward_domain::auth::ResourceContext;
use dbward_domain::auth::AuthUser;
use dbward_domain::entities::{AgentDerivedStatus, AgentStatus};
use dbward_domain::policies::workflow::Workflow;
use dbward_domain::services::classification::{ClassifyError, Dialect};
use dbward_domain::services::fix_hints;
use dbward_domain::services::risk_scorer::{self, RiskAssessment, RiskInput, RiskLevel, TableRiskInfo};
use dbward_domain::services::sql_classifier;
use dbward_domain::services::sql_reviewer::{self, Finding, ReviewResult, RuleAction};
use dbward_domain::services::table_extractor;
use dbward_domain::services::workflow_matcher::{self, ApprovalDecision};
use dbward_domain::values::{DatabaseName, Environment, Operation};
use serde::Serialize;

use crate::error::AppError;
use crate::ports::{
    AgentRepo, Authorizer, Clock, DatabaseRegistry, IdGenerator, PolicyEvaluator, SchemaRepo,
};

// ---------------------------------------------------------------------------
// Input / Output DTOs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PreflightInput {
    pub database: DatabaseName,
    pub environment: Environment,
    pub sql: String,
    pub operation_override: Option<String>,
    pub include_explain: bool,
    pub explain_timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PreflightResult {
    pub status: PreflightStatus,
    pub risk: RiskLevel,
    pub classification: PreflightClassification,
    pub review: PreflightReview,
    pub risk_assessment: PreflightRiskAssessment,
    pub policy: PreflightPolicy,
    pub impact: PreflightImpact,
    pub fix_hints: Vec<String>,
    pub retryable: bool,
    pub next_actions: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightStatus {
    Requestable,
    Blocked,
    Warning,
}

#[derive(Debug, Clone, Serialize)]
pub struct PreflightClassification {
    pub statement_type: String,
    pub operation: String,
    pub mutating: bool,
    pub ddl: bool,
    pub multi_statement: bool,
    pub statement_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct PreflightReview {
    pub findings: Vec<PreflightFinding>,
    pub blocked: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PreflightFinding {
    pub code: String,
    pub action: String,
    pub message: String,
    pub statement_index: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct PreflightRiskAssessment {
    pub level: RiskLevel,
    pub factors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PreflightPolicy {
    pub sql_valid: bool,
    pub caller_can_submit: bool,
    pub would_auto_approve: bool,
    pub requires_approval: bool,
    pub approvers: Vec<PreflightApprover>,
    pub break_glass_allowed: bool,
    pub workflow_id: Option<String>,
    pub require_reason: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PreflightApprover {
    pub selector: String,
    pub min: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct PreflightImpact {
    pub status: ImpactStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explain_plan: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimated_rows: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimated_cost: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index_used: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImpactStatus {
    Completed,
    Timeout,
    Skipped,
    NotAvailable,
    DisabledByPolicy,
    Error,
}

// ---------------------------------------------------------------------------
// PreflightPolicy mapper
// ---------------------------------------------------------------------------

impl PreflightPolicy {
    pub fn from_workflow(
        workflow: &Workflow,
        decision: &ApprovalDecision,
        review_blocked: bool,
        caller_has_break_glass: bool,
        caller_can_submit: bool,
    ) -> Self {
        let requires_approval = matches!(decision, ApprovalDecision::NeedsApproval);
        let would_auto_approve = matches!(decision, ApprovalDecision::AutoApproved { .. });
        let sql_valid = !review_blocked;

        let approvers: Vec<PreflightApprover> = workflow
            .steps
            .iter()
            .flat_map(|step| step.approvers.iter())
            .map(|a| PreflightApprover {
                selector: a.selector.to_string(),
                min: a.min,
            })
            .collect();

        Self {
            sql_valid,
            caller_can_submit,
            would_auto_approve,
            requires_approval,
            approvers,
            break_glass_allowed: caller_has_break_glass,
            workflow_id: Some(workflow.id.clone()),
            require_reason: workflow.require_reason,
        }
    }
}

// ---------------------------------------------------------------------------
// Use Case
// ---------------------------------------------------------------------------

pub struct PreflightUseCase {
    pub authorizer: Arc<dyn Authorizer>,
    pub policy_evaluator: Arc<dyn PolicyEvaluator>,
    pub db_registry: Arc<dyn DatabaseRegistry>,
    pub schema_repo: Arc<dyn SchemaRepo>,
    pub agent_repo: Arc<dyn AgentRepo>,
    pub clock: Arc<dyn Clock>,
    pub id_gen: Arc<dyn IdGenerator>,
    pub max_sql_length: usize,
}

impl PreflightUseCase {
    /// Execute static preflight analysis (layers 1-4).
    /// EXPLAIN (layer 5) is handled by the server handler via PreflightJobRepo + watch.
    pub fn execute(
        &self,
        user: &AuthUser,
        input: &PreflightInput,
    ) -> Result<(PreflightResult, Option<PreflightExplainRequest>), AppError> {
        // 1. Input validation
        if input.sql.len() > self.max_sql_length {
            return Err(AppError::Validation(format!(
                "SQL exceeds max length ({} > {})",
                input.sql.len(),
                self.max_sql_length
            )));
        }

        // 2. Authorization
        self.authorizer.authorize_scoped(
            user,
            Permission::RequestPreflight,
            &input.database,
            &input.environment,
            &ResourceContext::Global,
        )?;

        let effective_include_explain = if input.include_explain {
            self.authorizer
                .authorize_scoped(
                    user,
                    Permission::RequestPreflightExplain,
                    &input.database,
                    &input.environment,
                    &ResourceContext::Global,
                )
                .is_ok()
        } else {
            false
        };

        // 3. Database registration check
        if !self.db_registry.exists_active(&input.database, &input.environment)? {
            return Err(AppError::Validation(format!(
                "database '{}' environment '{}' is not registered",
                input.database, input.environment
            )));
        }

        // 4. Dialect resolution
        let dialect_str = self
            .schema_repo
            .get_dialect(input.database.as_str(), input.environment.as_str())?;
        let dialect = match dialect_str.as_deref() {
            Some("postgresql") => Dialect::PostgreSql,
            Some("mysql") => Dialect::MySql,
            _ => Dialect::PostgreSql, // fallback
        };

        // 5. SQL Classification
        let classify_result = sql_classifier::classify_full(&input.sql, dialect);
        let classification = match &classify_result.classification {
            Err(ClassifyError::Rejected { reason }) => {
                return Ok((blocked_result(reason), None));
            }
            Err(ClassifyError::Empty) => {
                return Err(AppError::Validation("SQL is empty".into()));
            }
            Ok(c) => c,
        };

        // Operation override validation
        if let Some(ref op_str) = input.operation_override {
            let classified_op = classification.operation.as_str();
            if op_str != classified_op {
                return Err(AppError::Validation(format!(
                    "operation override '{}' disagrees with classified '{}'",
                    op_str, classified_op
                )));
            }
        }

        let operation = classification.operation;

        // 6. Workflow lookup
        let workflow = match self.policy_evaluator.evaluate_workflow(
            &input.database,
            &input.environment,
            operation,
        )? {
            Some(wf) => wf,
            None => {
                return Ok((blocked_result("no workflow configured (fail-closed)"), None));
            }
        };

        // 7. SQL Review
        let review_policy = self
            .policy_evaluator
            .get_sql_review_policy(&input.database, &input.environment)?;
        let review_result = match &classify_result.parsed_statements {
            Some(stmts) => {
                sql_reviewer::review_statements(stmts, Some(dialect), &review_policy.rules)
            }
            None => sql_reviewer::review(&input.sql, Some(dialect), &review_policy.rules),
        };

        // 8. Table extraction + risk input
        let tables = classify_result
            .parsed_statements
            .as_ref()
            .map(|stmts| table_extractor::extract_tables(stmts))
            .unwrap_or_default();

        let table_risk_info = self.resolve_table_risk(&input.database, &input.environment, &tables);

        let max_estimated_rows = table_risk_info
            .iter()
            .map(|t| t.estimated_rows)
            .max()
            .unwrap_or(0);

        // 9. Risk Assessment
        let risk_input = RiskInput {
            operation,
            findings: &review_result.findings,
            schema_status: if table_risk_info.is_empty() && !tables.is_empty() {
                risk_scorer::SchemaStatus::NotSynced
            } else {
                risk_scorer::SchemaStatus::Ready
            },
            tables: &table_risk_info,
            statement_count: classification.statement_count,
            has_dml: !operation.is_read_only(),
            allow_read_only: operation.is_read_only(),
            safe_ddl: false,
            max_estimated_rows,
        };
        let risk_assessment = risk_scorer::evaluate(&risk_input);

        // 10. Policy simulation
        let decision =
            workflow_matcher::evaluate(&workflow, Some(risk_assessment.level));

        let op_permission = if operation.is_read_only() {
            Permission::RequestQuery
        } else {
            Permission::RequestExecute
        };
        let caller_can_submit = self
            .authorizer
            .authorize_scoped(
                user,
                op_permission,
                &input.database,
                &input.environment,
                &ResourceContext::Global,
            )
            .is_ok();
        let caller_has_break_glass = self
            .authorizer
            .authorize_scoped(
                user,
                Permission::RequestBreakGlass,
                &input.database,
                &input.environment,
                &ResourceContext::Global,
            )
            .is_ok();

        let policy = PreflightPolicy::from_workflow(
            &workflow,
            &decision,
            review_result.blocked,
            caller_has_break_glass,
            caller_can_submit,
        );

        // 11. Status determination
        let status = determine_status(&review_result, &policy, &risk_assessment, &workflow);

        // 12. Fix hints
        let hints = fix_hints::generate(&review_result.findings, risk_assessment.level);

        // 13. Impact / EXPLAIN
        let (impact, explain_request) = if !effective_include_explain {
            (
                PreflightImpact {
                    status: ImpactStatus::Skipped,
                    explain_plan: None,
                    estimated_rows: None,
                    estimated_cost: None,
                    index_used: None,
                },
                None,
            )
        } else if !workflow.explain {
            (
                PreflightImpact {
                    status: ImpactStatus::DisabledByPolicy,
                    explain_plan: None,
                    estimated_rows: None,
                    estimated_cost: None,
                    index_used: None,
                },
                None,
            )
        } else if !self.has_eligible_agent(&input.database, &input.environment)? {
            (
                PreflightImpact {
                    status: ImpactStatus::NotAvailable,
                    explain_plan: None,
                    estimated_rows: None,
                    estimated_cost: None,
                    index_used: None,
                },
                None,
            )
        } else {
            // Signal to handler that EXPLAIN job should be created
            let job_id = self.id_gen.generate();
            let explain_req = PreflightExplainRequest {
                job_id,
                database: input.database.clone(),
                environment: input.environment.clone(),
                sql: input.sql.clone(),
                timeout_ms: input.explain_timeout_ms,
                user_id: user.subject_id.clone(),
            };
            (
                PreflightImpact {
                    status: ImpactStatus::Skipped, // placeholder, handler replaces
                    explain_plan: None,
                    estimated_rows: None,
                    estimated_cost: None,
                    index_used: None,
                },
                Some(explain_req),
            )
        };

        // 14. Build classification DTO
        let classification_dto = PreflightClassification {
            statement_type: format!("{:?}", operation),
            operation: operation.as_str().to_string(),
            mutating: !operation.is_read_only(),
            ddl: classification.is_ddl_only,
            multi_statement: classification.statement_count > 1,
            statement_count: classification.statement_count,
        };

        // 15. Build review DTO
        let review_dto = PreflightReview {
            findings: review_result
                .findings
                .iter()
                .map(|f| PreflightFinding {
                    code: format!("{:?}", f.rule).to_lowercase(),
                    action: match f.action {
                        RuleAction::Block => "block".to_string(),
                        RuleAction::Warn => "warn".to_string(),
                        RuleAction::Off => "off".to_string(),
                    },
                    message: f.message.clone(),
                    statement_index: f.statement_index,
                })
                .collect(),
            blocked: review_result.blocked,
        };

        // 16. Build risk DTO
        let risk_dto = PreflightRiskAssessment {
            level: risk_assessment.level,
            factors: risk_assessment
                .factors
                .iter()
                .map(|f| format!("{f:?}"))
                .collect(),
        };

        // 17. Next actions
        let next_actions = build_next_actions(status, &review_result.findings);

        let result = PreflightResult {
            status,
            risk: risk_assessment.level,
            classification: classification_dto,
            review: review_dto,
            risk_assessment: risk_dto,
            policy,
            impact,
            fix_hints: hints,
            retryable: status != PreflightStatus::Requestable,
            next_actions,
        };

        Ok((result, explain_request))
    }

    fn has_eligible_agent(
        &self,
        database: &DatabaseName,
        environment: &Environment,
    ) -> Result<bool, AppError> {
        let now = self.clock.now();
        let agents = self.agent_repo.list()?;
        Ok(agents.iter().any(|a| {
            a.status != AgentStatus::Draining
                && a.derived_status(now) == AgentDerivedStatus::Healthy
                && a.databases.iter().any(|cap| {
                    &cap.database == database && &cap.environment == environment
                })
        }))
    }

    fn resolve_table_risk(
        &self,
        database: &DatabaseName,
        environment: &Environment,
        tables: &[table_extractor::TableRef],
    ) -> Vec<TableRiskInfo> {
        if tables.is_empty() {
            return vec![];
        }
        let json = self
            .schema_repo
            .get_tables_for(database.as_str(), environment.as_str(), tables)
            .ok()
            .flatten();
        match json {
            Some(ref s) => serde_json::from_str::<Vec<TableRiskInfo>>(s).unwrap_or_default(),
            None => vec![],
        }
    }
}

/// Returned when EXPLAIN is needed — the HTTP handler creates the job + waits.
#[derive(Debug, Clone)]
pub struct PreflightExplainRequest {
    pub job_id: String,
    pub database: DatabaseName,
    pub environment: Environment,
    pub sql: String,
    pub timeout_ms: u64,
    pub user_id: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn determine_status(
    review: &ReviewResult,
    policy: &PreflightPolicy,
    risk: &RiskAssessment,
    workflow: &Workflow,
) -> PreflightStatus {
    if review.blocked {
        return PreflightStatus::Blocked;
    }
    if !policy.caller_can_submit {
        return PreflightStatus::Blocked;
    }
    // Check risk against auto_approve threshold
    if let Some(ref aa) = workflow.auto_approve {
        if let Some(ref max_risk) = aa.max_risk_level {
            if risk.level > *max_risk {
                return PreflightStatus::Warning;
            }
        }
    }
    if review.findings.iter().any(|f| f.action == RuleAction::Warn) {
        return PreflightStatus::Warning;
    }
    PreflightStatus::Requestable
}

fn blocked_result(reason: &str) -> PreflightResult {
    PreflightResult {
        status: PreflightStatus::Blocked,
        risk: RiskLevel::Unknown,
        classification: PreflightClassification {
            statement_type: "unknown".into(),
            operation: "unknown".into(),
            mutating: false,
            ddl: false,
            multi_statement: false,
            statement_count: 0,
        },
        review: PreflightReview {
            findings: vec![PreflightFinding {
                code: "rejected".into(),
                action: "block".into(),
                message: reason.to_string(),
                statement_index: 0,
            }],
            blocked: true,
        },
        risk_assessment: PreflightRiskAssessment {
            level: RiskLevel::Unknown,
            factors: vec![],
        },
        policy: PreflightPolicy {
            sql_valid: false,
            caller_can_submit: false,
            would_auto_approve: false,
            requires_approval: false,
            approvers: vec![],
            break_glass_allowed: false,
            workflow_id: None,
            require_reason: false,
        },
        impact: PreflightImpact {
            status: ImpactStatus::Skipped,
            explain_plan: None,
            estimated_rows: None,
            estimated_cost: None,
            index_used: None,
        },
        fix_hints: vec![reason.to_string()],
        retryable: false,
        next_actions: vec![],
    }
}

fn build_next_actions(status: PreflightStatus, findings: &[Finding]) -> Vec<String> {
    match status {
        PreflightStatus::Requestable => vec![],
        PreflightStatus::Blocked => {
            let mut actions = vec![];
            if findings.iter().any(|f| {
                matches!(
                    f.rule,
                    sql_reviewer::RuleId::NoWhereUpdate | sql_reviewer::RuleId::NoWhereDelete
                )
            }) {
                actions.push("Run preflight again with a narrower WHERE clause".to_string());
            }
            if findings
                .iter()
                .any(|f| f.rule == sql_reviewer::RuleId::LargeInList)
            {
                actions.push("Consider batching into smaller transactions".to_string());
            }
            if actions.is_empty() {
                actions.push("Fix the blocking issues and run preflight again".to_string());
            }
            actions
        }
        PreflightStatus::Warning => {
            vec!["Review warnings before submitting the request".to_string()]
        }
    }
}
