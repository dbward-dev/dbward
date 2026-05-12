use std::sync::Arc;

use dbward_domain::auth::{AuthUser, Permission, ResourceContext};
use dbward_domain::entities::{AuditEvent, ExecutionResult, ExecutionStatus, RequestStatus, ResultAccess, SelectorType};
use dbward_domain::services::status_machine::{self, EventMetadata, RequestTrigger, TransitionContext};
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
    pub async fn execute(&self, input: AgentSubmitResultInput, user: &AuthUser) -> Result<AgentSubmitResultOutput, AppError> {
        // 1. Authorization (global)
        self.authorizer.authorize_global(user, Permission::AgentSubmitResult)
            .map_err(AppError::Forbidden)?;

        // 2. Get execution
        let execution = self.agent_repo.get_execution(&input.execution_id)?
            .ok_or_else(|| AppError::NotFound("execution not found".into()))?;

        // 3. Resource-level authorization (agent_id match via Authorizer)
        self.authorizer.authorize_scoped(
            user,
            Permission::AgentSubmitResult,
            &dbward_domain::values::DatabaseName::wildcard(),
            &dbward_domain::values::Environment::wildcard(),
            &ResourceContext::AgentExecution { agent_id: execution.agent_id.clone() },
        ).map_err(AppError::Forbidden)?;

        // 4. Verify execution is still active
        if execution.status != ExecutionStatus::Claimed {
            return Err(AppError::Conflict(format!(
                "execution is {:?}, cannot submit result", execution.status
            )));
        }

        // 5. Get request
        let request = self.request_repo.get(&execution.request_id)?
            .ok_or_else(|| AppError::Internal("request not found for execution".into()))?;

        // 6. Determine final status via status_machine
        // (Cancelled, Complete) → Cancelled is handled by status_machine (ADR-003/004)
        let now = self.clock.now();
        let result = status_machine::transition(
            request.status,
            &RequestTrigger::Complete { success: input.success },
            TransitionContext {
                request_id: request.id.clone(),
                actor_id: user.subject_id.clone(),
                actor_type: user.subject_type,
                database: request.database.clone(),
                environment: request.environment.clone(),
                operation: request.operation,
                timestamp: now,
                metadata: EventMetadata::Completed { success: input.success, execution_id: execution.id.clone() },
            },
        ).map_err(|e| AppError::Conflict(e.to_string()))?;

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
            self.result_store.put(&storage_key, err_json.to_string().as_bytes()).await?;
        }

        // Build share_with ResultAccess records
        let share_with_records: Vec<ResultAccess> = if let Some(ref rm) = result_manifest {
            request.share_with.iter().enumerate().map(|(i, sel)| {
                let (st, sv) = parse_selector_for_access(sel);
                ResultAccess {
                    id: format!("{}-ra-{}", rm.id, i),
                    result_id: rm.id.clone(),
                    selector_type: st,
                    selector_value: sv,
                }
            }).collect()
        } else {
            vec![]
        };

        // 8. Atomically update execution + request status + audit + result manifest
        let now = self.clock.now();
        let audit_event = AuditEvent::simple(
            if input.success { "execution.completed" } else { "execution.failed" },
            "execution",
            &user.subject_id,
            Some(&execution.id),
        );
        let request_updated = self.agent_repo.complete_execution(
            &execution.id,
            &execution.request_id,
            input.success,
            now,
            &audit_event,
            result_manifest.as_ref(),
            &share_with_records,
        )?;

        // 9. Publish result to long-poll channel
        let summary = ResultSummary {
            execution_id: execution.id.clone(),
            success: input.success,
            rows_affected: None,
            truncated: false,
            error_message: input.error_message.clone(),
        };
        self.result_channel.publish(&execution.request_id, summary).await;

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
