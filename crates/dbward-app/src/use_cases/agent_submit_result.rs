use std::sync::Arc;

use dbward_domain::auth::{AuthUser, Permission, ResourceContext};
use dbward_domain::entities::{ExecutionStatus, RequestStatus};
use dbward_domain::services::status_machine::{self, EventMetadata, RequestTrigger, TransitionContext};

use crate::error::AppError;
use crate::ports::*;

pub struct AgentSubmitResult {
    pub authorizer: Arc<dyn Authorizer>,
    pub agent_repo: Arc<dyn AgentRepo>,
    pub request_repo: Arc<dyn RequestRepo>,
    pub result_store: Arc<dyn ResultStore>,
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

        // 7. Save result to external storage (if success and not no_store)
        if input.success && !request.no_store {
            if let Some(data) = &input.result_data {
                let storage_key = format!("results/{}/{}", execution.request_id, execution.id);
                self.result_store.put(&storage_key, data).await?;
            }
        }

        // 8. Update execution status + finished_at
        let exec_status = if input.success { ExecutionStatus::Completed } else { ExecutionStatus::Failed };
        self.agent_repo.update_execution_status(&execution.id, exec_status)?;

        // 9. Update request status (skip if cancelled — request stays cancelled)
        let now = self.clock.now();
        if new_request_status != RequestStatus::Cancelled {
            let ok = match new_request_status {
                RequestStatus::Executed => self.request_repo.mark_executed(&execution.request_id, now)?,
                RequestStatus::Failed => self.request_repo.mark_failed(&execution.request_id, now)?,
                _ => true,
            };
            if !ok {
                return Err(AppError::Conflict("concurrent status change".into()));
            }
        }

        result.commit(&*self.event_dispatcher);

        Ok(AgentSubmitResultOutput {
            request_id: execution.request_id,
            status: new_request_status,
        })
    }
}
