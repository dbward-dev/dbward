use std::sync::Arc;

use dbward_domain::auth::{AuthUser, Permission, ResourceContext};
use dbward_domain::entities::{ExecutionStatus, RequestStatus};
use dbward_domain::services::status_machine::{self, RequestEvent};

use crate::error::AppError;
use crate::ports::*;

pub struct AgentSubmitResult {
    pub authorizer: Arc<dyn Authorizer>,
    pub agent_repo: Arc<dyn AgentRepo>,
    pub request_repo: Arc<dyn RequestRepo>,
    pub result_store: Arc<dyn ResultStore>,
    pub audit: Arc<dyn AuditLogger>,
    pub notifier: Arc<dyn Notifier>,
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
        // 1. Authorization
        self.authorizer.authorize_global(user, Permission::AgentSubmitResult)
            .map_err(AppError::Forbidden)?;

        // 2. Get execution
        let execution = self.agent_repo.get_execution(&input.execution_id)?
            .ok_or_else(|| AppError::NotFound("execution not found".into()))?;

        // 3. Verify ownership
        if execution.agent_id != user.subject_id {
            return Err(AppError::Forbidden(crate::error::AuthzError::Forbidden {
                permission: Permission::AgentSubmitResult,
                reason: "not your execution".into(),
            }));
        }

        // 4. Verify execution is claimable for result submission
        if execution.status != ExecutionStatus::Claimed {
            return Err(AppError::Conflict(format!(
                "execution is {:?}, cannot submit result", execution.status
            )));
        }

        // 5. Get request for status transition
        let request = self.request_repo.get(&execution.request_id)?
            .ok_or_else(|| AppError::Internal("request not found for execution".into()))?;

        // 6. Determine new status via status_machine
        let event = RequestEvent::Complete { success: input.success };
        let new_status = status_machine::transition(request.status, &event)
            .map_err(|e| AppError::Conflict(e.to_string()))?;

        // 7. Save result to external storage (if success and data provided)
        if input.success {
            if let Some(data) = &input.result_data {
                let storage_key = format!("results/{}/{}", execution.request_id, execution.id);
                self.result_store.put(&storage_key, data).await?;
            }
        }

        // 8. Update execution status
        let exec_status = if input.success { ExecutionStatus::Completed } else { ExecutionStatus::Failed };
        self.agent_repo.update_execution_status(&execution.id, exec_status)?;

        // 9. Update request status (Executed or Failed)
        let now = self.clock.now();
        match new_status {
            RequestStatus::Executed => { self.request_repo.mark_executed(&execution.request_id, now)?; }
            RequestStatus::Failed => { self.request_repo.mark_failed(&execution.request_id, now)?; }
            _ => {}
        }

        Ok(AgentSubmitResultOutput {
            request_id: execution.request_id,
            status: new_status,
        })
    }
}
