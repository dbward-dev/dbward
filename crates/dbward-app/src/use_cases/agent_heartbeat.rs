use std::sync::Arc;

use dbward_domain::auth::{AuthUser, Permission, ResourceContext};
use dbward_domain::entities::ExecutionStatus;

use crate::error::AppError;
use crate::ports::*;

pub struct AgentHeartbeat {
    pub authorizer: Arc<dyn Authorizer>,
    pub agent_repo: Arc<dyn AgentRepo>,
    pub request_repo: Arc<dyn RequestRepo>,
    pub event_dispatcher: Arc<dyn EventDispatcher>,
    pub clock: Arc<dyn Clock>,
}

pub struct AgentHeartbeatInput {
    pub execution_id: String,
}

pub struct AgentHeartbeatOutput {
    pub cancelled: bool,
}

impl AgentHeartbeat {
    pub fn execute(&self, input: AgentHeartbeatInput, user: &AuthUser) -> Result<AgentHeartbeatOutput, AppError> {
        // 1. Authorization (global)
        self.authorizer.authorize_global(user, Permission::AgentHeartbeat)
            .map_err(AppError::Forbidden)?;

        // 2. Get execution
        let execution = self.agent_repo.get_execution(&input.execution_id)?
            .ok_or_else(|| AppError::NotFound("execution not found".into()))?;

        // 3. Resource-level authorization (agent_id match via Authorizer)
        self.authorizer.authorize_scoped(
            user,
            Permission::AgentHeartbeat,
            &dbward_domain::values::DatabaseName::wildcard(),
            &dbward_domain::values::Environment::wildcard(),
            &ResourceContext::AgentExecution { agent_id: execution.agent_id.clone() },
        ).map_err(AppError::Forbidden)?;

        // 4. Verify execution is still active (Claimed = in progress)
        if execution.status != ExecutionStatus::Claimed {
            return Err(AppError::Conflict(format!(
                "execution is {:?}, cannot heartbeat", execution.status
            )));
        }

        // 5. Extend lease (+300 seconds)
        let new_expiry = self.clock.now() + chrono::Duration::seconds(300);
        self.agent_repo.extend_lease(&execution.id, new_expiry)?;

        // 6. Check if request was cancelled
        let request = self.request_repo.get(&execution.request_id)?;
        let cancelled = request
            .map(|r| r.status == dbward_domain::entities::RequestStatus::Cancelled)
            .unwrap_or(false);

        Ok(AgentHeartbeatOutput { cancelled })
    }
}
