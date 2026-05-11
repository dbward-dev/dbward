use std::sync::Arc;

use dbward_domain::auth::{AuthUser, Permission, ResourceContext};
use dbward_domain::entities::{Execution, ExecutionStatus};
use dbward_domain::services::status_machine::{self, RequestEvent};

use crate::error::AppError;
use crate::ports::*;

pub struct AgentClaim {
    pub authorizer: Arc<dyn Authorizer>,
    pub request_repo: Arc<dyn RequestRepo>,
    pub agent_repo: Arc<dyn AgentRepo>,
    pub token_signer: Arc<dyn TokenSigner>,
    pub clock: Arc<dyn Clock>,
    pub id_gen: Arc<dyn IdGenerator>,
}

pub struct AgentClaimInput {
    pub request_id: String,
}

pub struct AgentClaimOutput {
    pub execution_id: String,
    pub request_id: String,
    pub execution_token: String,
    pub operation: String,
    pub database: String,
    pub environment: String,
    pub detail: String,
}

impl AgentClaim {
    pub fn execute(&self, input: AgentClaimInput, user: &AuthUser) -> Result<AgentClaimOutput, AppError> {
        // 1. Authorization (global permission)
        self.authorizer.authorize_global(user, Permission::AgentClaim)
            .map_err(AppError::Forbidden)?;

        // 2. Get request
        let request = self.request_repo.get(&input.request_id)?
            .ok_or_else(|| AppError::NotFound("request not found".into()))?;

        // 3. Status check: must be dispatched
        status_machine::transition(request.status, &RequestEvent::Claim)
            .map_err(|e| AppError::Conflict(e.to_string()))?;

        // 4. Resource-level authorization (agent_id match)
        self.authorizer.authorize_scoped(
            user,
            Permission::AgentClaim,
            &request.database,
            &request.environment,
            &ResourceContext::AgentExecution { agent_id: user.subject_id.clone() },
        ).map_err(AppError::Forbidden)?;

        // 5. Create execution record
        let now = self.clock.now();
        let execution_id = self.id_gen.generate();
        let lease_expires_at = now + chrono::Duration::seconds(300);

        // 6. Sign execution token
        let detail_hash = hash_detail(&request.detail);
        let token = self.token_signer.sign(&ExecutionTokenClaims {
            request_id: request.id.clone(),
            operation: request.operation.as_str().to_string(),
            database: request.database.as_str().to_string(),
            environment: request.environment.as_str().to_string(),
            detail_hash,
            requester: request.requester.clone(),
        });

        let execution = Execution {
            id: execution_id.clone(),
            request_id: request.id.clone(),
            agent_id: user.subject_id.clone(),
            status: ExecutionStatus::Claimed,
            token: token.clone(),
            lease_expires_at,
            started_at: None,
            finished_at: None,
            error_message: None,
            created_at: now,
        };
        self.agent_repo.create_execution(&execution)?;

        // 7. Transition request to Running (via mark_dispatched is wrong — need a new method)
        // For now, the infra layer's create_execution should atomically set request.status = Running.
        // This is handled by the repo implementation (same TX as create_execution).

        Ok(AgentClaimOutput {
            execution_id,
            request_id: request.id,
            execution_token: token,
            operation: request.operation.as_str().to_string(),
            database: request.database.as_str().to_string(),
            environment: request.environment.as_str().to_string(),
            detail: request.detail,
        })
    }
}

/// Deterministic hash of SQL detail for token verification.
fn hash_detail(detail: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    detail.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}
