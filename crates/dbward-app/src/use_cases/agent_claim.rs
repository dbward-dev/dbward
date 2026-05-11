use std::sync::Arc;

use sha2::{Digest, Sha256};

use dbward_domain::auth::{AuthUser, Permission, ResourceContext};
use dbward_domain::entities::{Execution, ExecutionStatus};
use dbward_domain::services::status_machine::{self, RequestEvent};
use dbward_domain::values::Operation;

use crate::error::AppError;
use crate::ports::*;

pub struct AgentClaim {
    pub authorizer: Arc<dyn Authorizer>,
    pub request_repo: Arc<dyn RequestRepo>,
    pub agent_repo: Arc<dyn AgentRepo>,
    pub policy: Arc<dyn PolicyEvaluator>,
    pub token_signer: Arc<dyn TokenSigner>,
    pub clock: Arc<dyn Clock>,
    pub id_gen: Arc<dyn IdGenerator>,
}

pub struct AgentClaimInput {
    pub request_id: String,
    pub agent_id: String,
    pub agent_databases: Vec<dbward_domain::entities::DatabaseCapability>,
    pub agent_operations: Vec<Operation>,
}

pub struct AgentClaimOutput {
    pub execution_id: String,
    pub request_id: String,
    pub execution_token: String,
    pub operation: String,
    pub database: String,
    pub environment: String,
    pub detail: String,
    pub statement_timeout_secs: u32,
}

impl AgentClaim {
    pub fn execute(&self, input: AgentClaimInput, user: &AuthUser) -> Result<AgentClaimOutput, AppError> {
        // 1. Authorization (global permission)
        self.authorizer.authorize_global(user, Permission::AgentClaim)
            .map_err(AppError::Forbidden)?;

        // 2. Get request
        let request = self.request_repo.get(&input.request_id)?
            .ok_or_else(|| AppError::NotFound("request not found".into()))?;

        // 3. Status check: must be dispatched → running
        status_machine::transition(request.status, &RequestEvent::Claim)
            .map_err(|e| AppError::Conflict(e.to_string()))?;

        // 4. Capability verification: agent must support (database, environment)
        let has_capability = input.agent_databases.iter().any(|cap| {
            (cap.database.is_wildcard() || cap.database == request.database)
                && (cap.environment.is_wildcard() || cap.environment == request.environment)
        });
        if !has_capability {
            return Err(AppError::Forbidden(crate::error::AuthzError::Forbidden {
                permission: Permission::AgentClaim,
                reason: "agent lacks capability for this database/environment".into(),
            }));
        }

        // 5. Operation capability check
        if !input.agent_operations.is_empty() && !input.agent_operations.contains(&request.operation) {
            return Err(AppError::Forbidden(crate::error::AuthzError::Forbidden {
                permission: Permission::AgentClaim,
                reason: "agent lacks capability for this operation".into(),
            }));
        }

        // 6. Migration exclusion: no concurrent migrate on same (db, env)
        if matches!(request.operation, Operation::MigrateUp | Operation::MigrateDown) {
            if self.agent_repo.has_running_migration(&request.database, &request.environment, &request.id)? {
                return Err(AppError::Conflict("migration already running for this database".into()));
            }
        }

        // 7. Resource-level authorization
        self.authorizer.authorize_scoped(
            user,
            Permission::AgentClaim,
            &request.database,
            &request.environment,
            &ResourceContext::AgentExecution { agent_id: input.agent_id.clone() },
        ).map_err(AppError::Forbidden)?;

        // 8. Get execution policy for statement_timeout
        let exec_policy = self.policy.get_execution_policy(&request.database, &request.environment);

        // 9. Create execution record
        let now = self.clock.now();
        let execution_id = self.id_gen.generate();
        let lease_expires_at = now + chrono::Duration::seconds(300);

        // 10. Sign execution token (SHA-256 for detail_hash)
        let detail_hash = sha256_hex(&request.detail);
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
            agent_id: input.agent_id,
            status: ExecutionStatus::Claimed,
            token: token.clone(),
            lease_expires_at,
            started_at: Some(now),
            finished_at: None,
            error_message: None,
            created_at: now,
        };
        self.agent_repo.create_execution(&execution)?;

        // 11. Mark request as running
        self.request_repo.mark_running(&request.id, now)?;

        Ok(AgentClaimOutput {
            execution_id,
            request_id: request.id,
            execution_token: token,
            operation: request.operation.as_str().to_string(),
            database: request.database.as_str().to_string(),
            environment: request.environment.as_str().to_string(),
            detail: request.detail,
            statement_timeout_secs: exec_policy.statement_timeout_secs,
        })
    }
}

/// Deterministic SHA-256 hash (hex-encoded) for cross-process token verification.
fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}
