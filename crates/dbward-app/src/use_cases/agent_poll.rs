use std::sync::Arc;

use dbward_domain::auth::{AuthUser, Permission};
use dbward_domain::entities::{Agent, AgentStatus, AuditEvent, DatabaseCapability};
use dbward_domain::values::{DatabaseName, Environment, Operation};

use crate::error::AppError;
use crate::ports::*;

pub struct AgentPoll {
    pub authorizer: Arc<dyn Authorizer>,
    pub agent_repo: Arc<dyn AgentRepo>,
    pub audit_logger: Arc<dyn AuditLogger>,
    pub license_checker: Arc<dyn LicenseChecker>,
    pub clock: Arc<dyn Clock>,
}

pub struct AgentPollInput {
    pub capabilities: Vec<DatabaseCapability>,
    pub operations: Vec<Operation>,
    pub limit: Option<u32>,
    pub in_flight: u32,
    pub max_concurrent: u32,
}

pub struct AgentPollOutput {
    pub jobs: Vec<PollJob>,
}

pub struct PollJob {
    pub id: String,
    pub created_by: String,
    pub operation: Operation,
    pub environment: Environment,
    pub database: DatabaseName,
    pub detail: String,
}

impl AgentPoll {
    pub fn execute(
        &self,
        input: AgentPollInput,
        user: &AuthUser,
    ) -> Result<AgentPollOutput, AppError> {
        // 1. Authorization
        self.authorizer
            .authorize_global(user, Permission::AgentPoll)
            .map_err(AppError::Forbidden)?;

        // 2. Check if this is a new agent registration
        let existing = self.agent_repo.get(&user.subject_id)?;
        let is_new = existing.is_none();

        // 2b. Free tier agent limit
        if is_new {
            let agents = self.agent_repo.list()?;
            if agents.len() as u32 >= self.license_checker.max_agents() {
                return Err(AppError::PlanLimit("agent limit reached".into()));
            }
        }

        // 3. Upsert agent (register/update last_seen + status)
        let now = self.clock.now();
        let agent = Agent {
            id: user.subject_id.clone(),
            token_id: user.token_id.clone().unwrap_or_default(),
            databases: input.capabilities.clone(),
            status: AgentStatus::Active,
            max_concurrent: input.max_concurrent,
            in_flight: input.in_flight,
            last_seen: Some(now),
            created_at: now,
            lease_duration_secs: None,
        };
        self.agent_repo.upsert(&agent)?;

        // 3b. Emit audit event for new agent registration
        if is_new {
            let _ = self.audit_logger.record(&AuditEvent::simple(
                "agent_registered",
                "agent",
                &user.subject_id,
                Some(&user.subject_id),
                self.clock.now(),
            ));
        }

        // 4. Find dispatched jobs matching capabilities
        let pairs: Vec<(DatabaseName, Environment)> = input
            .capabilities
            .iter()
            .map(|c| (c.database.clone(), c.environment.clone()))
            .collect();
        let mut jobs = self.agent_repo.find_dispatched_jobs(&pairs)?;

        // 5. Filter by operations (if specified)
        if !input.operations.is_empty() {
            jobs.retain(|r| input.operations.contains(&r.operation));
        }

        // 6. Apply limit
        let limit = input.limit.unwrap_or(10).min(20) as usize;
        jobs.truncate(limit);

        // 7. Map to output
        let poll_jobs = jobs
            .into_iter()
            .map(|r| PollJob {
                id: r.id,
                created_by: r.requester,
                operation: r.operation,
                environment: r.environment,
                database: r.database,
                detail: r.detail,
            })
            .collect();

        Ok(AgentPollOutput { jobs: poll_jobs })
    }
}
