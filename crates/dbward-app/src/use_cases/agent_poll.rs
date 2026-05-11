use std::sync::Arc;

use dbward_domain::auth::{AuthUser, Permission};
use dbward_domain::entities::{Agent, DatabaseCapability, Request};
use dbward_domain::values::{DatabaseName, Environment};

use crate::error::AppError;
use crate::ports::*;

pub struct AgentPoll {
    pub authorizer: Arc<dyn Authorizer>,
    pub agent_repo: Arc<dyn AgentRepo>,
    pub clock: Arc<dyn Clock>,
}

pub struct AgentPollInput {
    pub capabilities: Vec<DatabaseCapability>,
}

pub struct AgentPollOutput {
    pub jobs: Vec<PollJob>,
}

pub struct PollJob {
    pub id: String,
    pub requester: String,
    pub operation: dbward_domain::values::Operation,
    pub environment: Environment,
    pub database: DatabaseName,
    pub detail: String,
}

impl AgentPoll {
    pub fn execute(&self, input: AgentPollInput, user: &AuthUser) -> Result<AgentPollOutput, AppError> {
        // 1. Authorization
        self.authorizer.authorize_global(user, Permission::AgentPoll)
            .map_err(AppError::Forbidden)?;

        // 2. Upsert agent (register/update last_seen)
        let now = self.clock.now();
        let agent = Agent {
            id: user.subject_id.clone(),
            token_id: user.token_id.clone().unwrap_or_default(),
            databases: input.capabilities.clone(),
            status: dbward_domain::entities::AgentStatus::Active,
            max_concurrent: 1,
            in_flight: 0,
            last_seen: Some(now),
            created_at: now,
        };
        self.agent_repo.upsert(&agent)?;

        // 3. Find dispatched jobs matching capabilities
        let pairs: Vec<(DatabaseName, Environment)> = input.capabilities.iter()
            .map(|c| (c.database.clone(), c.environment.clone()))
            .collect();
        let jobs = self.agent_repo.find_dispatched_jobs(&pairs)?;

        // 4. Map to output
        let poll_jobs = jobs.into_iter().map(|r| PollJob {
            id: r.id,
            requester: r.requester,
            operation: r.operation,
            environment: r.environment,
            database: r.database,
            detail: r.detail,
        }).collect();

        Ok(AgentPollOutput { jobs: poll_jobs })
    }
}
