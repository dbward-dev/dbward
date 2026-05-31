use std::sync::Arc;

use dbward_domain::auth::Permission;

use crate::error::{AppError, AuthzError};
use crate::ports::*;

// --- DryRunClaim ---

pub struct DryRunClaim {
    pub dry_run_repo: Arc<dyn DryRunRepo>,
    pub agent_repo: Arc<dyn AgentRepo>,
    pub clock: Arc<dyn Clock>,
    pub id_gen: Arc<dyn IdGenerator>,
}

impl DryRunClaim {
    /// Claim a dry-run job for the given agent. Returns the claim token.
    pub fn execute(&self, job_id: &str, agent_id: &str) -> Result<String, AppError> {
        // Scope check: verify job belongs to agent's registered databases
        if let Some(request_id) = self.dry_run_repo.get_request_id(job_id)?
            && let Ok(jobs) = self.dry_run_repo.find_for_request(&request_id)
            && let Some(job) = jobs.iter().find(|j| j.id == job_id)
            && let Some(agent) = self.agent_repo.get(agent_id)?
        {
            let scope_ok = agent.databases.iter().any(|d| {
                d.database.as_str() == job.database_name
                    && d.environment.as_str() == job.environment
            });
            if !scope_ok {
                return Err(AppError::Forbidden(AuthzError::Forbidden {
                    permission: Permission::AgentClaim,
                    reason: "agent not authorized for this job".into(),
                }));
            }
        }

        let claim_token = self.id_gen.generate();
        let now = self.clock.now().to_rfc3339();
        let claimed = self
            .dry_run_repo
            .claim(job_id, agent_id, &claim_token, &now)?;
        if !claimed {
            return Err(AppError::Conflict("already_claimed".into()));
        }
        Ok(claim_token)
    }
}

// --- DryRunSubmitResult ---

pub struct DryRunSubmitResult {
    pub dry_run_repo: Arc<dyn DryRunRepo>,
    pub context_repo: Arc<dyn ContextRepo>,
    pub clock: Arc<dyn Clock>,
}

pub struct DryRunResultInput<'a> {
    pub job_id: &'a str,
    pub agent_id: &'a str,
    pub claim_token: &'a str,
    pub result_json: Option<&'a str>,
    pub error: Option<&'a str>,
}

impl DryRunSubmitResult {
    pub fn execute(&self, input: DryRunResultInput<'_>) -> Result<(), AppError> {
        let now = self.clock.now().to_rfc3339();

        // Complete or fail the job
        let success = if let Some(error) = input.error {
            self.dry_run_repo
                .fail(input.job_id, input.agent_id, input.claim_token, error, &now)?
        } else {
            let result = input.result_json.unwrap_or("{}");
            self.dry_run_repo.complete(
                input.job_id,
                input.agent_id,
                input.claim_token,
                result,
                &now,
            )?
        };
        if !success {
            return Err(AppError::Conflict(
                "claim_token mismatch or job not claimed".into(),
            ));
        }

        // Check if all jobs for this request are done → aggregate EXPLAIN → update context
        if let Some(request_id) = self.dry_run_repo.get_request_id(input.job_id)?
            && let Ok(jobs) = self.dry_run_repo.find_for_request(&request_id)
        {
            let all_done = jobs
                .iter()
                .all(|j| j.status != "pending" && j.status != "claimed");
            if all_done {
                let results: Vec<serde_json::Value> = jobs
                    .iter()
                    .map(|j| {
                        if j.status == "completed" {
                            let plan = j
                                .result_json
                                .as_deref()
                                .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
                                .unwrap_or(serde_json::Value::Null);
                            serde_json::json!({"sql": &j.sql_text, "plan": plan})
                        } else {
                            let hint = j
                                .error_message
                                .as_deref()
                                .filter(|m| {
                                    m.contains("permission denied")
                                        || m.contains("Access denied")
                                })
                                .map(|_| "Grant EXPLAIN privilege to agent DB user");
                            serde_json::json!({"sql": &j.sql_text, "error": &j.error_message, "hint": hint})
                        }
                    })
                    .collect();
                let explain_json = serde_json::to_string(&results).unwrap_or_default();
                let ctx_status = if jobs.iter().all(|j| j.status == "completed") {
                    "ready"
                } else {
                    "partial"
                };
                let now_str = self.clock.now().to_rfc3339();
                if let Err(e) = self.context_repo.update_explain(
                    &request_id,
                    &explain_json,
                    ctx_status,
                    &now_str,
                ) {
                    tracing::warn!(%e, %request_id, "failed to update request context after dry-run");
                }
            }
        }

        Ok(())
    }
}
