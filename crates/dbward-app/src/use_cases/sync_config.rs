use std::sync::Arc;

use dbward_domain::entities::{Webhook, WebhookFormat, WebhookStatus};
use dbward_domain::policies::{ApproverGroup, Workflow, WorkflowStep, WorkflowStepMode};
use dbward_domain::values::{DatabaseName, Environment, Operation, Selector};

use crate::error::AppError;
use crate::ports::{Clock, IdGenerator, PolicyRepo, WebhookRepo};

pub struct SyncConfig {
    pub policy_repo: Arc<dyn PolicyRepo>,
    pub webhook_repo: Arc<dyn WebhookRepo>,
    pub clock: Arc<dyn Clock>,
    pub id_gen: Arc<dyn IdGenerator>,
}

// --- Workflow input DTOs ---

pub struct WorkflowInput {
    pub database: String,
    pub environment: String,
    pub operations: Vec<String>,
    pub steps: Vec<WorkflowStepInput>,
    pub skip_approval_for: Vec<String>,
    pub require_reason: bool,
    pub allow_self_approve: bool,
    pub allow_same_approver_across_steps: bool,
    pub pending_ttl_secs: Option<u64>,
    pub statement_timeout_secs: Option<u64>,
}

pub struct WorkflowStepInput {
    pub mode: String,
    pub approvers: Vec<ApproverInput>,
}

pub struct ApproverInput {
    pub selector_type: String, // "role", "group", "user"
    pub value: String,
    pub min: u32,
}

// --- Webhook input DTO ---

pub struct WebhookInput {
    pub url: String,
    pub events: Vec<String>,
    pub format: String,
    pub secret: Option<String>,
}

impl SyncConfig {
    pub fn sync_workflows(&self, workflows: Vec<WorkflowInput>) -> Result<(), AppError> {
        // Clean all config-sourced workflows first
        for i in 0..100 {
            let _ = self.policy_repo.delete_workflow(&format!("config-wf-{i}"));
        }

        for (i, wf) in workflows.iter().enumerate() {
            let id = format!("config-wf-{i}");
            let db = if wf.database == "*" {
                DatabaseName::wildcard()
            } else {
                DatabaseName::new(&wf.database)
                    .map_err(|e| AppError::Validation(format!("workflow db: {e}")))?
            };
            let env = if wf.environment == "*" {
                Environment::wildcard()
            } else {
                Environment::new(&wf.environment)
                    .map_err(|e| AppError::Validation(format!("workflow env: {e}")))?
            };

            let mut operations: Vec<Operation> = Vec::new();
            for op_str in &wf.operations {
                let op = op_str
                    .parse::<Operation>()
                    .map_err(|e| AppError::Validation(format!("workflow {id}: {e}")))?;
                operations.push(op);
            }

            let steps: Vec<WorkflowStep> = wf
                .steps
                .iter()
                .map(|s| {
                    let mode = if s.mode == "any" {
                        WorkflowStepMode::Any
                    } else {
                        WorkflowStepMode::All
                    };
                    let approvers = s
                        .approvers
                        .iter()
                        .filter_map(|a| {
                            let selector = match a.selector_type.as_str() {
                                "role" => Some(Selector::Role(a.value.clone())),
                                "group" => Some(Selector::Group(a.value.clone())),
                                "user" => Some(Selector::User(a.value.clone())),
                                _ => None,
                            };
                            selector.map(|s| ApproverGroup {
                                selector: s,
                                min: a.min,
                            })
                        })
                        .collect();
                    WorkflowStep { approvers, mode }
                })
                .collect();

            let workflow = Workflow {
                id,
                database: db,
                environment: env,
                operations,
                steps,
                skip_approval_for: wf
                    .skip_approval_for
                    .iter()
                    .filter_map(|s| Selector::parse(s).ok())
                    .collect(),
                require_reason: wf.require_reason,
                allow_self_approve: wf.allow_self_approve,
                allow_same_approver_across_steps: wf.allow_same_approver_across_steps,
                pending_ttl_secs: wf.pending_ttl_secs,
                statement_timeout_secs: wf.statement_timeout_secs,
                approval_ttl_secs: None,
                created_at: None,
                updated_at: None,
            };
            self.policy_repo.create_workflow(&workflow)?;
        }
        Ok(())
    }

    pub fn sync_webhooks(&self, webhooks: Vec<WebhookInput>) -> Result<(), AppError> {
        // Delete all config-sourced webhooks
        for i in 0..100 {
            let _ = self.webhook_repo.delete(&format!("config-wh-{i}"));
        }

        let now = self.clock.now();
        for (i, wh) in webhooks.iter().enumerate() {
            let format = match wh.format.as_str() {
                "slack" => WebhookFormat::Slack,
                _ => WebhookFormat::Generic,
            };
            let webhook = Webhook {
                id: format!("config-wh-{i}"),
                url: wh.url.clone(),
                events: wh.events.clone(),
                format,
                secret: wh.secret.clone(),
                status: WebhookStatus::Active,
                created_at: Some(now),
                updated_at: Some(now),
            };
            self.webhook_repo.create(&webhook)?;
        }
        Ok(())
    }
}
