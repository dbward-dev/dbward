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

            let mut steps: Vec<WorkflowStep> = Vec::new();
            for s in &wf.steps {
                let mode = match s.mode.as_str() {
                    "any" => WorkflowStepMode::Any,
                    "all" => WorkflowStepMode::All,
                    other => {
                        return Err(AppError::Validation(format!(
                            "workflow step: unknown mode '{other}' (expected 'any' or 'all')"
                        )));
                    }
                };
                let mut approvers = Vec::new();
                for a in &s.approvers {
                    let selector = match a.selector_type.as_str() {
                        "role" => Selector::Role(a.value.clone()),
                        "group" => Selector::Group(a.value.clone()),
                        "user" => Selector::User(a.value.clone()),
                        other => {
                            return Err(AppError::Validation(format!(
                                "workflow step: unknown selector_type '{other}'"
                            )));
                        }
                    };
                    approvers.push(ApproverGroup {
                        selector,
                        min: a.min,
                    });
                }
                steps.push(WorkflowStep { approvers, mode });
            }

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
                "generic" => WebhookFormat::Generic,
                other => {
                    return Err(AppError::Validation(format!(
                        "webhook: unknown format '{other}'"
                    )));
                }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AppError;
    use crate::ports::{PolicyRepo, WebhookRepo};
    use crate::test_support::{FixedClock, FixedIdGen};
    use dbward_domain::entities::Webhook;
    use dbward_domain::policies::{
        ExecutionPolicy, NotificationPolicy, ResultPolicy, Workflow,
    };
    use dbward_domain::values::{DatabaseName, Environment};

    // --- Minimal fakes ---

    struct FakePolicyRepo;
    impl PolicyRepo for FakePolicyRepo {
        fn create_workflow(&self, _: &Workflow) -> Result<(), AppError> {
            Ok(())
        }
        fn get_workflow(&self, _: &str) -> Result<Option<Workflow>, AppError> {
            Ok(None)
        }
        fn list_workflows(&self) -> Result<Vec<Workflow>, AppError> {
            Ok(vec![])
        }
        fn delete_workflow(&self, _: &str) -> Result<bool, AppError> {
            Ok(false)
        }
        fn count_workflows(&self) -> Result<u32, AppError> {
            Ok(0)
        }
        fn create_execution_policy(&self, _: &ExecutionPolicy) -> Result<(), AppError> {
            Ok(())
        }
        fn get_execution_policy(&self, _: &str) -> Result<Option<ExecutionPolicy>, AppError> {
            Ok(None)
        }
        fn list_execution_policies(&self) -> Result<Vec<ExecutionPolicy>, AppError> {
            Ok(vec![])
        }
        fn delete_execution_policy(&self, _: &str) -> Result<bool, AppError> {
            Ok(false)
        }
        fn find_result_policy(
            &self,
            _: &DatabaseName,
            _: &Environment,
        ) -> Result<Option<ResultPolicy>, AppError> {
            Ok(None)
        }
        fn create_result_policy(&self, _: &ResultPolicy) -> Result<(), AppError> {
            Ok(())
        }
        fn get_result_policy(&self, _: &str) -> Result<Option<ResultPolicy>, AppError> {
            Ok(None)
        }
        fn list_result_policies(&self) -> Result<Vec<ResultPolicy>, AppError> {
            Ok(vec![])
        }
        fn update_result_policy(&self, _: &ResultPolicy) -> Result<bool, AppError> {
            Ok(false)
        }
        fn delete_result_policy(&self, _: &str) -> Result<bool, AppError> {
            Ok(false)
        }
        fn create_notification_policy(&self, _: &NotificationPolicy) -> Result<(), AppError> {
            Ok(())
        }
        fn get_notification_policy(
            &self,
            _: &str,
        ) -> Result<Option<NotificationPolicy>, AppError> {
            Ok(None)
        }
        fn list_notification_policies(&self) -> Result<Vec<NotificationPolicy>, AppError> {
            Ok(vec![])
        }
        fn update_notification_policy(&self, _: &NotificationPolicy) -> Result<bool, AppError> {
            Ok(false)
        }
        fn delete_notification_policy(&self, _: &str) -> Result<bool, AppError> {
            Ok(false)
        }
        fn create_role(&self, _: &dbward_domain::auth::RoleDefinition) -> Result<(), AppError> {
            Ok(())
        }
        fn list_roles(&self) -> Result<Vec<dbward_domain::auth::RoleDefinition>, AppError> {
            Ok(vec![])
        }
        fn get_roles_by_names(
            &self,
            _: &[String],
        ) -> Result<Vec<dbward_domain::auth::RoleDefinition>, AppError> {
            Ok(vec![])
        }
        fn delete_role(&self, _: &str) -> Result<bool, AppError> {
            Ok(false)
        }
        fn count_roles(&self) -> Result<u32, AppError> {
            Ok(0)
        }
    }

    struct FakeWebhookRepo;
    impl WebhookRepo for FakeWebhookRepo {
        fn create(&self, _: &Webhook) -> Result<(), AppError> {
            Ok(())
        }
        fn get(&self, _: &str) -> Result<Option<Webhook>, AppError> {
            Ok(None)
        }
        fn list(&self) -> Result<Vec<Webhook>, AppError> {
            Ok(vec![])
        }
        fn update(&self, _: &Webhook) -> Result<(), AppError> {
            Ok(())
        }
        fn delete(&self, _: &str) -> Result<(), AppError> {
            Ok(())
        }
    }

    fn make_sync() -> SyncConfig {
        SyncConfig {
            policy_repo: Arc::new(FakePolicyRepo),
            webhook_repo: Arc::new(FakeWebhookRepo),
            clock: Arc::new(FixedClock::now_utc()),
            id_gen: Arc::new(FixedIdGen::new()),
        }
    }

    fn valid_workflow_input() -> WorkflowInput {
        WorkflowInput {
            database: "primary".into(),
            environment: "production".into(),
            operations: vec!["execute_select".into()],
            steps: vec![WorkflowStepInput {
                mode: "any".into(),
                approvers: vec![ApproverInput {
                    selector_type: "role".into(),
                    value: "admin".into(),
                    min: 1,
                }],
            }],
            skip_approval_for: vec![],
            require_reason: false,
            allow_self_approve: false,
            allow_same_approver_across_steps: false,
            pending_ttl_secs: None,
            statement_timeout_secs: None,
        }
    }

    #[test]
    fn sync_workflows_valid_conversion() {
        let sync = make_sync();
        let result = sync.sync_workflows(vec![valid_workflow_input()]);
        assert!(result.is_ok());
    }

    #[test]
    fn sync_workflows_invalid_mode_returns_err() {
        let sync = make_sync();
        let mut wf = valid_workflow_input();
        wf.steps[0].mode = "invalid".into();
        let err = sync.sync_workflows(vec![wf]).unwrap_err();
        match err {
            AppError::Validation(msg) => assert!(msg.contains("unknown mode 'invalid'")),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn sync_workflows_invalid_selector_type_returns_err() {
        let sync = make_sync();
        let mut wf = valid_workflow_input();
        wf.steps[0].approvers[0].selector_type = "invalid".into();
        let err = sync.sync_workflows(vec![wf]).unwrap_err();
        match err {
            AppError::Validation(msg) => assert!(msg.contains("unknown selector_type 'invalid'")),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn sync_workflows_invalid_format_returns_err() {
        let sync = make_sync();
        let wh = WebhookInput {
            url: "https://example.com".into(),
            events: vec!["request_created".into()],
            format: "invalid".into(),
            secret: None,
        };
        let err = sync.sync_webhooks(vec![wh]).unwrap_err();
        match err {
            AppError::Validation(msg) => assert!(msg.contains("unknown format 'invalid'")),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn sync_workflows_invalid_operation_returns_err() {
        let sync = make_sync();
        let mut wf = valid_workflow_input();
        wf.operations = vec!["invalid_op".into()];
        let err = sync.sync_workflows(vec![wf]).unwrap_err();
        match err {
            AppError::Validation(msg) => assert!(msg.contains("invalid_op")),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn sync_workflows_wildcard_db_env() {
        let sync = make_sync();
        let mut wf = valid_workflow_input();
        wf.database = "*".into();
        wf.environment = "*".into();
        let result = sync.sync_workflows(vec![wf]);
        assert!(result.is_ok());
    }
}
