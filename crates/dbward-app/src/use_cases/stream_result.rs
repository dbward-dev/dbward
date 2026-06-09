use std::sync::Arc;

use dbward_domain::auth::{AuthUser, Permission, ResourceContext};
use dbward_domain::values::ResultSummary;

use crate::error::AppError;
use crate::ports::*;

pub struct StreamResult {
    pub authorizer: Arc<dyn Authorizer>,
    pub request_reader: Arc<dyn RequestReader>,
    pub result_channel: Arc<dyn ResultChannel>,
    pub policy_repo: Arc<dyn PolicyRepo>,
}

pub struct StreamResultInput {
    pub request_id: String,
    pub timeout_secs: Option<u64>,
}

pub enum StreamResultData {
    /// Relay から受け取った完全な結果
    Result(ResultSummary),
    /// リクエストが Executed/Failed だが relay にデータなし
    TerminalPlaceholder { success: bool },
    /// タイムアウト（relay subscribe 時間切れ）
    Timeout,
}

pub struct StreamResultOutput {
    pub data: StreamResultData,
}

impl StreamResult {
    pub async fn execute(
        &self,
        input: StreamResultInput,
        user: &AuthUser,
    ) -> Result<StreamResultOutput, AppError> {
        let request = self
            .request_reader
            .get(&input.request_id)?
            .ok_or_else(|| AppError::NotFound("request not found".into()))?;

        // Live stream access: only requester + admin + ResultPolicy.access (NOT share_with)
        let policy_access: Vec<String> = self
            .policy_repo
            .find_result_policy(&request.database, &request.environment)
            .ok()
            .flatten()
            .map(|p| p.access.iter().map(|s| s.to_string()).collect())
            .unwrap_or_default();
        self.authorizer
            .authorize_scoped(
                user,
                Permission::ResultView,
                &request.database,
                &request.environment,
                &ResourceContext::Result {
                    requester_id: request.requester.clone(),
                    access_selectors: policy_access,
                },
            )
            .map_err(AppError::Forbidden)?;

        // Terminal state: signal handler to fetch from storage
        if request.status.is_terminal() {
            use dbward_domain::entities::RequestStatus;
            match request.status {
                RequestStatus::Executed | RequestStatus::Failed => {
                    let success = request.status == RequestStatus::Executed;
                    return Ok(StreamResultOutput {
                        data: StreamResultData::TerminalPlaceholder { success },
                    });
                }
                _ => {
                    // Rejected/Cancelled/Expired — no result exists, return status summary
                    let data = ResultSummary {
                        execution_id: String::new(),
                        success: false,
                        rows_affected: None,
                        truncated: false,
                        error_message: Some(format!("request {}", request.status.as_str())),
                        result_data: None,
                    };
                    return Ok(StreamResultOutput {
                        data: StreamResultData::Result(data),
                    });
                }
            }
        }

        let timeout = input.timeout_secs.unwrap_or(300);
        let data = self
            .result_channel
            .subscribe(&input.request_id, timeout)
            .await?;

        Ok(StreamResultOutput {
            data: match data {
                Some(summary) => StreamResultData::Result(summary),
                None => StreamResultData::Timeout,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AuthzError;
    use async_trait::async_trait;
    use dbward_domain::auth::{ResourceContext, SubjectType};
    use dbward_domain::entities::{Request as DomainRequest, RequestStatus};
    use dbward_domain::values::{DatabaseName, Environment, Operation};
    use std::sync::Mutex;

    struct AllowAll;
    impl Authorizer for AllowAll {
        fn authorize_global(&self, _: &AuthUser, _: Permission) -> Result<(), AuthzError> {
            Ok(())
        }
        fn authorize_scoped(
            &self,
            _: &AuthUser,
            _: Permission,
            _: &DatabaseName,
            _: &Environment,
            _: &ResourceContext,
        ) -> Result<(), AuthzError> {
            Ok(())
        }
    }

    struct FakeRequestRepo {
        request: Mutex<Option<DomainRequest>>,
    }
    impl FakeRequestRepo {
        fn with_status(status: RequestStatus) -> Self {
            Self {
                request: Mutex::new(Some(DomainRequest {
                    id: "req-1".into(),
                    requester: "alice".into(),
                    database: DatabaseName::new("app").unwrap(),
                    environment: Environment::new("production").unwrap(),
                    operation: Operation::ExecuteDml,
                    status,
                    detail: "UPDATE t SET x=1".into(),
                    reason: None,
                    idempotency_key: None,
                    emergency: false,
                    workflow_snapshot_json: None,
                    decision_trace_json: None,
                    execution_plan_json: None,
                    metadata_json: "{}".into(),
                    no_store: false,
                    cancel_reason: None,
                    cancelled_by: None,
                    expires_at: None,
                    share_with: vec![],
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                    resolved_at: None,
                })),
            }
        }
        fn empty() -> Self {
            Self {
                request: Mutex::new(None),
            }
        }
    }
    impl RequestReader for FakeRequestRepo {
        fn get(&self, _: &str) -> Result<Option<dbward_domain::entities::Request>, AppError> {
            Ok(self.request.lock().unwrap().clone())
        }
        fn list(
            &self,
            _: u32,
            _: u32,
            _: Option<&str>,
            _: Option<&str>,
        ) -> Result<(Vec<dbward_domain::entities::Request>, u32), AppError> {
            Ok((vec![], 0))
        }
        fn find_by_idempotency_key(
            &self,
            _: &str,
        ) -> Result<Option<dbward_domain::entities::Request>, AppError> {
            Ok(None)
        }
        fn list_visible_to_user(
            &self,
            _: &str,
            _: &[String],
            _: &[String],
            _: Option<&str>,
            _: u32,
            _: u32,
        ) -> Result<(Vec<dbward_domain::entities::Request>, u32), AppError> {
            Ok((vec![], 0))
        }
        fn list_pending_for_user(
            &self,
            _: &str,
            _: &[String],
            _: &[String],
            _: u32,
            _: u32,
        ) -> Result<(Vec<dbward_domain::entities::Request>, u32), AppError> {
            Ok((vec![], 0))
        }
        fn is_pending_approver(
            &self,
            _: &str,
            _: &str,
            _: &[String],
            _: &[String],
        ) -> Result<bool, AppError> {
            Ok(false)
        }
        fn count_executions(&self, _: &str) -> Result<u32, AppError> {
            Ok(0)
        }
        fn count_completed_executions(&self, _: &str) -> Result<u32, AppError> {
            Ok(0)
        }
        fn find_stored_execution_ids(&self, _: &str) -> Result<Vec<String>, AppError> {
            Ok(vec![])
        }
        fn list_results_for_user(
            &self,
            _: &str,
            _: &[String],
            _: &[String],
            _: u32,
        ) -> Result<Vec<crate::ports::repos::StoredResultEntry>, AppError> {
            Ok(vec![])
        }
        fn count_by_status(&self, _: &str) -> Result<u32, AppError> {
            Ok(0)
        }
        fn get_pending_approvers_for_requests(
            &self,
            _: &[&str],
        ) -> Result<std::collections::HashMap<String, (u32, Vec<String>)>, AppError> {
            Ok(std::collections::HashMap::new())
        }
    }

    struct FakeResultChannel;
    #[async_trait]
    impl ResultChannel for FakeResultChannel {
        fn create_slot(&self, _: &str) {}
        async fn publish(&self, _: &str, _: ResultSummary) {}
        async fn subscribe(&self, _: &str, _: u64) -> Result<Option<ResultSummary>, AppError> {
            Ok(None)
        }
        async fn notify_all(&self) {}
    }

    struct FakePolicyRepo;
    impl PolicyRepo for FakePolicyRepo {
        fn create_workflow(&self, _: &dbward_domain::policies::Workflow) -> Result<(), AppError> {
            Ok(())
        }
        fn get_workflow(
            &self,
            _: &str,
        ) -> Result<Option<dbward_domain::policies::Workflow>, AppError> {
            Ok(None)
        }
        fn list_workflows(&self) -> Result<Vec<dbward_domain::policies::Workflow>, AppError> {
            Ok(vec![])
        }
        fn delete_workflow(&self, _: &str) -> Result<bool, AppError> {
            Ok(false)
        }
        fn count_workflows(&self) -> Result<u32, AppError> {
            Ok(0)
        }
        fn create_execution_policy(
            &self,
            _: &dbward_domain::policies::ExecutionPolicy,
        ) -> Result<(), AppError> {
            Ok(())
        }
        fn get_execution_policy(
            &self,
            _: &str,
        ) -> Result<Option<dbward_domain::policies::ExecutionPolicy>, AppError> {
            Ok(None)
        }
        fn list_execution_policies(
            &self,
        ) -> Result<Vec<dbward_domain::policies::ExecutionPolicy>, AppError> {
            Ok(vec![])
        }
        fn delete_execution_policy(&self, _: &str) -> Result<bool, AppError> {
            Ok(false)
        }
        fn find_result_policy(
            &self,
            _: &dbward_domain::values::DatabaseName,
            _: &dbward_domain::values::Environment,
        ) -> Result<Option<dbward_domain::policies::ResultPolicy>, AppError> {
            Ok(None)
        }
        fn create_result_policy(
            &self,
            _: &dbward_domain::policies::ResultPolicy,
        ) -> Result<(), AppError> {
            Ok(())
        }
        fn get_result_policy(
            &self,
            _: &str,
        ) -> Result<Option<dbward_domain::policies::ResultPolicy>, AppError> {
            Ok(None)
        }
        fn list_result_policies(
            &self,
        ) -> Result<Vec<dbward_domain::policies::ResultPolicy>, AppError> {
            Ok(vec![])
        }
        fn update_result_policy(
            &self,
            _: &dbward_domain::policies::ResultPolicy,
        ) -> Result<bool, AppError> {
            Ok(false)
        }
        fn delete_result_policy(&self, _: &str) -> Result<bool, AppError> {
            Ok(false)
        }
        fn create_notification_policy(
            &self,
            _: &dbward_domain::policies::NotificationPolicy,
        ) -> Result<(), AppError> {
            Ok(())
        }
        fn get_notification_policy(
            &self,
            _: &str,
        ) -> Result<Option<dbward_domain::policies::NotificationPolicy>, AppError> {
            Ok(None)
        }
        fn list_notification_policies(
            &self,
        ) -> Result<Vec<dbward_domain::policies::NotificationPolicy>, AppError> {
            Ok(vec![])
        }
        fn update_notification_policy(
            &self,
            _: &dbward_domain::policies::NotificationPolicy,
        ) -> Result<bool, AppError> {
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

    fn user() -> AuthUser {
        AuthUser {
            subject_id: "alice".into(),
            subject_type: SubjectType::User,
            roles: vec![],
            groups: vec![],
            token_id: None,
        }
    }

    #[tokio::test]
    async fn not_found_returns_error() {
        let uc = StreamResult {
            authorizer: Arc::new(AllowAll),
            request_reader: Arc::new(FakeRequestRepo::empty()),
            result_channel: Arc::new(FakeResultChannel),
            policy_repo: Arc::new(FakePolicyRepo),
        };
        let result = uc
            .execute(
                StreamResultInput {
                    request_id: "nope".into(),
                    timeout_secs: None,
                },
                &user(),
            )
            .await;
        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    #[tokio::test]
    async fn terminal_state_returns_immediately() {
        let uc = StreamResult {
            authorizer: Arc::new(AllowAll),
            request_reader: Arc::new(FakeRequestRepo::with_status(RequestStatus::Executed)),
            result_channel: Arc::new(FakeResultChannel),
            policy_repo: Arc::new(FakePolicyRepo),
        };
        let out = uc
            .execute(
                StreamResultInput {
                    request_id: "req-1".into(),
                    timeout_secs: None,
                },
                &user(),
            )
            .await
            .unwrap();
        assert!(matches!(
            out.data,
            StreamResultData::TerminalPlaceholder { success: true }
        ));
    }

    #[tokio::test]
    async fn pending_state_subscribes_and_returns_none_on_timeout() {
        let uc = StreamResult {
            authorizer: Arc::new(AllowAll),
            request_reader: Arc::new(FakeRequestRepo::with_status(RequestStatus::Pending)),
            result_channel: Arc::new(FakeResultChannel),
            policy_repo: Arc::new(FakePolicyRepo),
        };
        let out = uc
            .execute(
                StreamResultInput {
                    request_id: "req-1".into(),
                    timeout_secs: Some(1),
                },
                &user(),
            )
            .await
            .unwrap();
        assert!(matches!(out.data, StreamResultData::Timeout));
    }

    #[tokio::test]
    async fn failed_terminal_returns_placeholder_with_success_false() {
        let uc = StreamResult {
            authorizer: Arc::new(AllowAll),
            request_reader: Arc::new(FakeRequestRepo::with_status(RequestStatus::Failed)),
            result_channel: Arc::new(FakeResultChannel),
            policy_repo: Arc::new(FakePolicyRepo),
        };
        let out = uc
            .execute(
                StreamResultInput {
                    request_id: "req-1".into(),
                    timeout_secs: Some(1),
                },
                &user(),
            )
            .await
            .unwrap();
        assert!(matches!(
            out.data,
            StreamResultData::TerminalPlaceholder { success: false }
        ));
    }

    #[tokio::test]
    async fn rejected_terminal_returns_result_not_placeholder() {
        let uc = StreamResult {
            authorizer: Arc::new(AllowAll),
            request_reader: Arc::new(FakeRequestRepo::with_status(RequestStatus::Rejected)),
            result_channel: Arc::new(FakeResultChannel),
            policy_repo: Arc::new(FakePolicyRepo),
        };
        let out = uc
            .execute(
                StreamResultInput {
                    request_id: "req-1".into(),
                    timeout_secs: Some(1),
                },
                &user(),
            )
            .await
            .unwrap();
        assert!(matches!(out.data, StreamResultData::Result(_)));
    }
}
