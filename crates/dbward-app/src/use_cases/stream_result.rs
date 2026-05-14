use std::sync::Arc;

use dbward_domain::auth::{AuthUser, Permission, ResourceContext};
use dbward_domain::values::ResultSummary;

use crate::error::AppError;
use crate::ports::*;

pub struct StreamResult {
    pub authorizer: Arc<dyn Authorizer>,
    pub request_repo: Arc<dyn RequestRepo>,
    pub result_channel: Arc<dyn ResultChannel>,
}

pub struct StreamResultInput {
    pub request_id: String,
    pub timeout_secs: Option<u64>,
}

pub struct StreamResultOutput {
    pub data: Option<ResultSummary>,
}

impl StreamResult {
    pub async fn execute(
        &self,
        input: StreamResultInput,
        user: &AuthUser,
    ) -> Result<StreamResultOutput, AppError> {
        let request = self
            .request_repo
            .get(&input.request_id)?
            .ok_or_else(|| AppError::NotFound("request not found".into()))?;

        // Live stream access: only requester + admin + ResultPolicy.access (NOT share_with)
        self.authorizer
            .authorize_scoped(
                user,
                Permission::ResultView,
                &request.database,
                &request.environment,
                &ResourceContext::Result {
                    requester_id: request.requester.clone(),
                    access_selectors: vec![], // share_with excluded from live stream
                },
            )
            .map_err(AppError::Forbidden)?;

        // Terminal state: return stored result if available
        if request.status.is_terminal() {
            let success = matches!(
                request.status,
                dbward_domain::entities::RequestStatus::Executed
            );
            let data = ResultSummary {
                execution_id: String::new(),
                success,
                rows_affected: None,
                truncated: false,
                error_message: if !success {
                    Some(format!("request {}", request.status.as_str()))
                } else {
                    None
                },
                result_data: None,
            };
            return Ok(StreamResultOutput { data: Some(data) });
        }

        let timeout = input.timeout_secs.unwrap_or(300);
        let data = self
            .result_channel
            .subscribe(&input.request_id, timeout)
            .await?;

        Ok(StreamResultOutput { data })
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
    impl RequestRepo for FakeRequestRepo {
        fn get(&self, _: &str) -> Result<Option<DomainRequest>, AppError> {
            Ok(self.request.lock().unwrap().clone())
        }
        fn insert(&self, _: &DomainRequest) -> Result<(), AppError> {
            Ok(())
        }
        fn list(
            &self,
            _: u32,
            _: u32,
            _: Option<&str>,
            _: Option<&str>,
        ) -> Result<(Vec<DomainRequest>, u32), AppError> {
            Ok((vec![], 0))
        }
        fn find_by_idempotency_key(&self, _: &str) -> Result<Option<DomainRequest>, AppError> {
            Ok(None)
        }
        fn list_pending_for_user(
            &self,
            _: &str,
            _: &[String],
            _: &[String],
            _: u32,
            _: u32,
        ) -> Result<(Vec<DomainRequest>, u32), AppError> {
            Ok((vec![], 0))
        }
        fn insert_approval(&self, _: &dbward_domain::entities::Approval) -> Result<(), AppError> {
            Ok(())
        }
        fn get_approvals(
            &self,
            _: &str,
        ) -> Result<Vec<dbward_domain::entities::Approval>, AppError> {
            Ok(vec![])
        }
        fn count_executions(&self, _: &str) -> Result<u32, AppError> {
            Ok(0)
        }
        fn mark_approved(
            &self,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn approve_and_mark_approved(
            &self,
            _: &dbward_domain::entities::Approval,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_rejected(
            &self,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn reject_and_record(
            &self,
            _: &str,
            _: &dbward_domain::entities::Approval,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_cancelled(
            &self,
            _: &str,
            _: &str,
            _: Option<&str>,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_dispatched(
            &self,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn create_and_dispatch(&self, _: &DomainRequest) -> Result<(), AppError> {
            Ok(())
        }
        fn mark_running(
            &self,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_executed(
            &self,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_failed(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
        fn cancel_all_for_user(
            &self,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<u32, AppError> {
            Ok(0)
        }
        fn find_expired_approved(&self, _: &str) -> Result<Vec<String>, AppError> {
            Ok(vec![])
        }
        fn find_expired_pending(&self, _: &str) -> Result<Vec<String>, AppError> {
            Ok(vec![])
        }
        fn find_dispatched_older_than(&self, _: &str) -> Result<Vec<String>, AppError> {
            Ok(vec![])
        }
        fn mark_expired(&self, _: &str, _: &str) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_expired_and_record(
            &self,
            _: &str,
            _: &dbward_domain::entities::AuditEvent,
            _: &str,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_approved_from_dispatched(&self, _: &str, _: &str) -> Result<bool, AppError> {
            Ok(true)
        }
        fn purge_old_requests(&self, _: &str) -> Result<u32, AppError> {
            Ok(0)
        }
        fn count_by_status(&self, _: &str) -> Result<u32, AppError> {
            Ok(0)
        }
        fn wal_checkpoint(&self) -> Result<(), AppError> {
            Ok(())
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
        fn is_pending_approver(
            &self,
            _: &str,
            _: &str,
            _: &[String],
            _: &[String],
        ) -> Result<bool, AppError> {
            Ok(false)
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
            request_repo: Arc::new(FakeRequestRepo::empty()),
            result_channel: Arc::new(FakeResultChannel),
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
            request_repo: Arc::new(FakeRequestRepo::with_status(RequestStatus::Executed)),
            result_channel: Arc::new(FakeResultChannel),
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
        assert!(out.data.is_some());
        assert!(out.data.unwrap().success);
    }

    #[tokio::test]
    async fn pending_state_subscribes_and_returns_none_on_timeout() {
        let uc = StreamResult {
            authorizer: Arc::new(AllowAll),
            request_repo: Arc::new(FakeRequestRepo::with_status(RequestStatus::Pending)),
            result_channel: Arc::new(FakeResultChannel),
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
        assert!(out.data.is_none());
    }
}
