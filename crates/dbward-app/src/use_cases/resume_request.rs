use std::sync::Arc;

use dbward_domain::auth::{AuthUser, Permission, ResourceContext};
use dbward_domain::entities::RequestStatus;
use dbward_domain::services::status_machine::{
    self, EventMetadata, RequestTrigger, TransitionContext,
};

use crate::error::AppError;
use crate::ports::*;

pub struct ResumeRequest {
    pub authorizer: Arc<dyn Authorizer>,
    pub policy: Arc<dyn PolicyEvaluator>,
    pub request_reader: Arc<dyn RequestReader>,
    pub request_writer: Arc<dyn RequestWriter>,
    pub result_channel: Arc<dyn ResultChannel>,
    pub event_dispatcher: Arc<dyn EventDispatcher>,
    pub policy_repo: Arc<dyn PolicyRepo>,
    pub clock: Arc<dyn Clock>,
}

pub struct ResumeRequestInput {
    pub request_id: String,
}

#[derive(Debug)]
pub struct ResumeRequestOutput {
    pub id: String,
    pub status: RequestStatus,
}

impl ResumeRequest {
    pub fn execute(
        &self,
        input: ResumeRequestInput,
        user: &AuthUser,
        ctx: &dbward_domain::entities::AuditContext,
    ) -> Result<ResumeRequestOutput, AppError> {
        // 1. Get request
        let request = self
            .request_reader
            .get(&input.request_id)?
            .ok_or_else(|| AppError::NotFound("request not found".into()))?;

        // 2. Authorization: requester or admin (scoped)
        self.authorizer
            .authorize_scoped(
                user,
                Permission::RequestResume,
                &request.database,
                &request.environment,
                &ResourceContext::Request {
                    requester_id: request.requester.clone(),
                },
            )
            .map_err(AppError::Forbidden)?;

        // 3. Status check via status_machine
        let now = self.clock.now();
        let result = status_machine::transition(
            request.status,
            &RequestTrigger::Dispatch,
            TransitionContext {
                request_id: request.id.clone(),
                actor_id: user.subject_id.clone(),
                actor_type: user.subject_type,
                database: request.database.clone(),
                environment: request.environment.clone(),
                operation: request.operation,
                timestamp: now,
                metadata: EventMetadata::Dispatched,
                requester_id: request.requester.clone(),
                audit_context: ctx.clone(),
            },
        )
        .map_err(|e| AppError::Conflict(e.to_string()))?;

        // 4. Approval TTL check (based on resolved_at = when approval was granted)
        if let Some(resolved_at) = request.resolved_at {
            if let Some(wf_json) = &request.workflow_snapshot_json {
                if let Ok(wf) = serde_json::from_str::<dbward_domain::policies::Workflow>(wf_json) {
                    if let Some(ttl) = wf.approval_ttl_secs {
                        let elapsed = (self.clock.now() - resolved_at).num_seconds() as u64;
                        if elapsed > ttl {
                            return Err(AppError::Gone("approval expired".into()));
                        }
                    }
                }
            }
        }

        // 5. Execution count check (applies to all dispatches including initial)
        let exec_policy = self
            .policy
            .get_execution_policy(&request.database, &request.environment);
        let exec_count = self.request_reader.count_executions(&request.id)?;

        if exec_count >= exec_policy.max_executions {
            return Err(AppError::Conflict("max executions reached".into()));
        }

        // 5b. Additional re-dispatch checks (window expiry, retry policy)
        if matches!(
            request.status,
            RequestStatus::Executed | RequestStatus::Failed | RequestStatus::ExecutionLost
        ) {
            if let Some(resolved_at) = request.resolved_at {
                let elapsed = (self.clock.now() - resolved_at).num_seconds() as u64;
                if elapsed > exec_policy.execution_window_secs {
                    return Err(AppError::Gone("execution window expired".into()));
                }
            }

            if !exec_policy.retry_on_failure && request.status == RequestStatus::Failed {
                return Err(AppError::Conflict("retry on failure disabled".into()));
            }
        }

        // 6. Mark dispatched
        let ok = self.request_writer.mark_dispatched(&request.id, now)?;
        if !ok {
            return Err(AppError::Conflict("concurrent status change".into()));
        }

        // Pre-create result slot so subscribers can wait before agent completes
        // M-21: Skip streaming slot if policy says StoreOnly
        let delivery_mode = self
            .policy_repo
            .find_result_policy(&request.database, &request.environment)
            .ok()
            .flatten()
            .map(|p| p.delivery_mode)
            .unwrap_or_default();
        if delivery_mode != dbward_domain::policies::DeliveryMode::StoreOnly {
            self.result_channel.create_slot(&request.id);
        }

        result.commit(&*self.event_dispatcher);

        Ok(ResumeRequestOutput {
            id: request.id,
            status: RequestStatus::Dispatched,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use async_trait::async_trait;
    use chrono::{DateTime, Utc};
    use dbward_domain::auth::SubjectType;
    use dbward_domain::entities::Request;
    use dbward_domain::values::{DatabaseName, Environment, Operation};
    use std::sync::Mutex;

    struct FakePolicy;
    impl PolicyEvaluator for FakePolicy {
        fn evaluate_workflow(
            &self,
            _: &DatabaseName,
            _: &Environment,
            _: Operation,
        ) -> Result<Option<dbward_domain::policies::Workflow>, AppError> {
            Ok(None)
        }
        fn get_execution_policy(
            &self,
            _: &DatabaseName,
            _: &Environment,
        ) -> dbward_domain::policies::ExecutionPolicy {
            Default::default()
        }
    }

    struct FakeResultChannel;
    #[async_trait]
    impl ResultChannel for FakeResultChannel {
        fn create_slot(&self, _: &str) {}
        async fn publish(&self, _: &str, _: dbward_domain::values::ResultSummary) {}
        async fn subscribe(
            &self,
            _: &str,
            _: u64,
        ) -> Result<Option<dbward_domain::values::ResultSummary>, AppError> {
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
            Ok(true)
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
            Ok(true)
        }
        fn find_result_policy(
            &self,
            _: &DatabaseName,
            _: &Environment,
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
            Ok(true)
        }
        fn count_roles(&self) -> Result<u32, AppError> {
            Ok(0)
        }
    }

    struct FakeDispatchReader {
        request: Mutex<Option<Request>>,
    }
    impl RequestReader for FakeDispatchReader {
        fn get(&self, _: &str) -> Result<Option<Request>, AppError> {
            Ok(self.request.lock().unwrap().clone())
        }
        fn list(
            &self,
            _: u32,
            _: u32,
            _: Option<&str>,
            _: Option<&str>,
        ) -> Result<(Vec<Request>, u32), AppError> {
            Ok((vec![], 0))
        }
        fn find_by_idempotency_key(&self, _: &str) -> Result<Option<Request>, AppError> {
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
        ) -> Result<(Vec<Request>, u32), AppError> {
            Ok((vec![], 0))
        }
        fn list_pending_for_user(
            &self,
            _: &str,
            _: &[String],
            _: &[String],
            _: u32,
            _: u32,
        ) -> Result<(Vec<Request>, u32), AppError> {
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
        fn list_results_for_user(
            &self,
            _: &str,
            _: &[String],
            _: &[String],
            _: u32,
        ) -> Result<Vec<StoredResultEntry>, AppError> {
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

    struct FakeDispatchWriter {
        dispatched: Mutex<bool>,
    }
    impl RequestWriter for FakeDispatchWriter {
        fn insert(&self, _: &Request) -> Result<(), AppError> {
            Ok(())
        }
        fn create_and_dispatch(&self, _: &Request) -> Result<(), AppError> {
            Ok(())
        }
        fn mark_approved(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_rejected(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_cancelled(
            &self,
            _: &str,
            _: &str,
            _: Option<&str>,
            _: DateTime<Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_dispatched(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> {
            *self.dispatched.lock().unwrap() = true;
            Ok(true)
        }
        fn mark_running(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_executed(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_failed(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
        fn cancel_all_for_user(
            &self,
            _: &str,
            _: &str,
            _: &str,
            _: DateTime<Utc>,
            _: &dbward_domain::entities::AuditContext,
        ) -> Result<Vec<String>, AppError> {
            Ok(vec![])
        }
        fn mark_approved_from_dispatched(&self, _: &str, _: &str) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_approved_from_dispatched_and_record(
            &self,
            _: &str,
            _: &dbward_domain::entities::AuditEvent,
            _: &str,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
    }

    fn make_request(status: RequestStatus) -> Request {
        Request {
            id: "req-001".into(),
            requester: "alice".into(),
            database: DatabaseName::new("app").unwrap(),
            environment: Environment::new("production").unwrap(),
            operation: Operation::ExecuteDml,
            detail: "UPDATE x SET y=1".into(),
            status,
            emergency: false,
            reason: None,
            idempotency_key: None,
            metadata_json: "{}".into(),
            share_with: vec![],
            no_store: false,
            workflow_snapshot_json: None,
            decision_trace_json: None,
            cancel_reason: None,
            cancelled_by: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            resolved_at: None,
            expires_at: None,
        }
    }

    fn make_uc(reader: Arc<FakeDispatchReader>, writer: Arc<FakeDispatchWriter>) -> ResumeRequest {
        ResumeRequest {
            authorizer: Arc::new(AllowAll),
            policy: Arc::new(FakePolicy),
            request_reader: reader,
            request_writer: writer,
            result_channel: Arc::new(FakeResultChannel),
            event_dispatcher: Arc::new(NoopDispatcher),
            policy_repo: Arc::new(FakePolicyRepo),
            clock: Arc::new(FixedClock::now_utc()),
        }
    }

    #[test]
    fn dispatch_approved_succeeds() {
        let reader = Arc::new(FakeDispatchReader {
            request: Mutex::new(Some(make_request(RequestStatus::Approved))),
        });
        let writer = Arc::new(FakeDispatchWriter {
            dispatched: Mutex::new(false),
        });
        let uc = make_uc(reader, writer.clone());
        let user = AuthUser {
            subject_id: "alice".into(),
            subject_type: SubjectType::User,
            roles: vec![],
            groups: vec![],
            token_id: None,
        };

        let out = uc
            .execute(
                ResumeRequestInput {
                    request_id: "req-001".into(),
                },
                &user,
                &dbward_domain::entities::AuditContext::System,
            )
            .unwrap();
        assert_eq!(out.status, RequestStatus::Dispatched);
        assert!(*writer.dispatched.lock().unwrap());
    }

    #[test]
    fn dispatch_pending_fails() {
        let reader = Arc::new(FakeDispatchReader {
            request: Mutex::new(Some(make_request(RequestStatus::Pending))),
        });
        let writer = Arc::new(FakeDispatchWriter {
            dispatched: Mutex::new(false),
        });
        let uc = make_uc(reader, writer);
        let user = AuthUser {
            subject_id: "alice".into(),
            subject_type: SubjectType::User,
            roles: vec![],
            groups: vec![],
            token_id: None,
        };

        assert!(matches!(
            uc.execute(
                ResumeRequestInput {
                    request_id: "req-001".into()
                },
                &user,
                &dbward_domain::entities::AuditContext::System
            ),
            Err(AppError::Conflict(_))
        ));
    }

    #[test]
    fn dispatch_break_glass_succeeds() {
        let reader = Arc::new(FakeDispatchReader {
            request: Mutex::new(Some(make_request(RequestStatus::BreakGlass))),
        });
        let writer = Arc::new(FakeDispatchWriter {
            dispatched: Mutex::new(false),
        });
        let uc = make_uc(reader, writer);
        let user = AuthUser {
            subject_id: "alice".into(),
            subject_type: SubjectType::User,
            roles: vec![],
            groups: vec![],
            token_id: None,
        };

        let out = uc
            .execute(
                ResumeRequestInput {
                    request_id: "req-001".into(),
                },
                &user,
                &dbward_domain::entities::AuditContext::System,
            )
            .unwrap();
        assert_eq!(out.status, RequestStatus::Dispatched);
    }

    // --- Configurable fakes for boundary tests ---

    struct ConfigurableReader {
        request: Mutex<Option<Request>>,
        exec_count: u32,
    }
    impl RequestReader for ConfigurableReader {
        fn get(&self, _: &str) -> Result<Option<Request>, AppError> {
            Ok(self.request.lock().unwrap().clone())
        }
        fn list(
            &self,
            _: u32,
            _: u32,
            _: Option<&str>,
            _: Option<&str>,
        ) -> Result<(Vec<Request>, u32), AppError> {
            Ok((vec![], 0))
        }
        fn find_by_idempotency_key(&self, _: &str) -> Result<Option<Request>, AppError> {
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
        ) -> Result<(Vec<Request>, u32), AppError> {
            Ok((vec![], 0))
        }
        fn list_pending_for_user(
            &self,
            _: &str,
            _: &[String],
            _: &[String],
            _: u32,
            _: u32,
        ) -> Result<(Vec<Request>, u32), AppError> {
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
            Ok(self.exec_count)
        }
        fn list_results_for_user(
            &self,
            _: &str,
            _: &[String],
            _: &[String],
            _: u32,
        ) -> Result<Vec<StoredResultEntry>, AppError> {
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

    struct ConfigurablePolicy {
        exec_policy: dbward_domain::policies::ExecutionPolicy,
    }
    impl PolicyEvaluator for ConfigurablePolicy {
        fn evaluate_workflow(
            &self,
            _: &DatabaseName,
            _: &Environment,
            _: Operation,
        ) -> Result<Option<dbward_domain::policies::Workflow>, AppError> {
            Ok(None)
        }
        fn get_execution_policy(
            &self,
            _: &DatabaseName,
            _: &Environment,
        ) -> dbward_domain::policies::ExecutionPolicy {
            self.exec_policy.clone()
        }
    }

    fn make_user() -> AuthUser {
        AuthUser {
            subject_id: "alice".into(),
            subject_type: SubjectType::User,
            roles: vec![],
            groups: vec![],
            token_id: None,
        }
    }

    fn exec_input() -> ResumeRequestInput {
        ResumeRequestInput {
            request_id: "req-001".into(),
        }
    }

    #[test]
    fn approval_ttl_exactly_expired_returns_gone() {
        use chrono::Duration;

        let now = Utc::now();
        let resolved_at = now - Duration::seconds(61);

        let wf = dbward_domain::policies::Workflow {
            id: "wf-1".into(),
            database: DatabaseName::wildcard(),
            environment: Environment::wildcard(),
            operations: vec![],
            steps: vec![],
            require_reason: false,
            allow_self_approve: false,
            allow_same_approver_across_steps: false,
            explain: true,
            pending_ttl_secs: None,
            statement_timeout_secs: None,
            approval_ttl_secs: Some(60),
            created_at: None,
            updated_at: None,
        };

        let mut req = make_request(RequestStatus::Approved);
        req.resolved_at = Some(resolved_at);
        req.workflow_snapshot_json = Some(serde_json::to_string(&wf).unwrap());

        let reader = Arc::new(ConfigurableReader {
            request: Mutex::new(Some(req)),
            exec_count: 0,
        });
        let writer = Arc::new(FakeDispatchWriter {
            dispatched: Mutex::new(false),
        });

        let uc = ResumeRequest {
            authorizer: Arc::new(AllowAll),
            policy: Arc::new(FakePolicy),
            request_reader: reader,
            request_writer: writer,
            result_channel: Arc::new(FakeResultChannel),
            event_dispatcher: Arc::new(NoopDispatcher),
            policy_repo: Arc::new(FakePolicyRepo),
            clock: Arc::new(FixedClock(now)),
        };

        let err = uc
            .execute(
                exec_input(),
                &make_user(),
                &dbward_domain::entities::AuditContext::System,
            )
            .unwrap_err();
        assert!(matches!(err, AppError::Gone(_)));
    }

    #[test]
    fn max_executions_boundary_returns_conflict() {
        let reader = Arc::new(ConfigurableReader {
            request: Mutex::new(Some(make_request(RequestStatus::Approved))),
            exec_count: 3,
        });
        let writer = Arc::new(FakeDispatchWriter {
            dispatched: Mutex::new(false),
        });

        let policy = Arc::new(ConfigurablePolicy {
            exec_policy: dbward_domain::policies::ExecutionPolicy {
                max_executions: 3,
                ..Default::default()
            },
        });

        let uc = ResumeRequest {
            authorizer: Arc::new(AllowAll),
            policy,
            request_reader: reader,
            request_writer: writer,
            result_channel: Arc::new(FakeResultChannel),
            event_dispatcher: Arc::new(NoopDispatcher),
            policy_repo: Arc::new(FakePolicyRepo),
            clock: Arc::new(FixedClock::now_utc()),
        };

        let err = uc
            .execute(
                exec_input(),
                &make_user(),
                &dbward_domain::entities::AuditContext::System,
            )
            .unwrap_err();
        assert!(matches!(err, AppError::Conflict(_)));
    }

    #[test]
    fn execution_window_expired_returns_gone() {
        use chrono::Duration;

        let now = Utc::now();
        let resolved_at = now - Duration::seconds(3601);

        let mut req = make_request(RequestStatus::Executed);
        req.resolved_at = Some(resolved_at);

        let reader = Arc::new(ConfigurableReader {
            request: Mutex::new(Some(req)),
            exec_count: 0,
        });
        let writer = Arc::new(FakeDispatchWriter {
            dispatched: Mutex::new(false),
        });

        let policy = Arc::new(ConfigurablePolicy {
            exec_policy: dbward_domain::policies::ExecutionPolicy {
                execution_window_secs: 3600,
                ..Default::default()
            },
        });

        let uc = ResumeRequest {
            authorizer: Arc::new(AllowAll),
            policy,
            request_reader: reader,
            request_writer: writer,
            result_channel: Arc::new(FakeResultChannel),
            event_dispatcher: Arc::new(NoopDispatcher),
            policy_repo: Arc::new(FakePolicyRepo),
            clock: Arc::new(FixedClock(now)),
        };

        let err = uc
            .execute(
                exec_input(),
                &make_user(),
                &dbward_domain::entities::AuditContext::System,
            )
            .unwrap_err();
        assert!(matches!(err, AppError::Gone(_)));
    }

    #[test]
    fn retry_on_failure_disabled_returns_conflict() {
        let mut req = make_request(RequestStatus::Failed);
        req.resolved_at = Some(Utc::now());

        let reader = Arc::new(ConfigurableReader {
            request: Mutex::new(Some(req)),
            exec_count: 0,
        });
        let writer = Arc::new(FakeDispatchWriter {
            dispatched: Mutex::new(false),
        });

        let policy = Arc::new(ConfigurablePolicy {
            exec_policy: dbward_domain::policies::ExecutionPolicy {
                retry_on_failure: false,
                // Large window so window check passes
                execution_window_secs: 86400,
                ..Default::default()
            },
        });

        let uc = ResumeRequest {
            authorizer: Arc::new(AllowAll),
            policy,
            request_reader: reader,
            request_writer: writer,
            result_channel: Arc::new(FakeResultChannel),
            event_dispatcher: Arc::new(NoopDispatcher),
            policy_repo: Arc::new(FakePolicyRepo),
            clock: Arc::new(FixedClock::now_utc()),
        };

        let err = uc
            .execute(
                exec_input(),
                &make_user(),
                &dbward_domain::entities::AuditContext::System,
            )
            .unwrap_err();
        assert!(matches!(err, AppError::Conflict(_)));
    }
}
