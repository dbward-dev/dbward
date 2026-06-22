use std::sync::Arc;

use sha2::Digest;

use dbward_domain::auth::{AuthUser, Permission, ResourceContext};
use dbward_domain::entities::{
    AuditEvent, ExecutionResult, ExecutionStatus, RequestStatus, ResultAccess, SelectorType,
};
use dbward_domain::services::status_machine::{
    self, EventMetadata, RequestTrigger, TransitionContext,
};
use dbward_domain::values::ResultSummary;

use crate::error::AppError;
use crate::ports::*;

pub struct AgentSubmitResult {
    pub authorizer: Arc<dyn Authorizer>,
    pub agent_repo: Arc<dyn AgentRepo>,
    pub request_reader: Arc<dyn RequestReader>,
    pub result_store: Arc<dyn ResultStore>,
    pub result_channel: Arc<dyn ResultChannel>,
    pub notifier: Arc<dyn Notifier>,
    pub uow: Arc<dyn UnitOfWork>,
    pub clock: Arc<dyn Clock>,
    pub max_persist_bytes: usize,
    pub policy_repo: Arc<dyn PolicyRepo>,
    pub storage_backend: String,
}

pub struct AgentSubmitResultInput {
    pub execution_id: String,
    pub success: bool,
    pub result_data: Option<Vec<u8>>,
    pub error_message: Option<String>,
    pub rows_affected: Option<u64>,
    pub duration_ms: Option<u64>,
}

pub struct AgentSubmitResultOutput {
    pub request_id: String,
    pub status: RequestStatus,
}

impl AgentSubmitResult {
    pub async fn execute(
        &self,
        input: AgentSubmitResultInput,
        user: &AuthUser,
        ctx: &dbward_domain::entities::AuditContext,
    ) -> Result<AgentSubmitResultOutput, AppError> {
        // 1. Authorization (global)
        self.authorizer
            .authorize_global(user, Permission::AgentOperate)
            .map_err(AppError::Forbidden)?;

        // 2. Get execution
        let execution = self
            .agent_repo
            .get_execution(&input.execution_id)?
            .ok_or_else(|| AppError::NotFound("execution not found".into()))?;

        // 3. Resource-level authorization (agent_id match via Authorizer)
        self.authorizer
            .authorize_scoped(
                user,
                Permission::AgentOperate,
                &dbward_domain::values::DatabaseName::wildcard(),
                &dbward_domain::values::Environment::wildcard(),
                &ResourceContext::AgentExecution {
                    agent_id: execution.agent_id.clone(),
                },
            )
            .map_err(AppError::Forbidden)?;

        // 4. Get request (needed for late-completion check below)
        let request = self
            .request_reader
            .get(&execution.request_id)?
            .ok_or_else(|| AppError::Internal("request not found for execution".into()))?;

        // 5. Verify execution is still active (or eligible for late completion)
        let is_late_completion = execution.status == ExecutionStatus::Failed
            && request.status == RequestStatus::ExecutionLost;
        if execution.status != ExecutionStatus::Claimed && !is_late_completion {
            return Err(AppError::Conflict(format!(
                "execution is {:?}, cannot submit result",
                execution.status
            )));
        }

        // 6. Determine final status via status_machine
        // (Cancelled, Complete) → Cancelled is handled by status_machine (ADR-003/004)
        let now = self.clock.now();
        let result = status_machine::transition(
            request.status,
            &RequestTrigger::Complete {
                success: input.success,
            },
            TransitionContext {
                request_id: request.id.clone(),
                actor_id: user.subject_id.clone(),
                actor_type: user.subject_type,
                database: request.database.clone(),
                environment: request.environment.clone(),
                operation: request.operation,
                timestamp: now,
                metadata: EventMetadata::Completed {
                    success: input.success,
                    execution_id: execution.id.clone(),
                },
                requester_id: request.requester.clone(),
                audit_context: ctx.clone(),
            },
        )
        .map_err(|e| AppError::Conflict(e.to_string()))?;

        let new_request_status = result.status();

        // 6b. Look up ResultPolicy for this database/environment
        let policy = self
            .policy_repo
            .find_result_policy(&request.database, &request.environment)?;
        let retention_days = policy.as_ref().map(|p| p.retention_days).unwrap_or(30);
        let delivery_mode = policy
            .as_ref()
            .map(|p| p.delivery_mode)
            .unwrap_or(dbward_domain::policies::DeliveryMode::Both);
        let policy_access: Vec<&dbward_domain::values::Selector> = policy
            .as_ref()
            .map(|p| p.access.iter().collect())
            .unwrap_or_default();

        // delivery_mode only applies to successful results; failures always store
        let should_store = !matches!(delivery_mode, dbward_domain::policies::DeliveryMode::Stream)
            || !input.success;
        let should_stream = !matches!(
            delivery_mode,
            dbward_domain::policies::DeliveryMode::StoreOnly
        ) || !input.success;

        // 7. Store result to external storage (success results, or failure with partial data)
        let mut result_manifest: Option<ExecutionResult> = None;
        let data_len: u64;
        let has_result_data = !request.no_result_store && input.result_data.is_some();
        if (input.success || has_result_data) && !request.no_result_store {
            if let Some(data) = &input.result_data {
                if data.len() > self.max_persist_bytes {
                    return Err(AppError::PayloadTooLarge(format!(
                        "result size {} exceeds limit {}",
                        data.len(),
                        self.max_persist_bytes
                    )));
                }
                let storage_key = format!("{}/{}", execution.request_id, execution.id);
                if should_store {
                    let stored_at = self.clock.now();
                    let expires_at = stored_at + chrono::Duration::days(retention_days as i64);
                    self.result_store
                        .put(
                            &storage_key,
                            data,
                            crate::ports::PutOptions {
                                expires_at: Some(expires_at),
                            },
                        )
                        .await?;
                }
                data_len = data.len() as u64;
                let checksum = hex::encode(sha2::Sha256::digest(data));
                let stored_at = self.clock.now();
                result_manifest = Some(ExecutionResult {
                    id: format!("res-{}", execution.id),
                    request_id: execution.request_id.clone(),
                    execution_id: execution.id.clone(),
                    storage_backend: self.storage_backend.clone(),
                    storage_key: if should_store {
                        storage_key
                    } else {
                        String::new()
                    },
                    content_length: data_len,
                    checksum_sha256: checksum,
                    retention_days,
                    status: dbward_domain::entities::ResultStatus::Stored,
                    truncated: false,
                    truncation_reason: None,
                    stored_at,
                    expires_at: stored_at + chrono::Duration::days(retention_days as i64),
                });
            }
        } else if !input.success {
            // Store failure info
            let truncated_err = truncate_utf8(
                input.error_message.as_deref().unwrap_or("unknown error"),
                4096,
            );
            let err_json = serde_json::json!({
                "success": false,
                "error": truncated_err,
            });
            let storage_key = format!("{}/{}", execution.request_id, execution.id);
            let err_bytes = err_json.to_string().into_bytes();
            let stored_at = self.clock.now();
            let expires_at = stored_at + chrono::Duration::days(retention_days as i64);
            self.result_store
                .put(
                    &storage_key,
                    &err_bytes,
                    crate::ports::PutOptions {
                        expires_at: Some(expires_at),
                    },
                )
                .await?;
            data_len = err_bytes.len() as u64;
            let checksum = hex::encode(sha2::Sha256::digest(&err_bytes));
            result_manifest = Some(ExecutionResult {
                id: format!("res-{}", execution.id),
                request_id: execution.request_id.clone(),
                execution_id: execution.id.clone(),
                storage_backend: self.storage_backend.clone(),
                storage_key,
                content_length: data_len,
                checksum_sha256: checksum,
                retention_days,
                status: dbward_domain::entities::ResultStatus::Stored,
                truncated: false,
                truncation_reason: None,
                stored_at,
                expires_at: stored_at + chrono::Duration::days(retention_days as i64),
            });
        }

        // Build share_with ResultAccess records (UNION of request.share_with + policy.access)
        let share_with_records: Vec<ResultAccess> = if let Some(ref rm) = result_manifest {
            let mut records: Vec<ResultAccess> = request
                .share_with
                .iter()
                .enumerate()
                .map(|(i, sel)| {
                    let (st, sv) = parse_selector_for_access(sel);
                    ResultAccess {
                        id: format!("{}-ra-{}", rm.id, i),
                        result_id: rm.id.clone(),
                        selector_type: st,
                        selector_value: sv,
                    }
                })
                .collect();
            let base = records.len();
            for (i, sel) in policy_access.iter().enumerate() {
                let sel_str = sel.to_string();
                let (st, sv) = parse_selector_for_access(&sel_str);
                records.push(ResultAccess {
                    id: format!("{}-pa-{}", rm.id, base + i),
                    result_id: rm.id.clone(),
                    selector_type: st,
                    selector_value: sv,
                });
            }
            records
        } else {
            vec![]
        };

        // 8. Atomically update execution + request status + audit + result manifest
        let now = self.clock.now();
        let mut audit_event = AuditEvent::simple(
            if input.success {
                "execution.completed"
            } else {
                "execution.failed"
            },
            "execution",
            &user.subject_id,
            Some(&execution.id),
            now,
            ctx,
        );
        audit_event.database_name = Some(request.database.to_string());
        audit_event.environment = Some(request.environment.to_string());
        audit_event.operation = Some(request.operation.as_str().to_string());

        // A-3/A-4: Enrich metadata_json with rows_affected and duration_ms
        // rows_affected is only meaningful for successful executions
        let effective_rows = if input.success {
            input.rows_affected
        } else {
            None
        };
        if effective_rows.is_some() || input.duration_ms.is_some() {
            let mut meta = serde_json::from_str::<serde_json::Value>(&audit_event.metadata_json)
                .inspect_err(|e| {
                    tracing::warn!(
                        error = %e,
                        execution_id = %input.execution_id,
                        "corrupt metadata_json in audit event, resetting to empty"
                    );
                })
                .ok()
                .filter(|v| v.is_object())
                .unwrap_or_else(|| serde_json::json!({}));
            if let Some(rows) = effective_rows {
                meta["rows_affected"] = rows.into();
            }
            if let Some(dur) = input.duration_ms {
                meta["duration_ms"] = dur.into();
            }
            audit_event.metadata_json = meta.to_string();
        }

        // Atomic: execution update + request update + result manifest + audit (fail-closed)
        let exec_id = execution.id.clone();
        let req_id = execution.request_id.clone();
        let success = input.success;
        let rm_clone = result_manifest.clone();
        let sw_clone = share_with_records.clone();
        let outcome = match crate::ports::uow_execute::<crate::ports::CompletionOutcome>(
            &*self.uow,
            move |tx| {
                use crate::ports::CompletionOutcome;
                let exec_updated = tx.mark_completed(&exec_id, success, now)?;
                if !exec_updated {
                    // Execution already completed/cancelled by concurrent request.
                    // Return Conflict to prevent compensation delete of winner's storage.
                    return Err(AppError::Conflict("execution already completed".into()));
                }
                let updated = tx.mark_executed(&req_id, success, now)?;
                if !updated {
                    // Request was cancelled/already completed — still store result
                }
                if let Some(ref rm) = rm_clone {
                    tx.insert_result(rm)?;
                    tx.insert_result_access(&sw_clone)?;
                }
                tx.record(&audit_event)?;
                Ok(if updated {
                    CompletionOutcome::Normal
                } else {
                    CompletionOutcome::RequestCancelled
                })
            },
        ) {
            Ok(v) => v,
            Err(AppError::Conflict(_)) => {
                // Concurrent completion won — do NOT delete their stored result
                return Err(AppError::Conflict("execution already completed".into()));
            }
            Err(e) => {
                // Compensate: delete orphaned storage object
                if let Some(ref rm) = result_manifest {
                    if let Err(del_err) = self.result_store.delete(&rm.storage_key).await {
                        tracing::error!(key = %rm.storage_key, error = %del_err, "compensation delete failed for stored result");
                    }
                } else if !input.success {
                    let storage_key = format!("{}/{}", execution.request_id, execution.id);
                    if let Err(del_err) = self.result_store.delete(&storage_key).await {
                        tracing::error!(key = %storage_key, error = %del_err, "compensation delete failed for error result");
                    }
                }
                return Err(e);
            }
        };

        use crate::ports::CompletionOutcome;
        match outcome {
            CompletionOutcome::Normal => {
                // 9. Publish result to long-poll channel
                if should_stream {
                    let summary = ResultSummary {
                        execution_id: execution.id.clone(),
                        success: input.success,
                        rows_affected: if input.success {
                            input.rows_affected
                        } else {
                            None
                        },
                        truncated: false,
                        error_message: input.error_message.clone(),
                        result_data: if input.success {
                            input
                                .result_data
                                .as_ref()
                                .map(|d| String::from_utf8_lossy(d).into_owned())
                        } else {
                            None
                        },
                    };
                    self.result_channel
                        .publish(&execution.request_id, summary)
                        .await;
                }
                // Post-commit notification (audit already written by complete_execution)
                let event = result.into_event();
                self.notifier
                    .dispatch(crate::services::audit_event_builder::build_webhook_event(
                        &event,
                    ));
                Ok(AgentSubmitResultOutput {
                    request_id: execution.request_id,
                    status: new_request_status,
                })
            }
            CompletionOutcome::RequestCancelled => {
                // Result stored but don't publish or emit transition event
                Ok(AgentSubmitResultOutput {
                    request_id: execution.request_id,
                    status: RequestStatus::Cancelled,
                })
            }
        }
    }
}

fn truncate_utf8(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn parse_selector_for_access(sel: &str) -> (SelectorType, String) {
    if let Some(val) = sel.strip_prefix("role:") {
        (SelectorType::Role, val.to_string())
    } else if let Some(val) = sel.strip_prefix("group:") {
        (SelectorType::Group, val.to_string())
    } else if let Some(val) = sel.strip_prefix("user:") {
        (SelectorType::User, val.to_string())
    } else {
        (SelectorType::User, sel.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AuthzError;
    use async_trait::async_trait;
    use chrono::{DateTime, Utc};
    use dbward_domain::auth::{Permission as P, ResolvedRole, ResourceContext, SubjectType};
    use dbward_domain::entities::{
        Agent, AuditEvent, Execution, ExecutionStatus, Request as DomainRequest, RequestStatus,
    };
    use dbward_domain::values::{DatabaseName, Environment, Operation, ResultSummary};
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

    struct FakeClock;
    impl Clock for FakeClock {
        fn now(&self) -> DateTime<Utc> {
            Utc::now()
        }
    }

    struct NoopNotifier;
    impl crate::ports::Notifier for NoopNotifier {
        fn dispatch(&self, _: crate::ports::WebhookEvent) {}
    }

    struct FakeAgentRepo {
        execution: Mutex<Option<Execution>>,
    }
    impl AgentRepo for FakeAgentRepo {
        fn get_execution(&self, _: &str) -> Result<Option<Execution>, AppError> {
            Ok(self.execution.lock().unwrap().clone())
        }
        fn upsert(&self, _: &Agent) -> Result<(), AppError> {
            Ok(())
        }
        fn get(&self, _: &str) -> Result<Option<Agent>, AppError> {
            Ok(None)
        }
        fn list(&self) -> Result<Vec<Agent>, AppError> {
            Ok(vec![])
        }
        fn create_execution(&self, _: &Execution) -> Result<(), AppError> {
            Ok(())
        }
        fn update_execution_status(&self, _: &str, _: ExecutionStatus) -> Result<(), AppError> {
            Ok(())
        }
        fn extend_lease(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
        fn find_dispatched_jobs(
            &self,
            _: &[(DatabaseName, Environment)],
        ) -> Result<Vec<DomainRequest>, AppError> {
            Ok(vec![])
        }
        fn has_running_migration(
            &self,
            _: &DatabaseName,
            _: &Environment,
            _: &str,
        ) -> Result<bool, AppError> {
            Ok(false)
        }
        fn find_executions_for_request(&self, _: &str) -> Result<Vec<Execution>, AppError> {
            Ok(vec![])
        }
        fn claim_and_mark_running(
            &self,
            _: &Execution,
            _: &str,
            _: DateTime<Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn complete_execution(
            &self,
            _: &str,
            _: &str,
            _: bool,
            _: DateTime<Utc>,
            _: &AuditEvent,
            _: Option<&ExecutionResult>,
            _: &[ResultAccess],
        ) -> Result<crate::ports::CompletionOutcome, AppError> {
            Ok(crate::ports::CompletionOutcome::Normal)
        }
        fn find_expired_leases(&self, _: &str) -> Result<Vec<(String, String)>, AppError> {
            Ok(vec![])
        }
        fn mark_execution_lost(&self, _: &str, _: &str, _: &str) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_execution_lost_and_record(
            &self,
            _: &str,
            _: &str,
            _: &AuditEvent,
            _: &str,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn find_expired_results(&self, _: &str) -> Result<Vec<(String, String)>, AppError> {
            Ok(vec![])
        }
        fn delete_result(&self, _: &str) -> Result<(), AppError> {
            Ok(())
        }
    }

    struct FakeRequestRepo {
        request: Mutex<Option<DomainRequest>>,
    }
    impl RequestReader for FakeRequestRepo {
        fn get(&self, _: &str) -> Result<Option<DomainRequest>, AppError> {
            Ok(self.request.lock().unwrap().clone())
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
        fn find_by_idempotency_key(
            &self,
            _: &str,
            _: &str,
        ) -> Result<Option<DomainRequest>, AppError> {
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
        ) -> Result<(Vec<DomainRequest>, u32), AppError> {
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

    struct FakeResultStore {
        stored: Mutex<Vec<String>>,
    }
    #[async_trait]
    impl ResultStore for FakeResultStore {
        async fn put(
            &self,
            key: &str,
            _: &[u8],
            _: crate::ports::PutOptions,
        ) -> Result<(), AppError> {
            self.stored.lock().unwrap().push(key.into());
            Ok(())
        }
        async fn get_stream(&self, _: &str) -> Result<crate::ports::ResultStream, AppError> {
            Ok(crate::ports::ResultStream {
                content_length: Some(0),
                stream: Box::pin(EmptyStream),
            })
        }
        async fn delete(&self, _: &str) -> Result<(), AppError> {
            Ok(())
        }
        async fn health_check(&self) -> Result<(), AppError> {
            Ok(())
        }
    }

    struct EmptyStream;
    impl futures_core::Stream for EmptyStream {
        type Item = Result<bytes::Bytes, AppError>;
        fn poll_next(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            std::task::Poll::Ready(None)
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
            Ok(false)
        }
        fn count_roles(&self) -> Result<u32, AppError> {
            Ok(0)
        }
    }

    fn agent_user() -> AuthUser {
        AuthUser {
            subject_id: "agent-1".into(),
            subject_type: SubjectType::Agent,
            roles: vec![ResolvedRole {
                name: "agent-default".into(),
                permissions: [P::AgentOperate].into_iter().collect(),
                databases: vec![],
                environments: vec![],
            }],
            groups: vec![],
            token_id: None,
        }
    }

    fn make_execution(status: ExecutionStatus) -> Execution {
        Execution {
            id: "exec-1".into(),
            request_id: "req-1".into(),
            agent_id: "agent-1".into(),
            status,
            token: "tok".into(),
            lease_expires_at: Utc::now() + chrono::Duration::minutes(5),
            started_at: Some(Utc::now()),
            finished_at: None,
            error_message: None,
            created_at: Utc::now(),
        }
    }

    fn make_request(status: RequestStatus) -> DomainRequest {
        DomainRequest {
            id: "req-1".into(),
            requester: "alice".into(),
            database: DatabaseName::new("app").unwrap(),
            environment: Environment::new("production").unwrap(),
            operation: Operation::ExecuteDml,
            detail: "UPDATE t SET x=1".into(),
            status,
            emergency: false,
            reason: None,
            idempotency_key: None,
            idempotency_fingerprint: None,
            metadata_json: "{}".into(),
            share_with: vec![],
            no_result_store: false,
            workflow_snapshot_json: None,
            decision_trace_json: None,
            execution_plan_json: None,
            cancel_reason: None,
            cancelled_by: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            resolved_at: None,
            expires_at: None,
        }
    }

    fn make_uc(exec_status: ExecutionStatus, req_status: RequestStatus) -> AgentSubmitResult {
        AgentSubmitResult {
            authorizer: Arc::new(AllowAll),
            agent_repo: Arc::new(FakeAgentRepo {
                execution: Mutex::new(Some(make_execution(exec_status))),
            }),
            request_reader: Arc::new(FakeRequestRepo {
                request: Mutex::new(Some(make_request(req_status))),
            }),
            result_store: Arc::new(FakeResultStore {
                stored: Mutex::new(vec![]),
            }),
            result_channel: Arc::new(FakeResultChannel),
            notifier: Arc::new(NoopNotifier),
            uow: Arc::new(crate::test_support::NoopUnitOfWork),
            clock: Arc::new(FakeClock),
            max_persist_bytes: 10 * 1024 * 1024,
            policy_repo: Arc::new(FakePolicyRepo),
            storage_backend: "local".into(),
        }
    }

    #[tokio::test]
    async fn execution_not_found_returns_error() {
        let uc = AgentSubmitResult {
            authorizer: Arc::new(AllowAll),
            agent_repo: Arc::new(FakeAgentRepo {
                execution: Mutex::new(None),
            }),
            request_reader: Arc::new(FakeRequestRepo {
                request: Mutex::new(None),
            }),
            result_store: Arc::new(FakeResultStore {
                stored: Mutex::new(vec![]),
            }),
            result_channel: Arc::new(FakeResultChannel),
            notifier: Arc::new(NoopNotifier),
            uow: Arc::new(crate::test_support::NoopUnitOfWork),
            clock: Arc::new(FakeClock),
            max_persist_bytes: 10 * 1024 * 1024,
            policy_repo: Arc::new(FakePolicyRepo),
            storage_backend: "local".into(),
        };
        let input = AgentSubmitResultInput {
            execution_id: "nope".into(),
            success: true,
            result_data: None,
            error_message: None,
            rows_affected: None,
            duration_ms: None,
        };
        assert!(matches!(
            uc.execute(
                input,
                &agent_user(),
                &dbward_domain::entities::AuditContext::System
            )
            .await,
            Err(AppError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn not_claimed_returns_conflict() {
        let uc = make_uc(ExecutionStatus::Completed, RequestStatus::Running);
        let input = AgentSubmitResultInput {
            execution_id: "exec-1".into(),
            success: true,
            result_data: None,
            error_message: None,
            rows_affected: None,
            duration_ms: None,
        };
        assert!(matches!(
            uc.execute(
                input,
                &agent_user(),
                &dbward_domain::entities::AuditContext::System
            )
            .await,
            Err(AppError::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn success_submit_returns_executed() {
        let uc = make_uc(ExecutionStatus::Claimed, RequestStatus::Running);
        let input = AgentSubmitResultInput {
            execution_id: "exec-1".into(),
            success: true,
            result_data: Some(b"rows".to_vec()),
            error_message: None,
            rows_affected: None,
            duration_ms: None,
        };
        let out = uc
            .execute(
                input,
                &agent_user(),
                &dbward_domain::entities::AuditContext::System,
            )
            .await
            .unwrap();
        assert_eq!(out.status, RequestStatus::Executed);
    }

    #[tokio::test]
    async fn failure_submit_returns_failed() {
        let uc = make_uc(ExecutionStatus::Claimed, RequestStatus::Running);
        let input = AgentSubmitResultInput {
            execution_id: "exec-1".into(),
            success: false,
            result_data: None,
            error_message: Some("timeout".into()),
            rows_affected: None,
            duration_ms: None,
        };
        let out = uc
            .execute(
                input,
                &agent_user(),
                &dbward_domain::entities::AuditContext::System,
            )
            .await
            .unwrap();
        assert_eq!(out.status, RequestStatus::Failed);
    }

    #[tokio::test]
    async fn cancelled_request_stays_cancelled() {
        let uc = make_uc(ExecutionStatus::Claimed, RequestStatus::Cancelled);
        let input = AgentSubmitResultInput {
            execution_id: "exec-1".into(),
            success: true,
            result_data: None,
            error_message: None,
            rows_affected: None,
            duration_ms: None,
        };
        let out = uc
            .execute(
                input,
                &agent_user(),
                &dbward_domain::entities::AuditContext::System,
            )
            .await
            .unwrap();
        assert_eq!(out.status, RequestStatus::Cancelled);
    }

    #[tokio::test]
    async fn payload_too_large_rejected() {
        let mut uc = make_uc(ExecutionStatus::Claimed, RequestStatus::Running);
        uc.max_persist_bytes = 10;
        let input = AgentSubmitResultInput {
            execution_id: "exec-1".into(),
            success: true,
            result_data: Some(vec![0u8; 11]),
            error_message: None,
            rows_affected: None,
            duration_ms: None,
        };
        assert!(matches!(
            uc.execute(
                input,
                &agent_user(),
                &dbward_domain::entities::AuditContext::System
            )
            .await,
            Err(AppError::PayloadTooLarge(_))
        ));
    }

    #[tokio::test]
    async fn late_completion_execution_lost_accepts_result() {
        let uc = make_uc(ExecutionStatus::Failed, RequestStatus::ExecutionLost);
        let input = AgentSubmitResultInput {
            execution_id: "exec-1".into(),
            success: true,
            result_data: Some(b"ok".to_vec()),
            error_message: None,
            rows_affected: None,
            duration_ms: Some(100),
        };
        let out = uc
            .execute(
                input,
                &agent_user(),
                &dbward_domain::entities::AuditContext::System,
            )
            .await
            .unwrap();
        assert_eq!(out.status, RequestStatus::Executed);
    }

    #[tokio::test]
    async fn late_completion_rejects_if_not_execution_lost() {
        let uc = make_uc(ExecutionStatus::Failed, RequestStatus::Failed);
        let input = AgentSubmitResultInput {
            execution_id: "exec-1".into(),
            success: true,
            result_data: None,
            error_message: None,
            rows_affected: None,
            duration_ms: None,
        };
        assert!(matches!(
            uc.execute(
                input,
                &agent_user(),
                &dbward_domain::entities::AuditContext::System,
            )
            .await,
            Err(AppError::Conflict(_))
        ));
    }
}
