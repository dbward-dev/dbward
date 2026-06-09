use std::sync::Arc;

use dbward_domain::auth::{AuthUser, Permission, ResourceContext};
use dbward_domain::entities::RequestStatus;
use dbward_domain::services::status_machine::{
    self, EventMetadata, RequestTrigger, TransitionContext,
};

use crate::error::AppError;
use crate::ports::*;

pub struct CancelRequest {
    pub authorizer: Arc<dyn Authorizer>,
    pub request_reader: Arc<dyn RequestReader>,
    pub request_writer: Arc<dyn RequestWriter>,
    pub event_dispatcher: Arc<dyn EventDispatcher>,
    pub clock: Arc<dyn Clock>,
}

pub struct CancelRequestInput {
    pub request_id: String,
    pub reason: Option<String>,
}

pub struct CancelRequestOutput {
    pub id: String,
    pub status: RequestStatus,
}

impl CancelRequest {
    pub fn execute(
        &self,
        input: CancelRequestInput,
        user: &AuthUser,
        ctx: &dbward_domain::entities::AuditContext,
    ) -> Result<CancelRequestOutput, AppError> {
        if let Some(ref r) = input.reason
            && r.len() > 1024
        {
            return Err(AppError::Validation(
                "reason too long (max 1024 bytes)".into(),
            ));
        }

        let request = self
            .request_reader
            .get(&input.request_id)?
            .ok_or_else(|| AppError::NotFound("request not found".into()))?;

        self.authorizer
            .authorize_scoped(
                user,
                Permission::RequestCancel,
                &request.database,
                &request.environment,
                &ResourceContext::Request {
                    requester_id: request.requester.clone(),
                },
            )
            .map_err(AppError::Forbidden)?;

        let now = self.clock.now();
        let result = status_machine::transition(
            request.status,
            &RequestTrigger::Cancel,
            TransitionContext {
                request_id: request.id.clone(),
                actor_id: user.subject_id.clone(),
                actor_type: user.subject_type,
                database: request.database.clone(),
                environment: request.environment.clone(),
                operation: request.operation,
                timestamp: now,
                metadata: EventMetadata::Cancelled {
                    reason: input.reason.clone(),
                },
                requester_id: request.requester.clone(),
                audit_context: ctx.clone(),
            },
        )
        .map_err(|e| AppError::Conflict(e.to_string()))?;

        let ok = self.request_writer.mark_cancelled(
            &request.id,
            &user.subject_id,
            input.reason.as_deref(),
            now,
        )?;
        if !ok {
            return Err(AppError::Conflict("concurrent status change".into()));
        }

        result.commit(&*self.event_dispatcher);

        Ok(CancelRequestOutput {
            id: request.id,
            status: RequestStatus::Cancelled,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use chrono::Utc;
    use dbward_domain::auth::SubjectType;
    use dbward_domain::entities::Request;
    use dbward_domain::values::{DatabaseName, Environment, Operation};

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
            execution_plan_json: None,
            cancel_reason: None,
            cancelled_by: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            resolved_at: None,
            expires_at: None,
        }
    }

    #[test]
    fn cancel_pending_succeeds() {
        let reader = Arc::new(FakeRequestReader::with_request(make_request(
            RequestStatus::Pending,
        )));
        let writer = Arc::new(FakeRequestWriter::new());
        let uc = CancelRequest {
            authorizer: Arc::new(AllowAll),
            request_reader: reader,
            request_writer: writer.clone(),
            event_dispatcher: Arc::new(NoopDispatcher),
            clock: Arc::new(FixedClock::now_utc()),
        };
        let user = AuthUser {
            subject_id: "alice".into(),
            subject_type: SubjectType::User,
            roles: vec![],
            groups: vec![],
            token_id: None,
        };
        let out = uc
            .execute(
                CancelRequestInput {
                    request_id: "req-001".into(),
                    reason: Some("changed mind".into()),
                },
                &user,
                &dbward_domain::entities::AuditContext::System,
            )
            .unwrap();
        assert_eq!(out.status, RequestStatus::Cancelled);
        assert!(*writer.written.lock().unwrap());
    }

    #[test]
    fn cancel_rejected_fails() {
        let reader = Arc::new(FakeRequestReader::with_request(make_request(
            RequestStatus::Rejected,
        )));
        let writer = Arc::new(FakeRequestWriter::new());
        let uc = CancelRequest {
            authorizer: Arc::new(AllowAll),
            request_reader: reader,
            request_writer: writer,
            event_dispatcher: Arc::new(NoopDispatcher),
            clock: Arc::new(FixedClock::now_utc()),
        };
        let user = AuthUser {
            subject_id: "alice".into(),
            subject_type: SubjectType::User,
            roles: vec![],
            groups: vec![],
            token_id: None,
        };
        assert!(matches!(
            uc.execute(
                CancelRequestInput {
                    request_id: "req-001".into(),
                    reason: None
                },
                &user,
                &dbward_domain::entities::AuditContext::System,
            ),
            Err(AppError::Conflict(_))
        ));
    }

    #[test]
    fn cancel_denied_by_authorizer() {
        let reader = Arc::new(FakeRequestReader::with_request(make_request(
            RequestStatus::Pending,
        )));
        let writer = Arc::new(FakeRequestWriter::new());
        let uc = CancelRequest {
            authorizer: Arc::new(DenyAll),
            request_reader: reader,
            request_writer: writer,
            event_dispatcher: Arc::new(NoopDispatcher),
            clock: Arc::new(FixedClock::now_utc()),
        };
        let user = AuthUser {
            subject_id: "bob".into(),
            subject_type: SubjectType::User,
            roles: vec![],
            groups: vec![],
            token_id: None,
        };
        assert!(matches!(
            uc.execute(
                CancelRequestInput {
                    request_id: "req-001".into(),
                    reason: None
                },
                &user,
                &dbward_domain::entities::AuditContext::System,
            ),
            Err(AppError::Forbidden(_))
        ));
    }
}
