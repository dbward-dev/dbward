use std::sync::Arc;

use dbward_domain::auth::{AuthUser, Permission, ResourceContext};
use dbward_domain::entities::{Request, RequestStatus};

use crate::error::AppError;
use crate::ports::*;

pub struct GetRequest {
    pub request_repo: Arc<dyn RequestRepo>,
    pub authorizer: Arc<dyn Authorizer>,
}

#[derive(Debug)]
pub struct GetRequestOutput {
    pub request: Request,
    pub detail: String,
    pub is_approver_view: bool,
}

impl GetRequest {
    pub fn execute(&self, request_id: &str, user: &AuthUser) -> Result<GetRequestOutput, AppError> {
        let req = self
            .request_repo
            .get(request_id)?
            .ok_or_else(|| AppError::NotFound("request not found".into()))?;

        // Authorize BEFORE any waiting
        let scoped_ok = self.authorizer.authorize_scoped(
            user,
            Permission::RequestView,
            &req.database,
            &req.environment,
            &ResourceContext::Request {
                requester_id: req.requester.clone(),
            },
        );

        let is_approver_view = if let Err(authz_err) = scoped_ok {
            let approver = req.status == RequestStatus::Pending
                && self
                    .authorizer
                    .authorize_scoped(
                        user,
                        Permission::RequestApprove,
                        &req.database,
                        &req.environment,
                        &ResourceContext::Global,
                    )
                    .is_ok();
            if !approver {
                return Err(AppError::Forbidden(authz_err));
            }
            true
        } else {
            false
        };

        let detail = if is_approver_view && user.subject_id != req.requester {
            "[redacted - approve to view]".to_string()
        } else {
            req.detail.clone()
        };

        Ok(GetRequestOutput {
            request: req,
            detail,
            is_approver_view,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dbward_domain::auth::{AuthUser, SubjectType};
    use dbward_domain::entities::Request;
    use dbward_domain::values::{DatabaseName, Environment, Operation};
    use std::sync::Mutex;

    use crate::error::AuthzError;

    // --- Minimal test doubles ---

    struct MockRequestRepo {
        request: Mutex<Option<Request>>,
    }

    impl RequestRepo for MockRequestRepo {
        fn get(&self, _id: &str) -> Result<Option<Request>, AppError> {
            Ok(self.request.lock().unwrap().clone())
        }
        fn insert(&self, _: &Request) -> Result<(), AppError> {
            unimplemented!()
        }
        fn list(
            &self,
            _: u32,
            _: u32,
            _: Option<&str>,
            _: Option<&str>,
        ) -> Result<(Vec<Request>, u32), AppError> {
            unimplemented!()
        }
        fn find_by_idempotency_key(&self, _: &str) -> Result<Option<Request>, AppError> {
            unimplemented!()
        }
        fn list_pending_for_user(
            &self,
            _: &str,
            _: &[String],
            _: &[String],
            _: u32,
            _: u32,
        ) -> Result<(Vec<Request>, u32), AppError> {
            unimplemented!()
        }
        fn insert_approval(&self, _: &dbward_domain::entities::Approval) -> Result<(), AppError> {
            unimplemented!()
        }
        fn get_approvals(
            &self,
            _: &str,
        ) -> Result<Vec<dbward_domain::entities::Approval>, AppError> {
            unimplemented!()
        }
        fn count_executions(&self, _: &str) -> Result<u32, AppError> {
            unimplemented!()
        }
        fn mark_approved(
            &self,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            unimplemented!()
        }
        fn approve_and_mark_approved(
            &self,
            _: &dbward_domain::entities::Approval,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            unimplemented!()
        }
        fn mark_rejected(
            &self,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            unimplemented!()
        }
        fn reject_and_record(
            &self,
            _: &str,
            _: &dbward_domain::entities::Approval,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            unimplemented!()
        }
        fn mark_cancelled(
            &self,
            _: &str,
            _: &str,
            _: Option<&str>,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            unimplemented!()
        }
        fn mark_dispatched(
            &self,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            unimplemented!()
        }
        fn create_and_dispatch(&self, _: &Request) -> Result<(), AppError> {
            unimplemented!()
        }
        fn mark_running(
            &self,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            unimplemented!()
        }
        fn mark_executed(
            &self,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            unimplemented!()
        }
        fn mark_failed(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> {
            unimplemented!()
        }
        fn cancel_all_for_user(
            &self,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<u32, AppError> {
            unimplemented!()
        }
        fn find_expired_approved(&self, _: &str) -> Result<Vec<String>, AppError> {
            unimplemented!()
        }
        fn find_expired_pending(&self, _: &str) -> Result<Vec<String>, AppError> {
            unimplemented!()
        }
        fn find_dispatched_older_than(&self, _: &str) -> Result<Vec<String>, AppError> {
            unimplemented!()
        }
        fn mark_expired(&self, _: &str, _: &str) -> Result<bool, AppError> {
            unimplemented!()
        }
        fn mark_expired_and_record(
            &self,
            _: &str,
            _: &dbward_domain::entities::AuditEvent,
            _: &str,
        ) -> Result<bool, AppError> {
            unimplemented!()
        }
        fn mark_approved_from_dispatched(&self, _: &str, _: &str) -> Result<bool, AppError> {
            unimplemented!()
        }
        fn purge_old_requests(&self, _: &str) -> Result<u32, AppError> {
            unimplemented!()
        }
        fn count_by_status(&self, _: &str) -> Result<u32, AppError> {
            unimplemented!()
        }
        fn wal_checkpoint(&self) -> Result<(), AppError> {
            unimplemented!()
        }
        fn list_results_for_user(
            &self,
            _: &str,
            _: &[String],
            _: &[String],
            _: u32,
        ) -> Result<Vec<StoredResultEntry>, AppError> {
            unimplemented!()
        }
    }

    struct AllowAuthorizer;
    struct DenyAuthorizer;

    impl Authorizer for AllowAuthorizer {
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
        fn authorize_global(&self, _: &AuthUser, _: Permission) -> Result<(), AuthzError> {
            Ok(())
        }
    }

    impl Authorizer for DenyAuthorizer {
        fn authorize_scoped(
            &self,
            _: &AuthUser,
            _: Permission,
            _: &DatabaseName,
            _: &Environment,
            _: &ResourceContext,
        ) -> Result<(), AuthzError> {
            Err(AuthzError::Forbidden {
                permission: Permission::RequestView,
                reason: "denied".into(),
            })
        }
        fn authorize_global(&self, _: &AuthUser, _: Permission) -> Result<(), AuthzError> {
            Err(AuthzError::Forbidden {
                permission: Permission::RequestView,
                reason: "denied".into(),
            })
        }
    }

    fn test_user(id: &str) -> AuthUser {
        AuthUser {
            subject_id: id.to_string(),
            subject_type: SubjectType::User,
            groups: vec![],
            roles: vec![],
            token_id: None,
        }
    }

    fn test_request(requester: &str, status: RequestStatus) -> Request {
        Request {
            id: "req-1".into(),
            requester: requester.into(),
            database: DatabaseName::new("db1").unwrap(),
            environment: Environment::new("prod").unwrap(),
            operation: Operation::ExecuteSelect,
            detail: "SELECT 1".into(),
            status,
            emergency: false,
            reason: None,
            idempotency_key: None,
            metadata_json: "{}".into(),
            share_with: vec![],
            no_store: false,
            workflow_snapshot_json: None,
            cancel_reason: None,
            cancelled_by: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            resolved_at: None,
            expires_at: None,
        }
    }

    #[test]
    fn not_found() {
        let uc = GetRequest {
            request_repo: Arc::new(MockRequestRepo {
                request: Mutex::new(None),
            }),
            authorizer: Arc::new(AllowAuthorizer),
        };
        let err = uc.execute("req-1", &test_user("u1")).unwrap_err();
        assert!(matches!(err, AppError::NotFound(_)));
    }

    #[test]
    fn owner_sees_full_detail() {
        let uc = GetRequest {
            request_repo: Arc::new(MockRequestRepo {
                request: Mutex::new(Some(test_request("u1", RequestStatus::Pending))),
            }),
            authorizer: Arc::new(AllowAuthorizer),
        };
        let out = uc.execute("req-1", &test_user("u1")).unwrap();
        assert_eq!(out.detail, "SELECT 1");
        assert!(!out.is_approver_view);
    }

    #[test]
    fn forbidden_when_no_permission() {
        let uc = GetRequest {
            request_repo: Arc::new(MockRequestRepo {
                request: Mutex::new(Some(test_request("u1", RequestStatus::Pending))),
            }),
            authorizer: Arc::new(DenyAuthorizer),
        };
        let err = uc.execute("req-1", &test_user("u2")).unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)));
    }
}
