use std::sync::Arc;

use dbward_domain::auth::{AuthUser, Permission, ResourceContext};
use dbward_domain::entities::{Request, RequestStatus};
use dbward_domain::policies::workflow::Workflow;
use dbward_domain::services::approval_progress::{build_progress, ApprovalProgress};

use crate::error::AppError;
use crate::ports::*;

pub struct GetRequest {
    pub request_reader: Arc<dyn RequestReader>,
    pub approval_repo: Arc<dyn ApprovalRepo>,
    pub authorizer: Arc<dyn Authorizer>,
}

#[derive(Debug)]
pub struct GetRequestOutput {
    pub request: Request,
    pub detail: String,
    pub is_approver_view: bool,
    pub approval_progress: Option<ApprovalProgress>,
}

impl GetRequest {
    pub fn execute(&self, request_id: &str, user: &AuthUser) -> Result<GetRequestOutput, AppError> {
        let req = self
            .request_reader
            .get(request_id)?
            .ok_or_else(|| AppError::NotFound("request not found".into()))?;

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
            let role_names: Vec<String> = user.roles.iter().map(|r| r.name.clone()).collect();
            let is_approver = req.status == RequestStatus::Pending
                && self.request_reader.is_pending_approver(
                    &req.id,
                    &user.subject_id,
                    &user.groups,
                    &role_names,
                )?;
            if !is_approver {
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

        // Build approval progress from workflow snapshot + approvals
        let approval_progress = req
            .workflow_snapshot_json
            .as_deref()
            .and_then(|json| serde_json::from_str::<Workflow>(json).ok())
            .and_then(|wf| {
                self.approval_repo
                    .get_approvals(&req.id)
                    .ok()
                    .map(|approvals| build_progress(&wf.steps, &approvals))
            });

        Ok(GetRequestOutput {
            request: req,
            detail,
            is_approver_view,
            approval_progress,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::FakeApprovalRepo;
    use dbward_domain::auth::{AuthUser, SubjectType};
    use dbward_domain::entities::Request;
    use dbward_domain::values::{DatabaseName, Environment, Operation};
    use std::sync::Mutex;

    use crate::error::AuthzError;

    struct MockReader {
        request: Mutex<Option<Request>>,
        is_approver: bool,
    }
    impl RequestReader for MockReader {
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
            Ok(self.is_approver)
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
            request_reader: Arc::new(MockReader {
                request: Mutex::new(None),
                is_approver: false,
            }),
            approval_repo: Arc::new(FakeApprovalRepo::new()),
            authorizer: Arc::new(AllowAuthorizer),
        };
        assert!(matches!(
            uc.execute("req-1", &test_user("u1")).unwrap_err(),
            AppError::NotFound(_)
        ));
    }

    #[test]
    fn owner_sees_full_detail() {
        let uc = GetRequest {
            request_reader: Arc::new(MockReader {
                request: Mutex::new(Some(test_request("u1", RequestStatus::Pending))),
                is_approver: false,
            }),
            approval_repo: Arc::new(FakeApprovalRepo::new()),
            authorizer: Arc::new(AllowAuthorizer),
        };
        let out = uc.execute("req-1", &test_user("u1")).unwrap();
        assert_eq!(out.detail, "SELECT 1");
        assert!(!out.is_approver_view);
    }

    #[test]
    fn forbidden_when_no_permission() {
        let uc = GetRequest {
            request_reader: Arc::new(MockReader {
                request: Mutex::new(Some(test_request("u1", RequestStatus::Pending))),
                is_approver: false,
            }),
            approval_repo: Arc::new(FakeApprovalRepo::new()),
            authorizer: Arc::new(DenyAuthorizer),
        };
        assert!(matches!(
            uc.execute("req-1", &test_user("u2")).unwrap_err(),
            AppError::Forbidden(_)
        ));
    }

    #[test]
    fn current_step_approver_can_view_pending_request() {
        let uc = GetRequest {
            request_reader: Arc::new(MockReader {
                request: Mutex::new(Some(test_request("u1", RequestStatus::Pending))),
                is_approver: true,
            }),
            approval_repo: Arc::new(FakeApprovalRepo::new()),
            authorizer: Arc::new(DenyAuthorizer),
        };
        let out = uc.execute("req-1", &test_user("u2")).unwrap();
        assert!(out.is_approver_view);
        assert_eq!(out.detail, "[redacted - approve to view]");
    }

    #[test]
    fn non_approver_forbidden() {
        let uc = GetRequest {
            request_reader: Arc::new(MockReader {
                request: Mutex::new(Some(test_request("u1", RequestStatus::Pending))),
                is_approver: false,
            }),
            approval_repo: Arc::new(FakeApprovalRepo::new()),
            authorizer: Arc::new(DenyAuthorizer),
        };
        assert!(matches!(
            uc.execute("req-1", &test_user("u2")).unwrap_err(),
            AppError::Forbidden(_)
        ));
    }

    #[test]
    fn approver_cannot_view_non_pending_request() {
        let uc = GetRequest {
            request_reader: Arc::new(MockReader {
                request: Mutex::new(Some(test_request("u1", RequestStatus::Approved))),
                is_approver: true,
            }),
            approval_repo: Arc::new(FakeApprovalRepo::new()),
            authorizer: Arc::new(DenyAuthorizer),
        };
        assert!(matches!(
            uc.execute("req-1", &test_user("u2")).unwrap_err(),
            AppError::Forbidden(_)
        ));
    }
}
