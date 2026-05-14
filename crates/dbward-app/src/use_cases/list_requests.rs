use std::sync::Arc;

use dbward_domain::auth::{AuthUser, Permission};
use dbward_domain::entities::{Request, RequestStatus};

use crate::error::AppError;
use crate::ports::*;

pub struct ListRequests {
    pub request_repo: Arc<dyn RequestRepo>,
    pub authorizer: Arc<dyn Authorizer>,
}

pub struct ListRequestsInput {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub status: Option<String>,
    pub user: Option<String>,
    pub pending_for_me: Option<bool>,
}

pub struct ListRequestsOutput {
    pub requests: Vec<RequestSummary>,
    pub total: u32,
    pub limit: u32,
    pub offset: u32,
}

pub struct RequestSummary {
    pub id: String,
    pub requester: String,
    pub database: String,
    pub environment: String,
    pub operation: String,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl From<&Request> for RequestSummary {
    fn from(r: &Request) -> Self {
        Self {
            id: r.id.clone(),
            requester: r.requester.clone(),
            database: r.database.to_string(),
            environment: r.environment.to_string(),
            operation: r.operation.as_str().to_string(),
            status: r.status.as_str().to_string(),
            created_at: r.created_at,
        }
    }
}

impl ListRequests {
    pub fn execute(
        &self,
        input: ListRequestsInput,
        user: &AuthUser,
    ) -> Result<ListRequestsOutput, AppError> {
        let limit = input.limit.unwrap_or(50).min(100);
        let offset = input.offset.unwrap_or(0);
        let pending_for_me = input.pending_for_me.unwrap_or(false);

        // Note: pending_for_me returns requests where the user matches a workflow
        // approver selector. Scope is enforced by the workflow definition itself,
        // not by db/env permission scoping. This is by design: if a workflow lists
        // you as approver, you need to see the request to act on it.
        if pending_for_me {
            let has_view = self
                .authorizer
                .authorize_global(user, Permission::RequestView)
                .is_ok();
            let has_approve = self
                .authorizer
                .authorize_global(user, Permission::RequestApprove)
                .is_ok();
            if !has_view && !has_approve {
                return Err(AppError::Forbidden(crate::error::AuthzError::Forbidden {
                    permission: Permission::RequestView,
                    reason: "requires RequestView or RequestApprove".into(),
                }));
            }
        } else {
            self.authorizer
                .authorize_global(user, Permission::RequestView)
                .map_err(AppError::Forbidden)?;
        }

        // Note: pending_for_me returns requests where the user matches a workflow
        // approver selector. Scope is enforced by the workflow definition itself,
        // not by db/env permission scoping. This is by design: if a workflow lists
        // you as approver, you need to see the request to act on it.
        if pending_for_me {
            let roles: Vec<String> = user.roles.iter().map(|r| r.name.clone()).collect();
            let (requests, total) = self.request_repo.list_pending_for_user(
                &user.subject_id,
                &user.groups,
                &roles,
                limit,
                offset,
            )?;
            let items = requests.iter().map(RequestSummary::from).collect();
            return Ok(ListRequestsOutput {
                requests: items,
                total,
                limit,
                offset,
            });
        }

        let (requests, total) = self.request_repo.list(
            limit,
            offset,
            input.status.as_deref(),
            input.user.as_deref(),
        )?;

        let is_admin = user.roles.iter().any(|r| r.name == "admin");
        let can_approve = user.has_permission(Permission::RequestApprove);

        let items: Vec<RequestSummary> = requests
            .iter()
            .filter(|r| {
                if is_admin {
                    return true;
                }
                if r.requester == user.subject_id {
                    return true;
                }
                if can_approve && r.status == RequestStatus::Pending {
                    return true;
                }
                false
            })
            .map(RequestSummary::from)
            .collect();

        let effective_total = if is_admin { total } else { items.len() as u32 };

        Ok(ListRequestsOutput {
            requests: items,
            total: effective_total,
            limit,
            offset,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AuthzError;
    use chrono::Utc;
    use dbward_domain::auth::{ResolvedRole, ResourceContext, SubjectType};
    use dbward_domain::values::{DatabaseName, Environment, Operation};
    use std::sync::Mutex;

    struct AllowAll;
    impl Authorizer for AllowAll {
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

    struct DenyAll;
    impl Authorizer for DenyAll {
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

    struct FakeRepo {
        requests: Mutex<Vec<Request>>,
    }

    impl FakeRepo {
        fn new(requests: Vec<Request>) -> Self {
            Self {
                requests: Mutex::new(requests),
            }
        }
    }

    impl RequestRepo for FakeRepo {
        fn list(
            &self,
            _limit: u32,
            _offset: u32,
            _status: Option<&str>,
            _user: Option<&str>,
        ) -> Result<(Vec<Request>, u32), AppError> {
            let reqs = self.requests.lock().unwrap().clone();
            let total = reqs.len() as u32;
            Ok((reqs, total))
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
        fn insert(&self, _: &Request) -> Result<(), AppError> {
            Ok(())
        }
        fn get(&self, _: &str) -> Result<Option<Request>, AppError> {
            Ok(None)
        }
        fn find_by_idempotency_key(&self, _: &str) -> Result<Option<Request>, AppError> {
            Ok(None)
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
        fn mark_approved(&self, _: &str, _: chrono::DateTime<Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
        fn approve_and_mark_approved(
            &self,
            _: &dbward_domain::entities::Approval,
            _: &str,
            _: chrono::DateTime<Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_rejected(&self, _: &str, _: chrono::DateTime<Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
        fn reject_and_record(
            &self,
            _: &str,
            _: &dbward_domain::entities::Approval,
            _: chrono::DateTime<Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_cancelled(
            &self,
            _: &str,
            _: &str,
            _: Option<&str>,
            _: chrono::DateTime<Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_dispatched(&self, _: &str, _: chrono::DateTime<Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
        fn create_and_dispatch(&self, _: &Request) -> Result<(), AppError> {
            Ok(())
        }
        fn mark_running(&self, _: &str, _: chrono::DateTime<Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_executed(&self, _: &str, _: chrono::DateTime<Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_failed(&self, _: &str, _: chrono::DateTime<Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
        fn cancel_all_for_user(&self, _: &str, _: chrono::DateTime<Utc>) -> Result<u32, AppError> {
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
        ) -> Result<Vec<StoredResultEntry>, AppError> {
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

    fn make_user(id: &str, roles: &[&str]) -> AuthUser {
        AuthUser {
            subject_id: id.to_string(),
            subject_type: SubjectType::User,
            roles: roles
                .iter()
                .map(|name| ResolvedRole {
                    name: name.to_string(),
                    permissions: if *name == "admin" {
                        [Permission::All].into_iter().collect()
                    } else {
                        [Permission::RequestView, Permission::RequestApprove]
                            .into_iter()
                            .collect()
                    },
                    databases: vec![],
                    environments: vec![],
                })
                .collect(),
            groups: vec![],
            token_id: None,
        }
    }

    fn make_request(id: &str, requester: &str, status: RequestStatus) -> Request {
        Request {
            id: id.to_string(),
            requester: requester.to_string(),
            database: DatabaseName::new("app").unwrap(),
            environment: Environment::new("production").unwrap(),
            operation: Operation::ExecuteDml,
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
            created_at: Utc::now(),
            updated_at: Utc::now(),
            resolved_at: None,
            expires_at: None,
        }
    }

    #[test]
    fn admin_sees_all_requests() {
        let requests = vec![
            make_request("r1", "alice", RequestStatus::Pending),
            make_request("r2", "bob", RequestStatus::Approved),
        ];
        let repo = Arc::new(FakeRepo::new(requests));
        let uc = ListRequests {
            request_repo: repo,
            authorizer: Arc::new(AllowAll),
        };
        let user = make_user("admin-user", &["admin"]);
        let out = uc
            .execute(
                ListRequestsInput {
                    limit: None,
                    offset: None,
                    status: None,
                    user: None,
                    pending_for_me: None,
                },
                &user,
            )
            .unwrap();
        assert_eq!(out.requests.len(), 2);
        assert_eq!(out.total, 2);
    }

    #[test]
    fn non_admin_sees_own_and_pending_approvable() {
        let requests = vec![
            make_request("r1", "alice", RequestStatus::Pending),
            make_request("r2", "bob", RequestStatus::Approved),
            make_request("r3", "alice", RequestStatus::Approved),
        ];
        let repo = Arc::new(FakeRepo::new(requests));
        let uc = ListRequests {
            request_repo: repo,
            authorizer: Arc::new(AllowAll),
        };
        let user = make_user("alice", &["developer"]);
        let out = uc
            .execute(
                ListRequestsInput {
                    limit: None,
                    offset: None,
                    status: None,
                    user: None,
                    pending_for_me: None,
                },
                &user,
            )
            .unwrap();
        // alice sees: r1 (own+pending), r3 (own), r1 also approvable
        assert_eq!(out.requests.len(), 2);
        assert_eq!(out.total, 2);
    }

    #[test]
    fn forbidden_when_no_permission() {
        let repo = Arc::new(FakeRepo::new(vec![]));
        let uc = ListRequests {
            request_repo: repo,
            authorizer: Arc::new(DenyAll),
        };
        let user = make_user("nobody", &[]);
        let result = uc.execute(
            ListRequestsInput {
                limit: None,
                offset: None,
                status: None,
                user: None,
                pending_for_me: None,
            },
            &user,
        );
        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    #[test]
    fn limit_capped_at_100() {
        let repo = Arc::new(FakeRepo::new(vec![]));
        let uc = ListRequests {
            request_repo: repo,
            authorizer: Arc::new(AllowAll),
        };
        let user = make_user("alice", &["admin"]);
        let out = uc
            .execute(
                ListRequestsInput {
                    limit: Some(999),
                    offset: None,
                    status: None,
                    user: None,
                    pending_for_me: None,
                },
                &user,
            )
            .unwrap();
        assert_eq!(out.limit, 100);
    }
}
