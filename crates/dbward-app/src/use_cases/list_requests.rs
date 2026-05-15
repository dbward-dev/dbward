use std::sync::Arc;

use dbward_domain::auth::{AuthUser, Permission};
use dbward_domain::entities::{Request, RequestStatus};
use dbward_domain::policies::workflow::Workflow;

use crate::error::AppError;
use crate::ports::*;

pub struct ListRequests {
    pub request_reader: Arc<dyn RequestReader>,
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
    pub current_step: Option<u32>,
    pub total_steps: Option<u32>,
    pub next_approvers: Vec<String>,
}

impl RequestSummary {
    fn from_request(r: &Request) -> Self {
        let (current_step, total_steps, next_approvers) = if r.status == RequestStatus::Pending {
            extract_lightweight_progress(r)
        } else {
            (None, None, vec![])
        };
        Self {
            id: r.id.clone(),
            requester: r.requester.clone(),
            database: r.database.to_string(),
            environment: r.environment.to_string(),
            operation: r.operation.as_str().to_string(),
            status: r.status.as_str().to_string(),
            created_at: r.created_at,
            current_step,
            total_steps,
            next_approvers,
        }
    }
}

/// Extract lightweight progress from workflow_snapshot_json without approvals query.
/// Returns (None for current_step since we don't query approvals, total_steps, next_approvers from step[0]).
fn extract_lightweight_progress(r: &Request) -> (Option<u32>, Option<u32>, Vec<String>) {
    let wf = r
        .workflow_snapshot_json
        .as_deref()
        .and_then(|json| serde_json::from_str::<Workflow>(json).ok());
    match wf {
        Some(wf) => {
            let total = wf.steps.len() as u32;
            let approvers = wf
                .steps
                .first()
                .map(|step| {
                    step.approvers
                        .iter()
                        .map(|a| a.selector.to_string())
                        .collect()
                })
                .unwrap_or_default();
            (None, Some(total), approvers)
        }
        None => (None, None, vec![]),
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
            let (requests, total) = self.request_reader.list_pending_for_user(
                &user.subject_id,
                &user.groups,
                &roles,
                limit,
                offset,
            )?;
            let items = requests.iter().map(RequestSummary::from_request).collect();
            return Ok(ListRequestsOutput {
                requests: items,
                total,
                limit,
                offset,
            });
        }

        let (requests, total) = self.request_reader.list(
            limit,
            offset,
            input.status.as_deref(),
            input.user.as_deref(),
        )?;

        let is_admin = user.roles.iter().any(|r| r.name == "admin");

        if is_admin {
            let items = requests.iter().map(RequestSummary::from_request).collect();
            return Ok(ListRequestsOutput {
                requests: items,
                total,
                limit,
                offset,
            });
        }

        // Non-admin: use SQL-level visibility query for correct pagination
        let roles: Vec<String> = user.roles.iter().map(|r| r.name.clone()).collect();
        let (visible_requests, visible_total) = self.request_reader.list_visible_to_user(
            &user.subject_id,
            &user.groups,
            &roles,
            input.status.as_deref(),
            limit,
            offset,
        )?;
        let items: Vec<RequestSummary> = if let Some(ref filter_user) = input.user {
            visible_requests
                .iter()
                .filter(|r| r.requester == *filter_user)
                .map(RequestSummary::from_request)
                .collect()
        } else {
            visible_requests
                .iter()
                .map(RequestSummary::from_request)
                .collect()
        };
        let total = if input.user.is_some() {
            items.len() as u32
        } else {
            visible_total
        };

        Ok(ListRequestsOutput {
            requests: items,
            total,
            limit,
            offset,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use chrono::Utc;
    use dbward_domain::auth::{ResolvedRole, SubjectType};
    use dbward_domain::entities::RequestStatus;
    use dbward_domain::values::{DatabaseName, Environment, Operation};
    use std::sync::Mutex;

    struct FakeListReader {
        requests: Mutex<Vec<Request>>,
    }
    impl FakeListReader {
        fn new(requests: Vec<Request>) -> Self {
            Self {
                requests: Mutex::new(requests),
            }
        }
    }
    impl RequestReader for FakeListReader {
        fn get(&self, _: &str) -> Result<Option<Request>, AppError> {
            Ok(None)
        }
        fn list(
            &self,
            _: u32,
            _: u32,
            _: Option<&str>,
            _: Option<&str>,
        ) -> Result<(Vec<Request>, u32), AppError> {
            let reqs = self.requests.lock().unwrap().clone();
            let total = reqs.len() as u32;
            Ok((reqs, total))
        }
        fn find_by_idempotency_key(&self, _: &str) -> Result<Option<Request>, AppError> {
            Ok(None)
        }
        fn list_visible_to_user(
            &self,
            user_id: &str,
            _: &[String],
            _: &[String],
            _: Option<&str>,
            _: u32,
            _: u32,
        ) -> Result<(Vec<Request>, u32), AppError> {
            let reqs = self.requests.lock().unwrap();
            let visible: Vec<Request> = reqs
                .iter()
                .filter(|r| r.requester == user_id || r.status == RequestStatus::Pending)
                .cloned()
                .collect();
            let total = visible.len() as u32;
            Ok((visible, total))
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
        let uc = ListRequests {
            request_reader: Arc::new(FakeListReader::new(requests)),
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
        let uc = ListRequests {
            request_reader: Arc::new(FakeListReader::new(requests)),
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
        assert_eq!(out.requests.len(), 2);
        assert_eq!(out.total, 2);
    }

    #[test]
    fn forbidden_when_no_permission() {
        let uc = ListRequests {
            request_reader: Arc::new(FakeListReader::new(vec![])),
            authorizer: Arc::new(DenyAll),
        };
        let user = make_user("nobody", &[]);
        assert!(matches!(
            uc.execute(
                ListRequestsInput {
                    limit: None,
                    offset: None,
                    status: None,
                    user: None,
                    pending_for_me: None
                },
                &user
            ),
            Err(AppError::Forbidden(_))
        ));
    }

    #[test]
    fn limit_capped_at_100() {
        let uc = ListRequests {
            request_reader: Arc::new(FakeListReader::new(vec![])),
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
