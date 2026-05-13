use std::sync::Arc;

use dbward_domain::auth::{AuthUser, Permission};
use dbward_domain::entities::AuditEvent;

use crate::error::AppError;
use crate::ports::*;

pub struct UserManage {
    pub authorizer: Arc<dyn Authorizer>,
    pub user_repo: Arc<dyn UserRepo>,
    pub token_repo: Arc<dyn TokenRepo>,
    pub request_repo: Arc<dyn RequestRepo>,
    pub audit: Arc<dyn AuditLogger>,
    pub clock: Arc<dyn Clock>,
}

pub struct UserListOutput {
    pub users: Vec<dbward_domain::entities::User>,
}

pub struct UserSuspendInput {
    pub user_id: String,
}

pub struct UserSuspendOutput {
    pub id: String,
    pub revoked_tokens: u32,
    pub cancelled_requests: u32,
}

impl UserManage {
    pub fn list(&self, user: &AuthUser) -> Result<UserListOutput, AppError> {
        self.authorizer
            .authorize_global(user, Permission::UserManage)
            .map_err(AppError::Forbidden)?;
        let users = self.user_repo.list()?;
        Ok(UserListOutput { users })
    }

    pub fn suspend(
        &self,
        input: UserSuspendInput,
        user: &AuthUser,
    ) -> Result<UserSuspendOutput, AppError> {
        self.authorizer
            .authorize_global(user, Permission::UserManage)
            .map_err(AppError::Forbidden)?;

        // Check user exists
        self.user_repo
            .get(&input.user_id)?
            .ok_or_else(|| AppError::NotFound("user not found".into()))?;

        let now = self.clock.now();

        // Suspend (idempotent)
        self.user_repo.suspend(&input.user_id, now)?;

        // Revoke all tokens
        let revoked_tokens = self.token_repo.revoke_all_for_user(&input.user_id, now)?;

        // Cancel pending/approved/dispatched requests
        let cancelled_requests = self.request_repo.cancel_all_for_user(&input.user_id, now)?;

        // Audit
        self.audit.record(&AuditEvent::simple(
            "user_disabled",
            "identity",
            &user.subject_id,
            Some(&input.user_id),
        ))?;

        Ok(UserSuspendOutput {
            id: input.user_id,
            revoked_tokens,
            cancelled_requests,
        })
    }

    pub fn activate(&self, user_id: &str, user: &AuthUser) -> Result<(), AppError> {
        self.authorizer
            .authorize_global(user, Permission::UserManage)
            .map_err(AppError::Forbidden)?;

        self.user_repo
            .get(user_id)?
            .ok_or_else(|| AppError::NotFound("user not found".into()))?;

        let now = self.clock.now();
        self.user_repo.activate(user_id, now)?;

        self.audit.record(&AuditEvent::simple(
            "user_activated",
            "identity",
            &user.subject_id,
            Some(user_id),
        ))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AuthzError;
    use chrono::{DateTime, Utc};
    use dbward_domain::auth::{Permission as P, ResolvedRole, ResourceContext, SubjectType};
    use dbward_domain::entities::{Approval, AuditEvent, Request, Token, User};
    use dbward_domain::values::{DatabaseName, Environment};

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
    struct DenyAll;
    impl Authorizer for DenyAll {
        fn authorize_global(&self, _: &AuthUser, _: Permission) -> Result<(), AuthzError> {
            Err(AuthzError::Forbidden {
                permission: P::UserManage,
                reason: "denied".into(),
            })
        }
        fn authorize_scoped(
            &self,
            _: &AuthUser,
            _: Permission,
            _: &DatabaseName,
            _: &Environment,
            _: &ResourceContext,
        ) -> Result<(), AuthzError> {
            Err(AuthzError::Forbidden {
                permission: P::UserManage,
                reason: "denied".into(),
            })
        }
    }

    struct FakeClock;
    impl Clock for FakeClock {
        fn now(&self) -> DateTime<Utc> {
            Utc::now()
        }
    }
    struct FakeAudit;
    impl AuditLogger for FakeAudit {
        fn record(&self, _: &AuditEvent) -> Result<(), AppError> {
            Ok(())
        }
    }

    struct FakeUserRepo {
        has_user: bool,
    }
    impl UserRepo for FakeUserRepo {
        fn upsert(&self, _: &User) -> Result<(), AppError> {
            Ok(())
        }
        fn get(&self, _: &str) -> Result<Option<User>, AppError> {
            if self.has_user {
                Ok(Some(User {
                    id: "u1".into(),
                    display_name: None,
                    email: None,
                    groups: vec![],
                    roles: vec![],
                    status: dbward_domain::entities::UserStatus::Active,
                    last_seen_at: None,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                }))
            } else {
                Ok(None)
            }
        }
        fn list(&self) -> Result<Vec<User>, AppError> {
            Ok(vec![])
        }
        fn suspend(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
        fn is_suspended(&self, _: &str) -> Result<bool, AppError> {
            Ok(false)
        }
        fn ensure_exists(&self, _: &str) -> Result<(), AppError> {
            Ok(())
        }
        fn activate(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
    }

    struct FakeTokenRepo;
    impl TokenRepo for FakeTokenRepo {
        fn create(&self, _: &Token) -> Result<(), AppError> {
            Ok(())
        }
        fn verify(&self, _: &str, _: &str) -> Result<Option<Token>, AppError> {
            Ok(None)
        }
        fn list(&self) -> Result<Vec<Token>, AppError> {
            Ok(vec![])
        }
        fn get(&self, _: &str) -> Result<Option<Token>, AppError> {
            Ok(None)
        }
        fn revoke(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
        fn revoke_all_for_user(&self, _: &str, _: DateTime<Utc>) -> Result<u32, AppError> {
            Ok(2)
        }
        fn count_active(&self) -> Result<u32, AppError> {
            Ok(0)
        }
        fn purge_revoked(&self, _: &str) -> Result<u32, AppError> {
            Ok(0)
        }
    }

    struct FakeRequestRepo;
    impl RequestRepo for FakeRequestRepo {
        fn insert(&self, _: &Request) -> Result<(), AppError> {
            Ok(())
        }
        fn get(&self, _: &str) -> Result<Option<Request>, AppError> {
            Ok(None)
        }
        fn list(&self, _: u32, _: u32, _: Option<&str>) -> Result<(Vec<Request>, u32), AppError> {
            Ok((vec![], 0))
        }
        fn find_by_idempotency_key(&self, _: &str) -> Result<Option<Request>, AppError> {
            Ok(None)
        }
        fn insert_approval(&self, _: &Approval) -> Result<(), AppError> {
            Ok(())
        }
        fn get_approvals(&self, _: &str) -> Result<Vec<Approval>, AppError> {
            Ok(vec![])
        }
        fn count_executions(&self, _: &str) -> Result<u32, AppError> {
            Ok(0)
        }
        fn mark_approved(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
        fn approve_and_mark_approved(
            &self,
            _: &Approval,
            _: &str,
            _: DateTime<Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_rejected(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
        fn reject_and_record(
            &self,
            _: &str,
            _: &Approval,
            _: DateTime<Utc>,
        ) -> Result<bool, AppError> {
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
            Ok(true)
        }
        fn create_and_dispatch(&self, _: &Request) -> Result<(), AppError> {
            Ok(())
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
        fn cancel_all_for_user(&self, _: &str, _: DateTime<Utc>) -> Result<u32, AppError> {
            Ok(3)
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
            _: &AuditEvent,
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
    }

    fn admin_user() -> AuthUser {
        AuthUser {
            subject_id: "admin".into(),
            subject_type: SubjectType::User,
            roles: vec![ResolvedRole {
                name: "admin".into(),
                permissions: [P::UserManage].into_iter().collect(),
                databases: vec![],
                environments: vec![],
            }],
            groups: vec![],
            token_id: None,
        }
    }

    fn make_uc(has_user: bool, authz: Arc<dyn Authorizer>) -> UserManage {
        UserManage {
            authorizer: authz,
            user_repo: Arc::new(FakeUserRepo { has_user }),
            token_repo: Arc::new(FakeTokenRepo),
            request_repo: Arc::new(FakeRequestRepo),
            audit: Arc::new(FakeAudit),
            clock: Arc::new(FakeClock),
        }
    }

    #[test]
    fn list_denied_without_permission() {
        let uc = make_uc(false, Arc::new(DenyAll));
        assert!(matches!(
            uc.list(&admin_user()),
            Err(AppError::Forbidden(_))
        ));
    }

    #[test]
    fn suspend_not_found() {
        let uc = make_uc(false, Arc::new(AllowAll));
        assert!(matches!(
            uc.suspend(
                UserSuspendInput {
                    user_id: "ghost".into()
                },
                &admin_user()
            ),
            Err(AppError::NotFound(_))
        ));
    }

    #[test]
    fn suspend_success_returns_counts() {
        let uc = make_uc(true, Arc::new(AllowAll));
        let out = uc
            .suspend(
                UserSuspendInput {
                    user_id: "u1".into(),
                },
                &admin_user(),
            )
            .unwrap();
        assert_eq!(out.revoked_tokens, 2);
        assert_eq!(out.cancelled_requests, 3);
    }

    #[test]
    fn activate_not_found() {
        let uc = make_uc(false, Arc::new(AllowAll));
        assert!(matches!(
            uc.activate("ghost", &admin_user()),
            Err(AppError::NotFound(_))
        ));
    }
}
