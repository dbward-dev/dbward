use std::sync::Arc;

use dbward_domain::auth::{AuthUser, Permission};
use dbward_domain::entities::{AuditContext};

use crate::error::AppError;
use crate::ports::*;

pub struct UserManage {
    pub authorizer: Arc<dyn Authorizer>,
    pub user_repo: Arc<dyn UserRepo>,
    pub token_repo: Arc<dyn TokenRepo>,
    pub request_writer: Arc<dyn RequestWriter>,
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
    pub cancelled_requests: Vec<String>,
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
        ctx: &AuditContext,
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
        let cancelled_requests = self
            .request_writer
            .cancel_all_for_user(&input.user_id, &user.subject_id, "user suspended", now, &dbward_domain::entities::AuditContext::System)?;

        // Audit
        self.audit.record(&dbward_domain::entities::AuditEvent::simple(
            "user_disabled",
            "identity",
            &user.subject_id,
            Some(&input.user_id),
            self.clock.now(),
            ctx,
        ))?;

        Ok(UserSuspendOutput {
            id: input.user_id,
            revoked_tokens,
            cancelled_requests,
        })
    }

    pub fn activate(
        &self,
        user_id: &str,
        user: &AuthUser,
        ctx: &AuditContext,
    ) -> Result<(), AppError> {
        self.authorizer
            .authorize_global(user, Permission::UserManage)
            .map_err(AppError::Forbidden)?;

        self.user_repo
            .get(user_id)?
            .ok_or_else(|| AppError::NotFound("user not found".into()))?;

        let now = self.clock.now();
        self.user_repo.activate(user_id, now)?;

        self.audit.record(&dbward_domain::entities::AuditEvent::simple(
            "user_activated",
            "identity",
            &user.subject_id,
            Some(user_id),
            self.clock.now(),
            ctx,
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
    use dbward_domain::entities::{AuditContext, AuditEvent, Token, User};
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
        fn record(&self, _: &dbward_domain::entities::AuditEvent) -> Result<(), AppError> {
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
    impl RequestWriter for FakeRequestRepo {
        fn insert(&self, _: &dbward_domain::entities::Request) -> Result<(), AppError> {
            Ok(())
        }
        fn create_and_dispatch(
            &self,
            _: &dbward_domain::entities::Request,
        ) -> Result<(), AppError> {
            Ok(())
        }
        fn mark_approved(
            &self,
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
            _: &str,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
            _: &dbward_domain::entities::AuditContext,
        ) -> Result<Vec<String>, AppError> {
            Ok(vec!["r1".into(), "r2".into(), "r3".into()])
        }
        fn mark_approved_from_dispatched(&self, _: &str, _: &str) -> Result<bool, AppError> {
            Ok(true)
        }
    fn mark_approved_from_dispatched_and_record(&self, _: &str, _: &dbward_domain::entities::AuditEvent, _: &str) -> Result<bool, AppError> { Ok(true) }
    }

    fn admin_user() -> AuthUser {
        AuthUser {
            subject_id: "admin".into(),
            subject_type: SubjectType::User,
            roles: vec![ResolvedRole {
                name: "admin".into(),
                permissions: [P::All].into_iter().collect(),
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
            request_writer: Arc::new(FakeRequestRepo),
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
                &admin_user(),
                &AuditContext::System,
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
                &AuditContext::System,
            )
            .unwrap();
        assert_eq!(out.revoked_tokens, 2);
        assert_eq!(out.cancelled_requests.len(), 3);
    }

    #[test]
    fn activate_not_found() {
        let uc = make_uc(false, Arc::new(AllowAll));
        assert!(matches!(
            uc.activate("ghost", &admin_user(), &AuditContext::System),
            Err(AppError::NotFound(_))
        ));
    }
}
