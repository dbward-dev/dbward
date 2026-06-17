use std::sync::Arc;

use dbward_domain::auth::{AuthUser, Permission};
use dbward_domain::entities::AuditContext;

use crate::error::AppError;
use crate::ports::*;

pub struct UserManage {
    pub authorizer: Arc<dyn Authorizer>,
    pub user_repo: Arc<dyn UserRepo>,
    pub token_repo: Arc<dyn TokenRepo>,
    pub uow: Arc<dyn UnitOfWork>,
    pub clock: Arc<dyn Clock>,
    pub license: Arc<dyn LicenseChecker>,
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
            .authorize_global(user, Permission::UserWrite)
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
            .authorize_global(user, Permission::UserWrite)
            .map_err(AppError::Forbidden)?;

        // Check user exists
        self.user_repo
            .get(&input.user_id)?
            .ok_or_else(|| AppError::NotFound("user not found".into()))?;

        let now = self.clock.now();

        // Atomic: suspend + revoke tokens + cancel requests + audit
        let user_id = input.user_id.clone();
        let actor_id = user.subject_id.clone();
        let audit_event = dbward_domain::entities::AuditEvent::simple(
            "user.disabled",
            "identity",
            &actor_id,
            Some(&user_id),
            now,
            ctx,
        );
        let result = crate::ports::uow_execute(&*self.uow, move |tx| {
            tx.suspend_user(&user_id, now)?;
            let revoked = tx.revoke_all_for_user(&user_id, now)?;
            let cancelled =
                tx.cancel_all_for_user(&user_id, &actor_id, Some("user suspended"), now)?;
            tx.record(&audit_event)?;
            Ok((revoked, cancelled))
        })?;

        Ok(UserSuspendOutput {
            id: input.user_id,
            revoked_tokens: result.0,
            cancelled_requests: result.1,
        })
    }

    pub fn activate(
        &self,
        user_id: &str,
        user: &AuthUser,
        ctx: &AuditContext,
    ) -> Result<(), AppError> {
        self.authorizer
            .authorize_global(user, Permission::UserWrite)
            .map_err(AppError::Forbidden)?;

        let existing = self
            .user_repo
            .get(user_id)?
            .ok_or_else(|| AppError::NotFound("user not found".into()))?;

        // Only check limit when transitioning from suspended to active
        if existing.status == dbward_domain::entities::UserStatus::Suspended {
            let count = self.user_repo.count_active()?;
            if count >= self.license.max_users() {
                return Err(AppError::PlanLimit("user limit reached".into()));
            }
        }

        let now = self.clock.now();
        let uid = user_id.to_string();
        let actor_id = user.subject_id.clone();
        let audit_event = dbward_domain::entities::AuditEvent::simple(
            "user.activated",
            "identity",
            &actor_id,
            Some(user_id),
            now,
            ctx,
        );
        self.uow.execute(Box::new(move |tx| {
            tx.activate_user(&uid, now)?;
            tx.record(&audit_event)?;
            Ok(())
        }))?;

        Ok(())
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use super::*;
    use crate::error::AuthzError;
    use crate::test_support::NoopUnitOfWork;
    use chrono::{DateTime, Utc};
    use dbward_domain::auth::{Permission as P, ResolvedRole, ResourceContext, SubjectType};
    use dbward_domain::entities::{AuditContext, Token, User};
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
                permission: P::UserWrite,
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
                permission: P::UserWrite,
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
    }

    struct FakeLicense;
    impl LicenseChecker for FakeLicense {
        fn max_users(&self) -> u32 {
            u32::MAX
        }
        fn max_databases(&self) -> u32 {
            u32::MAX
        }
        fn max_workflows(&self) -> u32 {
            u32::MAX
        }
        fn max_webhooks(&self) -> u32 {
            u32::MAX
        }
        fn max_roles(&self) -> u32 {
            u32::MAX
        }
        fn is_enterprise(&self) -> bool {
            false
        }
        fn configured_plan(&self) -> &str {
            "free"
        }
        fn effective_plan(&self) -> &str {
            "free"
        }
        fn is_expired(&self) -> bool {
            false
        }
        fn check_expiry(&self, _: chrono::DateTime<chrono::Utc>) {}
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
            uow: Arc::new(NoopUnitOfWork),
            clock: Arc::new(FakeClock),
            license: Arc::new(FakeLicense),
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
        assert_eq!(out.revoked_tokens, 0); // NoopTxScope returns 0
        assert!(out.cancelled_requests.is_empty()); // NoopTxScope returns empty
    }

    #[test]
    fn activate_not_found() {
        let uc = make_uc(false, Arc::new(AllowAll));
        assert!(matches!(
            uc.activate("ghost", &admin_user(), &AuditContext::System),
            Err(AppError::NotFound(_))
        ));
    }

    #[test]
    fn activate_blocked_at_user_limit() {
        struct ZeroLicense;
        impl LicenseChecker for ZeroLicense {
            fn max_users(&self) -> u32 {
                0
            }
            fn max_databases(&self) -> u32 {
                u32::MAX
            }
            fn max_workflows(&self) -> u32 {
                u32::MAX
            }
            fn max_webhooks(&self) -> u32 {
                u32::MAX
            }
            fn max_roles(&self) -> u32 {
                u32::MAX
            }
            fn is_enterprise(&self) -> bool {
                false
            }
            fn configured_plan(&self) -> &str {
                "free"
            }
            fn effective_plan(&self) -> &str {
                "free"
            }
            fn is_expired(&self) -> bool {
                false
            }
            fn check_expiry(&self, _: chrono::DateTime<chrono::Utc>) {}
        }
        struct SuspendedUserRepo;
        impl UserRepo for SuspendedUserRepo {
            fn get(&self, _: &str) -> Result<Option<User>, AppError> {
                Ok(Some(User {
                    id: "u1".into(),
                    display_name: None,
                    email: None,
                    groups: vec![],
                    roles: vec![],
                    status: dbward_domain::entities::UserStatus::Suspended,
                    last_seen_at: None,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                }))
            }
            fn upsert(&self, _: &User) -> Result<(), AppError> {
                Ok(())
            }
            fn list(&self) -> Result<Vec<User>, AppError> {
                Ok(vec![])
            }
            fn suspend(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> {
                Ok(true)
            }
            fn activate(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> {
                Ok(true)
            }
            fn is_suspended(&self, _: &str) -> Result<bool, AppError> {
                Ok(true)
            }
            fn ensure_exists(&self, _: &str) -> Result<(), AppError> {
                Ok(())
            }
            fn count_active(&self) -> Result<u32, AppError> {
                Ok(5)
            }
        }
        let uc = UserManage {
            authorizer: Arc::new(AllowAll),
            user_repo: Arc::new(SuspendedUserRepo),
            token_repo: Arc::new(FakeTokenRepo),
            uow: Arc::new(NoopUnitOfWork),
            clock: Arc::new(FakeClock),
            license: Arc::new(ZeroLicense),
        };
        let result = uc.activate("u1", &admin_user(), &AuditContext::System);
        assert!(matches!(result, Err(AppError::PlanLimit(_))));
    }
}
