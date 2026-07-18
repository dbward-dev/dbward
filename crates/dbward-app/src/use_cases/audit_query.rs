use std::sync::Arc;

use dbward_domain::auth::{AuthUser, Permission};
use dbward_domain::entities::AuditEvent;

use crate::error::AppError;
use crate::ports::*;

pub struct AuditQuery {
    pub authorizer: Arc<dyn Authorizer>,
    pub audit_repo: Arc<dyn AuditRepo>,
    pub audit_verifier: Option<Arc<dyn crate::ports::crypto::AuditVerifier>>,
}

pub struct AuditListInput {
    pub filter: AuditFilter,
}

pub struct AuditListOutput {
    pub events: Vec<AuditEvent>,
}

pub struct AuditVerifyOutput {
    pub total_events: u64,
    pub first_broken_id: Option<String>,
}

impl AuditQuery {
    pub fn list(
        &self,
        input: AuditListInput,
        user: &AuthUser,
    ) -> Result<AuditListOutput, AppError> {
        // audit.read grants full access to all audit events
        self.authorizer
            .authorize_global(user, Permission::AuditRead)
            .map_err(AppError::Forbidden)?;

        let events = self.audit_repo.list(&input.filter)?;

        Ok(AuditListOutput { events })
    }

    pub fn verify(&self, user: &AuthUser) -> Result<AuditVerifyOutput, AppError> {
        self.authorizer
            .authorize_global(user, Permission::AuditRead)
            .map_err(AppError::Forbidden)?;
        let result = self
            .audit_repo
            .verify_chain(self.audit_verifier.as_deref())?;
        Ok(AuditVerifyOutput {
            total_events: result.total_events,
            first_broken_id: result.first_broken_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AuthzError;
    use dbward_domain::auth::{Permission as P, ResolvedRole, ResourceContext, SubjectType};
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
        fn authorize_approval(
            &self,
            _: &AuthUser,
            _: &DatabaseName,
            _: &Environment,
            _: &ResourceContext,
        ) -> Result<(), AuthzError> {
            Ok(())
        }
    }
    struct AllowViewOnly;
    impl Authorizer for AllowViewOnly {
        fn authorize_global(&self, _: &AuthUser, perm: Permission) -> Result<(), AuthzError> {
            if perm == Permission::AuditRead {
                Ok(())
            } else {
                Err(AuthzError::Forbidden {
                    permission: perm,
                    reason: "denied".into(),
                })
            }
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
        fn authorize_approval(
            &self,
            _: &AuthUser,
            _: &DatabaseName,
            _: &Environment,
            _: &ResourceContext,
        ) -> Result<(), AuthzError> {
            Ok(())
        }
    }
    struct DenyAll;
    impl Authorizer for DenyAll {
        fn authorize_global(&self, _: &AuthUser, perm: Permission) -> Result<(), AuthzError> {
            Err(AuthzError::Forbidden {
                permission: perm,
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
                permission: Permission::AuditRead,
                reason: "denied".into(),
            })
        }
        fn authorize_approval(
            &self,
            _: &AuthUser,
            _: &DatabaseName,
            _: &Environment,
            _: &ResourceContext,
        ) -> Result<(), AuthzError> {
            Err(AuthzError::Forbidden {
                permission: Permission::RequestView,
                reason: "denied".into(),
            })
        }
    }

    struct FakeAuditRepo;
    impl AuditRepo for FakeAuditRepo {
        fn list(&self, filter: &AuditFilter) -> Result<Vec<AuditEvent>, AppError> {
            let mut ev = AuditEvent::simple(
                "query_executed",
                "query",
                "alice",
                Some("req-1"),
                chrono::Utc::now(),
                &dbward_domain::entities::AuditContext::System,
            );
            ev.detail_raw = Some("SELECT 1".into());
            if let Some(ref actor) = filter.actor_id
                && actor != "alice"
            {
                return Ok(vec![]);
            }
            Ok(vec![ev])
        }
        fn verify_chain(
            &self,
            _: Option<&dyn crate::ports::crypto::AuditVerifier>,
        ) -> Result<AuditVerifyResult, AppError> {
            Ok(AuditVerifyResult {
                total_events: 42,
                first_broken_id: None,
                failure: None,
            })
        }
        fn purge_old(&self, _: &str) -> Result<u32, AppError> {
            Ok(0)
        }
        fn purge_authenticated(
            &self,
            _: &str,
            _: &dyn crate::ports::crypto::AuditSigner,
        ) -> Result<(u32, String), AppError> {
            Ok((0, String::new()))
        }
    }

    fn admin_user() -> AuthUser {
        AuthUser {
            subject_id: "admin".into(),
            subject_type: SubjectType::User,
            roles: vec![ResolvedRole {
                name: "admin".into(),
                permissions: [(P::AuditRead, dbward_domain::auth::OwnershipScope::Own)]
                    .into_iter()
                    .collect(),
                databases: vec![],
                environments: vec![],
            }],
            groups: vec![],
            token_id: None,
        }
    }
    fn normal_user() -> AuthUser {
        AuthUser {
            subject_id: "alice".into(),
            subject_type: SubjectType::User,
            roles: vec![],
            groups: vec![],
            token_id: None,
        }
    }

    #[test]
    fn admin_sees_all_with_detail_raw() {
        let uc = AuditQuery {
            authorizer: Arc::new(AllowAll),
            audit_repo: Arc::new(FakeAuditRepo),
            audit_verifier: None,
        };
        let out = uc
            .list(
                AuditListInput {
                    filter: AuditFilter {
                        actor_id: None,
                        event_type: None,
                        event_category: None,
                        outcome: None,
                        environment: None,
                        database: None,
                        since: None,
                        until: None,
                        limit: 100,
                        offset: 0,
                    },
                },
                &admin_user(),
            )
            .unwrap();
        assert_eq!(out.events.len(), 1);
        assert!(out.events[0].detail_raw.is_some());
    }

    #[test]
    fn audit_read_sees_all_with_detail_raw() {
        let uc = AuditQuery {
            authorizer: Arc::new(AllowViewOnly),
            audit_repo: Arc::new(FakeAuditRepo),
            audit_verifier: None,
        };
        let out = uc
            .list(
                AuditListInput {
                    filter: AuditFilter {
                        actor_id: None,
                        event_type: None,
                        event_category: None,
                        outcome: None,
                        environment: None,
                        database: None,
                        since: None,
                        until: None,
                        limit: 100,
                        offset: 0,
                    },
                },
                &normal_user(),
            )
            .unwrap();
        assert_eq!(out.events.len(), 1);
        assert!(out.events[0].detail_raw.is_some());
    }

    #[test]
    fn unauthorized_returns_forbidden() {
        let uc = AuditQuery {
            authorizer: Arc::new(DenyAll),
            audit_repo: Arc::new(FakeAuditRepo),
            audit_verifier: None,
        };
        assert!(matches!(
            uc.list(
                AuditListInput {
                    filter: AuditFilter {
                        actor_id: None,
                        event_type: None,
                        event_category: None,
                        outcome: None,
                        environment: None,
                        database: None,
                        since: None,
                        until: None,
                        limit: 100,
                        offset: 0
                    }
                },
                &normal_user()
            ),
            Err(AppError::Forbidden(_))
        ));
    }

    #[test]
    fn verify_chain_returns_result() {
        let uc = AuditQuery {
            authorizer: Arc::new(AllowAll),
            audit_repo: Arc::new(FakeAuditRepo),
            audit_verifier: None,
        };
        let out = uc.verify(&admin_user()).unwrap();
        assert_eq!(out.total_events, 42);
        assert!(out.first_broken_id.is_none());
    }
}
