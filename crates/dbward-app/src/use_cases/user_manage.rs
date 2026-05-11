use std::sync::Arc;

use dbward_domain::auth::{AuthUser, Permission};
use dbward_domain::entities::{AuditEvent, RequestStatus};

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
        self.authorizer.authorize_global(user, Permission::UserManage)
            .map_err(AppError::Forbidden)?;
        let users = self.user_repo.list()?;
        Ok(UserListOutput { users })
    }

    pub fn suspend(&self, input: UserSuspendInput, user: &AuthUser) -> Result<UserSuspendOutput, AppError> {
        self.authorizer.authorize_global(user, Permission::UserManage)
            .map_err(AppError::Forbidden)?;

        // Check user exists
        self.user_repo.get(&input.user_id)?
            .ok_or_else(|| AppError::NotFound("user not found".into()))?;

        let now = self.clock.now();

        // Suspend (idempotent)
        self.user_repo.suspend(&input.user_id, now)?;

        // Revoke all tokens
        let revoked_tokens = self.token_repo.revoke_all_for_user(&input.user_id, now)?;

        // Cancel pending/approved/dispatched requests
        let cancelled_requests = self.request_repo.cancel_all_for_user(&input.user_id, now)?;

        // Audit
        self.audit.record(&AuditEvent::simple("user_disabled", "identity", &user.subject_id, Some(&input.user_id)))?;

        Ok(UserSuspendOutput {
            id: input.user_id,
            revoked_tokens,
            cancelled_requests,
        })
    }
}
