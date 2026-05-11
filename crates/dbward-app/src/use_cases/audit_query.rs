use std::sync::Arc;

use dbward_domain::auth::{AuthUser, Permission};
use dbward_domain::entities::AuditEvent;

use crate::error::AppError;
use crate::ports::*;

pub struct AuditQuery {
    pub authorizer: Arc<dyn Authorizer>,
    pub audit_repo: Arc<dyn AuditRepo>,
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
    pub fn list(&self, input: AuditListInput, user: &AuthUser) -> Result<AuditListOutput, AppError> {
        // audit.view_all → all events; audit.view → own events only
        let has_view_all = self.authorizer.authorize_global(user, Permission::AuditViewAll).is_ok();
        if !has_view_all {
            self.authorizer.authorize_global(user, Permission::AuditView)
                .map_err(AppError::Forbidden)?;
        }

        let mut filter = input.filter;
        if !has_view_all {
            // Force filter to own events only
            filter.actor_id = Some(user.subject_id.clone());
        }

        let mut events = self.audit_repo.list(&filter)?;

        // Redact detail_raw for non-admin viewers
        if !has_view_all {
            for event in &mut events {
                event.detail_raw = None;
            }
        }

        Ok(AuditListOutput { events })
    }

    pub fn verify(&self, user: &AuthUser) -> Result<AuditVerifyOutput, AppError> {
        self.authorizer.authorize_global(user, Permission::AuditViewAll)
            .map_err(AppError::Forbidden)?;
        let result = self.audit_repo.verify_chain()?;
        Ok(AuditVerifyOutput {
            total_events: result.total_events,
            first_broken_id: result.first_broken_id,
        })
    }
}
