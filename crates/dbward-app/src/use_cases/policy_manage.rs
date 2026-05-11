use std::sync::Arc;

use dbward_domain::auth::{AuthUser, Permission, RoleDefinition};
use dbward_domain::entities::AuditEvent;
use dbward_domain::policies::{ExecutionPolicy, Workflow};

use crate::error::AppError;
use crate::ports::*;

pub struct PolicyManage {
    pub authorizer: Arc<dyn Authorizer>,
    pub policy_repo: Arc<dyn PolicyRepo>,
    pub license: Arc<dyn LicenseChecker>,
    pub audit: Arc<dyn AuditLogger>,
}

// --- Workflow ---

impl PolicyManage {
    pub fn create_workflow(&self, wf: Workflow, user: &AuthUser) -> Result<Workflow, AppError> {
        self.authorizer.authorize_global(user, Permission::WorkflowManage)
            .map_err(AppError::Forbidden)?;
        let count = self.policy_repo.count_workflows()?;
        if count >= self.license.max_workflows() {
            return Err(AppError::PlanLimit("workflow limit reached".into()));
        }
        self.policy_repo.create_workflow(&wf)?;
        self.audit.record(&AuditEvent::simple("policy_created", "policy", &user.subject_id, Some(&wf.id)))?;
        Ok(wf)
    }

    pub fn list_workflows(&self, user: &AuthUser) -> Result<Vec<Workflow>, AppError> {
        self.authorizer.authorize_global(user, Permission::WorkflowManage)
            .map_err(AppError::Forbidden)?;
        self.policy_repo.list_workflows()
    }

    pub fn delete_workflow(&self, id: &str, user: &AuthUser) -> Result<(), AppError> {
        self.authorizer.authorize_global(user, Permission::WorkflowManage)
            .map_err(AppError::Forbidden)?;
        let deleted = self.policy_repo.delete_workflow(id)?;
        if !deleted {
            return Err(AppError::NotFound("workflow not found".into()));
        }
        self.audit.record(&AuditEvent::simple("policy_deleted", "policy", &user.subject_id, Some(id)))?;
        Ok(())
    }

    // --- ExecutionPolicy ---

    pub fn create_execution_policy(&self, ep: ExecutionPolicy, user: &AuthUser) -> Result<ExecutionPolicy, AppError> {
        self.authorizer.authorize_global(user, Permission::PolicyManage)
            .map_err(AppError::Forbidden)?;
        self.policy_repo.create_execution_policy(&ep)?;
        self.audit.record(&AuditEvent::simple("policy_created", "policy", &user.subject_id, None))?;
        Ok(ep)
    }

    pub fn list_execution_policies(&self, user: &AuthUser) -> Result<Vec<ExecutionPolicy>, AppError> {
        self.authorizer.authorize_global(user, Permission::PolicyManage)
            .map_err(AppError::Forbidden)?;
        self.policy_repo.list_execution_policies()
    }

    pub fn delete_execution_policy(&self, id: &str, user: &AuthUser) -> Result<(), AppError> {
        self.authorizer.authorize_global(user, Permission::PolicyManage)
            .map_err(AppError::Forbidden)?;
        let deleted = self.policy_repo.delete_execution_policy(id)?;
        if !deleted {
            return Err(AppError::NotFound("execution policy not found".into()));
        }
        Ok(())
    }

    // --- Role ---

    pub fn create_role(&self, role: RoleDefinition, user: &AuthUser) -> Result<RoleDefinition, AppError> {
        self.authorizer.authorize_global(user, Permission::RoleManage)
            .map_err(AppError::Forbidden)?;
        if matches!(role.name.as_str(), "admin" | "agent-default") {
            return Err(AppError::Validation("cannot use built-in role name".into()));
        }
        let count = self.policy_repo.count_roles()?;
        if count >= self.license.max_roles() {
            return Err(AppError::PlanLimit("role limit reached".into()));
        }
        self.policy_repo.create_role(&role)?;
        self.audit.record(&AuditEvent::simple("policy_created", "policy", &user.subject_id, Some(&role.name)))?;
        Ok(role)
    }

    pub fn list_roles(&self, user: &AuthUser) -> Result<Vec<RoleDefinition>, AppError> {
        self.authorizer.authorize_global(user, Permission::RoleManage)
            .map_err(AppError::Forbidden)?;
        self.policy_repo.list_roles()
    }

    pub fn delete_role(&self, name: &str, user: &AuthUser) -> Result<(), AppError> {
        self.authorizer.authorize_global(user, Permission::RoleManage)
            .map_err(AppError::Forbidden)?;
        if matches!(name, "admin" | "agent-default") {
            return Err(AppError::Validation("cannot delete built-in role".into()));
        }
        let deleted = self.policy_repo.delete_role(name)?;
        if !deleted {
            return Err(AppError::NotFound("role not found".into()));
        }
        Ok(())
    }
}
