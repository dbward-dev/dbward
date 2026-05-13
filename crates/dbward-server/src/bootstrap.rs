use dbward_app::use_cases::token_manage::{TokenCreateInput, TokenManage};
use dbward_domain::auth::{AuthUser, Permission, ResolvedRole, SubjectType};
use dbward_domain::values::{DatabaseName, Environment};

use crate::state::AppState;

/// System-level AuthUser for bootstrap operations (bypasses normal auth).
fn system_user() -> AuthUser {
    AuthUser {
        subject_id: "system".into(),
        subject_type: SubjectType::User,
        roles: vec![ResolvedRole {
            name: "system".into(),
            permissions: [Permission::All].into_iter().collect(),
            databases: vec![DatabaseName::wildcard()],
            environments: vec![Environment::wildcard()],
        }],
        groups: vec![],
        token_id: None,
    }
}

pub fn create_bootstrap_token(
    state: &AppState,
    subject_id: &str,
    role: &str,
    is_agent: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let uc = TokenManage {
        authorizer: state.authorizer.clone(),
        token_repo: state.token_repo.clone(),
        user_repo: state.user_repo.clone(),
        policy_repo: state.policy_repo.clone(),
        license: state.license_checker.clone(),
        audit: state.audit_logger.clone(),
        clock: state.clock.clone(),
        id_gen: state.id_generator.clone(),
        token_gen: state.token_value_generator.clone(),
    };

    let subject_type = if is_agent { "agent" } else { "user" };
    let output = uc.create(
        TokenCreateInput {
            subject_id: subject_id.to_string(),
            subject_type: subject_type.to_string(),
            name: Some(format!("bootstrap-{subject_id}")),
            roles: vec![role.to_string()],
            groups: vec![],
            expires_at: None,
        },
        &system_user(),
    )?;

    Ok(output.token)
}
