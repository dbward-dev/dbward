use dbward_app::use_cases::token_manage::{TokenCreateInput, TokenManage};
use dbward_domain::auth::AuthUser;

use crate::state::AppState;

/// System-level AuthUser for bootstrap operations (bypasses normal auth).
fn system_user() -> AuthUser {
    dbward_infra::token_admin::system_user()
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

/// Create a token directly from a SQLite database path (no running server needed).
pub fn create_token_standalone(
    data: &str,
    user: &str,
    role: &str,
    is_agent: bool,
    groups: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let output = dbward_infra::token_admin::create_token(data, user, role, is_agent, groups)?;

    let token_type = if is_agent { "agent" } else { "user" };
    println!("Token created:");
    println!("  ID:    {}", output.id);
    println!("  Token: {}", output.token);
    println!("  User:  {user}");
    println!("  Role:  {role}");
    println!("  Type:  {token_type}");
    println!();
    println!("Save this token \u{2014} it cannot be retrieved later.");
    Ok(())
}

/// Revoke a token directly from a SQLite database path (no running server needed).
pub fn revoke_token_standalone(
    data: &str,
    token_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    dbward_infra::token_admin::revoke_token(data, token_id)?;
    println!("Token revoked: {token_id}");
    Ok(())
}
