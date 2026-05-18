use std::sync::Arc;

use dbward_app::use_cases::token_manage::{TokenCreateInput, TokenManage, TokenRevokeInput};
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
        &dbward_domain::entities::AuditContext::System,
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
    license_key: Option<&str>,
    license_file: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let conn = dbward_infra::sqlite::open(data)?;

    let token_repo = Arc::new(dbward_infra::sqlite::SqliteTokenRepo::new(conn.clone()));
    let user_repo = Arc::new(dbward_infra::sqlite::SqliteUserRepo::new(conn.clone()));
    let policy_repo = Arc::new(dbward_infra::sqlite::SqlitePolicyRepo::new(conn.clone()));
    let audit_logger = Arc::new(dbward_infra::sqlite::SqliteAuditLogger::new(conn));

    let license = crate::resolve_license(license_key, license_file);
    let uc = TokenManage {
        authorizer: Arc::new(dbward_infra::auth::RbacAuthorizer),
        token_repo,
        user_repo,
        policy_repo,
        license: Arc::new(dbward_infra::LicenseCheckerImpl::new(license)),
        audit: audit_logger,
        clock: Arc::new(dbward_infra::UtcClock),
        id_gen: Arc::new(dbward_infra::UuidGenerator),
        token_gen: Arc::new(dbward_infra::SecureTokenGenerator),
    };

    let subject_type = if is_agent { "agent" } else { "user" };
    let output = uc.create(
        TokenCreateInput {
            subject_id: user.to_string(),
            subject_type: subject_type.to_string(),
            name: Some(format!("cli-{user}")),
            roles: vec![role.to_string()],
            groups: groups.to_vec(),
            expires_at: None,
        },
        &system_user(),
        &dbward_domain::entities::AuditContext::System,
    )?;

    let token_type = if is_agent { "agent" } else { "user" };
    println!("Token created:");
    println!("  ID:    {}", output.id);
    println!("  Token: {}", output.token);
    println!("  User:  {user}");
    println!("  Role:  {role}");
    println!("  Type:  {token_type}");
    println!();
    println!("Save this token — it cannot be retrieved later.");

    Ok(())
}

/// Revoke a token directly from a SQLite database path (no running server needed).
pub fn revoke_token_standalone(
    data: &str,
    token_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let conn = dbward_infra::sqlite::open(data)?;

    let token_repo = Arc::new(dbward_infra::sqlite::SqliteTokenRepo::new(conn.clone()));
    let user_repo = Arc::new(dbward_infra::sqlite::SqliteUserRepo::new(conn.clone()));
    let policy_repo = Arc::new(dbward_infra::sqlite::SqlitePolicyRepo::new(conn.clone()));
    let audit_logger = Arc::new(dbward_infra::sqlite::SqliteAuditLogger::new(conn));

    let uc = TokenManage {
        authorizer: Arc::new(dbward_infra::auth::RbacAuthorizer),
        token_repo,
        user_repo,
        policy_repo,
        license: Arc::new(dbward_infra::LicenseCheckerImpl::new(
            dbward_domain::license::License::default(),
        )),
        audit: audit_logger,
        clock: Arc::new(dbward_infra::UtcClock),
        id_gen: Arc::new(dbward_infra::UuidGenerator),
        token_gen: Arc::new(dbward_infra::SecureTokenGenerator),
    };

    uc.revoke(
        TokenRevokeInput {
            token_id: token_id.to_string(),
        },
        &system_user(),
        &dbward_domain::entities::AuditContext::System,
    )?;

    println!("Token revoked: {token_id}");
    Ok(())
}
