//! Standalone token administration — shared by CLI and server binary.

use std::sync::Arc;

use dbward_app::use_cases::token_manage::{
    TokenCreateInput, TokenCreateOutput, TokenManage, TokenRevokeInput,
};
use dbward_domain::auth::{AuthUser, Permission, ResolvedRole, SubjectType};
use dbward_domain::values::{DatabaseName, Environment};

use crate::auth::RbacAuthorizer;
use crate::sqlite::{SqliteAuditLogger, SqlitePolicyRepo, SqliteTokenRepo, SqliteUserRepo};
use crate::{LicenseCheckerImpl, SecureTokenGenerator, UtcClock, UuidGenerator};

/// Build a `TokenManage` use case from a SQLite database path.
pub fn open(data: &str) -> Result<TokenManage, Box<dyn std::error::Error>> {
    let conn = crate::sqlite::open(data)?;
    Ok(TokenManage {
        authorizer: Arc::new(RbacAuthorizer),
        token_repo: Arc::new(SqliteTokenRepo::new(conn.clone())),
        user_repo: Arc::new(SqliteUserRepo::new(conn.clone())),
        policy_repo: Arc::new(SqlitePolicyRepo::new(conn.clone())),
        license: Arc::new(LicenseCheckerImpl::new(
            dbward_domain::license::License::default(),
        )),
        audit: Arc::new(SqliteAuditLogger::new(conn)),
        clock: Arc::new(UtcClock),
        id_gen: Arc::new(UuidGenerator),
        token_gen: Arc::new(SecureTokenGenerator),
    })
}

/// System-level user that bypasses all authorization checks.
pub fn system_user() -> AuthUser {
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

/// Create a token and return the output.
pub fn create_token(
    data: &str,
    user: &str,
    role: &str,
    is_agent: bool,
    groups: &[String],
) -> Result<TokenCreateOutput, Box<dyn std::error::Error>> {
    let uc = open(data)?;
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
    )?;
    Ok(output)
}

/// Revoke a token by ID.
pub fn revoke_token(data: &str, token_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    let uc = open(data)?;
    uc.revoke(
        TokenRevokeInput {
            token_id: token_id.to_string(),
        },
        &system_user(),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_token_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let output = create_token(db_path.to_str().unwrap(), "alice", "admin", false, &[]).unwrap();
        assert!(!output.id.is_empty());
        assert!(output.token.starts_with("dbw_"));
        assert_eq!(output.subject_id, "alice");
    }

    #[test]
    fn create_agent_token() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let output = create_token(
            db_path.to_str().unwrap(),
            "agent1",
            "admin",
            true,
            &["backend".to_string()],
        )
        .unwrap();
        assert!(output.token.starts_with("dbw_"));
    }

    #[test]
    fn revoke_nonexistent_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let _ = open(db_path.to_str().unwrap()).unwrap();
        let result = revoke_token(db_path.to_str().unwrap(), "nonexistent");
        assert!(result.is_err());
    }
}
