use std::path::Path;

use dbward_app::use_cases::token_manage::TokenCreateInput;
use dbward_domain::auth::{AuthUser, Permission, ResolvedRole, SubjectType};
use dbward_domain::entities::TokenStatus;
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
    let uc = state.tokens().manage();

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

/// Auto-bootstrap: on first startup, create DB + signing key + tokens.
/// Does NOT exit. Does NOT print tokens to stdout (file only).
pub fn auto_bootstrap(
    state: &AppState,
    state_dir: &Path,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let token_repo = state.token_repo();
    let agent_token_path = state_dir.join("agent-token");
    let admin_token_path = state_dir.join("admin-token");

    // Count active bootstrap tokens
    let existing: Vec<_> = token_repo
        .list()?
        .into_iter()
        .filter(|t| {
            t.name
                .as_deref()
                .is_some_and(|n| n.starts_with("bootstrap-"))
                && t.status == TokenStatus::Active
        })
        .collect();
    let count = existing.len();

    if force {
        // Revoke all existing bootstrap tokens
        let now = chrono::Utc::now();
        for t in &existing {
            token_repo.revoke(&t.id, now)?;
        }
        if count > 0 {
            eprintln!("[init] existing bootstrap tokens revoked ({count})");
        }
    } else if count == 3 {
        // Fully bootstrapped — verify token files exist
        let dev_token_path = state_dir.join("developer-token");
        let missing: Vec<_> = [&agent_token_path, &admin_token_path, &dev_token_path]
            .iter()
            .filter(|p| !p.exists())
            .map(|p| p.display().to_string())
            .collect();
        if !missing.is_empty() {
            return Err(format!(
                "bootstrap token file(s) missing: {}\n  \
                 Tokens exist in DB but files are not recoverable (SHA-256 hash only stored).\n  \
                 Run with --force-bootstrap to revoke existing tokens and generate new ones.",
                missing.join(", ")
            )
            .into());
        }
        // Warn about legacy agent tokens with overprivileged roles
        let bad_agents: Vec<_> = existing
            .iter()
            .filter(|t| {
                t.subject_type == dbward_domain::auth::SubjectType::Agent
                    && t.roles != vec!["agent-default".to_string()]
            })
            .collect();
        for t in &bad_agents {
            eprintln!(
                "[security] WARNING: agent token prefix={} subject_id={} has roles {:?} (expected [\"agent-default\"]). \
                 Revoke with --force-bootstrap or DELETE /api/tokens/{}",
                t.token_prefix, t.subject_id, t.roles, t.id
            );
        }
        return Ok(());
    } else if count > 0 {
        // Partial state (1-2 tokens) — fail-closed
        return Err(format!(
            "incomplete bootstrap state: {count}/3 tokens found.\n  \
             Run with --force-bootstrap to reset and regenerate tokens."
        )
        .into());
    }

    // Create bootstrap tokens
    let admin_token = create_bootstrap_token(state, "admin", "admin", false)?;
    let dev_token = create_bootstrap_token(state, "developer", "developer", false)?;
    let agent_token = create_bootstrap_token(state, "agent", "agent-default", true)?;

    // Write token files (0600)
    write_token_file(&admin_token_path, &admin_token)?;
    write_token_file(&agent_token_path, &agent_token)?;

    // Also write developer token for dev convenience
    let dev_token_path = state_dir.join("developer-token");
    write_token_file(&dev_token_path, &dev_token)?;

    eprintln!(
        "[init] bootstrap tokens written to {}, {}",
        admin_token_path.display(),
        agent_token_path.display()
    );

    Ok(())
}

fn write_token_file(path: &Path, token: &str) -> std::io::Result<()> {
    use std::io::Write;
    // Atomic: write to temp file then rename to prevent partial reads
    let tmp_path = path.with_extension("tmp");
    {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp_path)?;
            f.write_all(token.as_bytes())?;
            f.sync_all()?;
        }
        #[cfg(not(unix))]
        {
            let mut f = std::fs::File::create(&tmp_path)?;
            f.write_all(token.as_bytes())?;
            f.sync_all()?;
        }
    }
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}
