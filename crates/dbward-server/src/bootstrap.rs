use std::path::Path;

use sha2::{Digest, Sha256};

use dbward_domain::auth::SubjectType;
use dbward_domain::entities::TokenStatus;

use crate::state::AppState;

pub fn create_bootstrap_token(
    state: &AppState,
    subject_id: &str,
    role: &str,
    is_agent: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let subject_type = if is_agent {
        SubjectType::Agent
    } else {
        SubjectType::User
    };

    // scope_ceiling: explicit role for user tokens, None for agent tokens.
    let scope_ceiling = if is_agent {
        None
    } else {
        Some(dbward_domain::entities::ScopeCeiling {
            roles: vec![role.to_string()],
        })
    };

    // Generate token value directly (bypass UC to avoid "other user" hard-403)
    let raw = state.token_value_generator().generate_token_value();
    let prefix = dbward_domain::entities::Token::extract_prefix(&raw);
    let hash = hex::encode(Sha256::digest(raw.as_bytes()));

    let now = state.clock().now();
    let id = state.id_gen().generate();

    let token = dbward_domain::entities::Token {
        id: id.clone(),
        subject_id: subject_id.to_string(),
        subject_type,
        token_hash: hash,
        token_prefix: prefix,
        scope_ceiling: scope_ceiling.clone(),
        name: Some(format!("bootstrap-{subject_id}")),
        status: TokenStatus::Active,
        provisioning_kind: Some(dbward_domain::entities::ProvisioningKind::Bootstrap),
        expires_at: None,
        revoked_at: None,
        created_at: now,
    };

    let metadata = serde_json::json!({
        "issued_by": "system",
        "issued_for": subject_id,
        "scope_ceiling": scope_ceiling,
    });

    let mut audit_event = dbward_domain::entities::AuditEvent::simple(
        "token.created",
        "token",
        "system",
        Some(&id),
        now,
        &dbward_domain::entities::AuditContext::System,
    );
    audit_event.metadata_json = metadata.to_string();

    state.uow().execute(Box::new(move |tx| {
        tx.create_token(&token)?;
        tx.record(&audit_event)?;
        Ok(())
    }))?;

    Ok(raw)
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
    } else if count == 2 {
        // Fully bootstrapped — verify token files exist
        let requester_token_path = state_dir.join("requester-token");
        let missing: Vec<_> = [&agent_token_path, &admin_token_path, &requester_token_path]
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
        // Warn about legacy agent tokens with unexpected scope_ceiling
        let bad_agents: Vec<_> = existing
            .iter()
            .filter(|t| {
                if t.subject_type != dbward_domain::auth::SubjectType::Agent {
                    return false;
                }
                match &t.scope_ceiling {
                    None => false,                                                      // valid
                    Some(sc) if sc.roles == vec!["agent-default".to_string()] => false, // valid
                    _ => true, // unexpected
                }
            })
            .collect();
        for t in &bad_agents {
            eprintln!(
                "[security] WARNING: agent token prefix={} subject_id={} has unexpected scope_ceiling {:?} (expected None or [\"agent-default\"]). \
                 Revoke with --force-bootstrap or DELETE /api/tokens/{}",
                t.token_prefix, t.subject_id, t.scope_ceiling, t.id
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

    // --- V25: Insert bootstrap users into DB (idempotent) ---
    let user_repo = state.user_repo();
    let now = chrono::Utc::now();
    let bootstrap_users = [
        ("admin", vec!["admin".to_string(), "requester".to_string()]),
        ("agent", vec!["agent-default".to_string()]),
    ];
    for (id, roles) in &bootstrap_users {
        let user = dbward_domain::entities::User {
            id: id.to_string(),
            display_name: None,
            email: None,
            groups: vec![],
            roles: roles.clone(),
            status: dbward_domain::entities::UserStatus::Active,
            last_seen_at: None,
            created_at: now,
            updated_at: now,
        };
        // INSERT OR IGNORE equivalent: only insert if not exists
        if user_repo.get(id)?.is_none() {
            user_repo.upsert(&user)?;
        }
    }

    // Create bootstrap tokens
    let admin_token = create_bootstrap_token(state, "admin", "admin", false)?;
    let agent_token = create_bootstrap_token(state, "agent", "agent-default", true)?;

    // Write token files (0600)
    write_token_file(&admin_token_path, &admin_token)?;
    write_token_file(&agent_token_path, &agent_token)?;

    // Also write requester token for dev convenience
    let requester_token_path = state_dir.join("requester-token");
    write_token_file(&requester_token_path, &admin_token)?;

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
