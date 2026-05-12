pub mod background;
pub mod config;
pub mod metrics;
pub mod middleware;
pub mod routes;
pub mod state;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use axum::Router;
use state::AppState;
use tokio::time::Duration;

/// Entry point for the standalone binary.
pub async fn run_from_args(
    listen: &str,
    data: &str,
    config_path: &str,
    dev_bootstrap: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,dbward_server=debug".parse().unwrap()),
        )
        .init();

    // Load config
    let cfg = config::ServerConfig::load(std::path::Path::new(config_path))
        .map_err(|e| format!("config: {e}"))?;

    // Open SQLite (open already calls initialize internally)
    let conn = dbward_infra::sqlite::open(data)?;

    // Build infra implementations
    let token_repo = Arc::new(dbward_infra::sqlite::SqliteTokenRepo::new(conn.clone()));
    let user_repo = Arc::new(dbward_infra::sqlite::SqliteUserRepo::new(conn.clone()));
    let policy_repo = Arc::new(dbward_infra::sqlite::SqlitePolicyRepo::new(conn.clone()));
    let request_repo = Arc::new(dbward_infra::sqlite::SqliteRequestRepo::new(conn.clone()));
    let agent_repo = Arc::new(dbward_infra::sqlite::SqliteAgentRepo::new(conn.clone()));
    let webhook_repo = Arc::new(dbward_infra::sqlite::SqliteWebhookRepo::new(conn.clone()));
    let database_registry = Arc::new(dbward_infra::sqlite::SqliteDatabaseRegistry::new(conn.clone()));
    let audit_logger: Arc<dyn dbward_app::ports::AuditLogger> =
        Arc::new(dbward_infra::sqlite::SqliteAuditLogger::new(conn.clone()));
    let audit_repo = Arc::new(dbward_infra::sqlite::SqliteAuditRepo::new(conn.clone()));
    let policy_evaluator = Arc::new(dbward_infra::sqlite::SqlitePolicyEvaluator::new(conn.clone()));

    // Auth
    let token_verifier: Arc<dyn dbward_app::ports::TokenVerifier> = Arc::new(
        dbward_infra::auth::ApiTokenVerifier::new(
            token_repo.clone(),
            user_repo.clone(),
            policy_repo.clone(),
        ),
    );
    let role_resolver: Arc<dyn dbward_app::ports::RoleResolver> = Arc::new(
        dbward_infra::auth::ConfigRoleResolver::new(
            vec![],
            HashMap::new(),
            HashMap::new(),
            None,
        ),
    );
    let authorizer: Arc<dyn dbward_app::ports::Authorizer> = Arc::new(
        dbward_infra::auth::RbacAuthorizer,
    );

    // Result storage
    let result_store: Arc<dyn dbward_app::ports::ResultStore> = match cfg.result_storage.backend.as_str() {
        "s3" => Arc::new(dbward_infra::storage::S3ResultStore::new(
            cfg.result_storage.bucket.as_deref().unwrap_or("dbward"),
            cfg.result_storage.region.as_deref().unwrap_or("us-east-1"),
            cfg.result_storage.endpoint.as_deref(),
        )?),
        _ => Arc::new(dbward_infra::storage::LocalResultStore::new(&cfg.result_storage.root_dir)?),
    };

    // Services
    let data_path = std::path::Path::new(data);
    let data_dir = data_path.parent().unwrap_or(std::path::Path::new("."));
    let token_signer: Arc<dyn dbward_app::ports::TokenSigner> = Arc::new(
        dbward_infra::Ed25519TokenSigner::load_or_generate(data_dir)?,
    );
    let result_channel: Arc<dyn dbward_app::ports::ResultChannel> = Arc::new(
        dbward_infra::InMemoryResultChannel::new(),
    );
    let notifier: Arc<dyn dbward_app::ports::Notifier> = Arc::new(
        dbward_infra::webhook::WebhookDispatcher::new(vec![]),
    );
    let event_dispatcher: Arc<dyn dbward_app::ports::EventDispatcher> = Arc::new(
        dbward_infra::webhook::CompositeEventDispatcher {
            audit: audit_logger.clone(),
            notifier: notifier.clone(),
        },
    );
    let ssrf_validator: Arc<dyn dbward_app::ports::SsrfValidator> = Arc::new(
        dbward_infra::webhook::SsrfGuard,
    );
    let license_checker: Arc<dyn dbward_app::ports::LicenseChecker> = Arc::new(
        dbward_infra::LicenseCheckerImpl::new(dbward_domain::license::License::default()),
    );
    let clock: Arc<dyn dbward_app::ports::Clock> = Arc::new(dbward_infra::UtcClock);
    let id_generator: Arc<dyn dbward_app::ports::IdGenerator> = Arc::new(dbward_infra::UuidGenerator);

    let draining = Arc::new(AtomicBool::new(false));

    let state = AppState {
        token_verifier,
        role_resolver,
        authorizer,
        request_repo,
        agent_repo,
        user_repo,
        token_repo,
        webhook_repo,
        policy_repo,
        database_registry,
        audit_logger,
        audit_repo,
        policy_evaluator,
        result_store,
        result_channel,
        token_signer,
        notifier,
        event_dispatcher,
        ssrf_validator,
        license_checker,
        clock,
        id_generator,
        metrics: Arc::new(metrics::Metrics::new()),
        draining: draining.clone(),
    };

    // Dev bootstrap: create tokens and output to stdout
    if dev_bootstrap {
        register_databases(&conn, &cfg.databases)?;
        sync_workflows(&state, &cfg.workflows)?;

        let admin_token = create_bootstrap_token(&state, "admin", "admin", false)?;
        let dev_token = create_bootstrap_token(&state, "developer", "developer", false)?;
        let agent_token = create_bootstrap_token(&state, "agent", "admin", true)?;
        let tokens = serde_json::json!({
            "admin": admin_token,
            "developer": dev_token,
            "agent": agent_token,
        });
        println!("{}", serde_json::to_string(&tokens)?);
    } else {
        register_databases(&conn, &cfg.databases)?;
        sync_workflows(&state, &cfg.workflows)?;
    }

    let addr: std::net::SocketAddr = listen.parse()?;
    start(addr, state).await
}

fn register_databases(
    conn: &dbward_infra::sqlite::DbConn,
    databases: &[config::DatabaseDef],
) -> Result<(), Box<dyn std::error::Error>> {
    let c = conn.blocking_lock();
    for db in databases {
        for env in &db.environments {
            let id = format!("{}:{}", db.name, env);
            c.execute(
                "INSERT OR IGNORE INTO databases (id, name, environment, created_at) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![id, db.name, env, chrono::Utc::now().to_rfc3339()],
            )?;
        }
    }
    Ok(())
}

fn sync_workflows(
    state: &AppState,
    workflows: &[config::WorkflowDef],
) -> Result<(), Box<dyn std::error::Error>> {
    use dbward_domain::policies::Workflow;
    use dbward_domain::values::{DatabaseName, Environment};

    for (i, wf) in workflows.iter().enumerate() {
        let id = format!("config-wf-{i}");
        let db = if wf.database == "*" {
            DatabaseName::wildcard()
        } else {
            DatabaseName::new(&wf.database).map_err(|e| format!("workflow db: {e}"))?
        };
        let env = if wf.environment == "*" {
            Environment::wildcard()
        } else {
            Environment::new(&wf.environment).map_err(|e| format!("workflow env: {e}"))?
        };
        let workflow = Workflow {
            id,
            database: db,
            environment: env,
            operations: vec![],
            steps: vec![],
            skip_approval_for: vec![],
            require_reason: wf.require_reason,
            allow_self_approve: false,
            allow_same_approver_across_steps: false,
            pending_ttl_secs: None,
            approval_ttl_secs: None,
        };
        state.policy_repo.create_workflow(&workflow)?;
    }
    Ok(())
}

fn create_bootstrap_token(
    state: &AppState,
    subject_id: &str,
    role: &str,
    is_agent: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    use dbward_domain::auth::SubjectType;
    use dbward_domain::entities::{Token, TokenStatus};
    use sha2::{Digest, Sha256};

    let token_id = state.id_generator.generate();
    let raw_token = format!("dbw_{}", state.id_generator.generate().replace('-', ""));
    let token_hash = hex::encode(Sha256::digest(raw_token.as_bytes()));
    let token_prefix = raw_token[4..12].to_string();

    let token = Token {
        id: token_id,
        subject_type: if is_agent { SubjectType::Agent } else { SubjectType::User },
        subject_id: subject_id.to_string(),
        token_hash,
        token_prefix,
        roles: vec![role.to_string()],
        groups: vec![],
        name: Some(format!("bootstrap-{subject_id}")),
        status: TokenStatus::Active,
        expires_at: None,
        created_at: state.clock.now(),
        revoked_at: None,
    };
    state.token_repo.create(&token)?;
    Ok(raw_token)
}

pub fn build_app(state: AppState) -> Router {
    routes::build_router(state)
}

pub async fn start(addr: std::net::SocketAddr, state: AppState) -> Result<(), Box<dyn std::error::Error>> {
    let draining = state.draining.clone();
    let result_channel = state.result_channel.clone();

    // Startup recovery: warn about in-flight requests
    let dispatched = state.request_repo.count_by_status("dispatched").unwrap_or(0);
    let running = state.request_repo.count_by_status("running").unwrap_or(0);
    if dispatched > 0 || running > 0 {
        tracing::warn!(dispatched, running, "in-flight requests detected on startup");
    }

    // Spawn background tasks
    let bg_handle = background::spawn_background_tasks(state.clone(), draining.clone());

    let app = build_app(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "server started");

    let shutdown_fut = async move {
        wait_for_signal().await;
        tracing::info!("shutdown signal received, entering drain mode");
        draining.store(true, Ordering::SeqCst);
        result_channel.notify_all().await;
        tracing::info!("draining for 20 seconds...");
        tokio::time::sleep(Duration::from_secs(20)).await;
    };

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_fut)
        .await?;

    bg_handle.abort();
    tracing::info!("server stopped");
    Ok(())
}

async fn wait_for_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
        tokio::select! {
            _ = ctrl_c => {},
            _ = sigterm.recv() => {},
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.ok();
    }
}
