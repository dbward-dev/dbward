pub mod background;
pub mod bootstrap;
pub mod config;
pub mod metrics;
pub mod middleware;
pub mod routes;
pub mod state;
pub mod util;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::Router;
use dbward_app::ports::PolicyRepo;
use dbward_app::use_cases::sync_config::{
    ApproverInput, SyncConfig, WebhookInput, WorkflowInput, WorkflowStepInput,
};
use dbward_domain::values::{DatabaseName, Environment};
use state::AppState;
use tokio::time::Duration;

/// Entry point for the standalone binary.
pub async fn run_from_args(
    listen: &str,
    data: &str,
    config_path: &str,
    dev_bootstrap: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Load config (logging depends on it, so errors go to stderr)
    let cfg = match config::ServerConfig::load(std::path::Path::new(config_path)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("fatal: failed to load config '{}': {}", config_path, e);
            return Err(format!("config: {e}").into());
        }
    };

    // Logging: apply config, with RUST_LOG env override taking precedence
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        cfg.logging.level.parse().unwrap_or_else(|_| {
            eprintln!(
                "warning: invalid log level '{}', falling back to 'info'",
                cfg.logging.level
            );
            "info".parse().unwrap()
        })
    });
    match cfg.logging.format {
        config::LogFormat::Json => {
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(env_filter)
                .init();
        }
        config::LogFormat::Text => {
            tracing_subscriber::fmt().with_env_filter(env_filter).init();
        }
    }

    // Open SQLite (open already calls initialize internally)
    let conn = dbward_infra::sqlite::open(data)?;

    // Build infra implementations
    let token_repo = Arc::new(dbward_infra::sqlite::SqliteTokenRepo::new(conn.clone()));
    let user_repo = Arc::new(dbward_infra::sqlite::SqliteUserRepo::new(conn.clone()));
    let policy_repo = Arc::new(dbward_infra::sqlite::SqlitePolicyRepo::new(conn.clone()));
    let request_repo = Arc::new(dbward_infra::sqlite::SqliteRequestRepo::new(conn.clone()));
    let agent_repo = Arc::new(dbward_infra::sqlite::SqliteAgentRepo::new(conn.clone()));
    let webhook_repo = Arc::new(dbward_infra::sqlite::SqliteWebhookRepo::new(conn.clone()));
    let database_registry = Arc::new(dbward_infra::sqlite::SqliteDatabaseRegistry::new(
        conn.clone(),
    ));
    let audit_logger: Arc<dyn dbward_app::ports::AuditLogger> =
        Arc::new(dbward_infra::sqlite::SqliteAuditLogger::new(conn.clone()));
    let audit_repo = Arc::new(dbward_infra::sqlite::SqliteAuditRepo::new(conn.clone()));
    let policy_evaluator = Arc::new(dbward_infra::sqlite::SqlitePolicyEvaluator::new(
        conn.clone(),
    ));

    // Auth
    let mut token_verifier_impl = dbward_infra::auth::ApiTokenVerifier::new(
        token_repo.clone(),
        user_repo.clone(),
        policy_repo.clone(),
    );

    // C-10: Inject OIDC verifier if configured
    if (cfg.auth.mode == "oidc" || cfg.auth.mode == "both")
        && let Some(ref oidc_cfg) = cfg.auth.oidc
    {
        let oidc = dbward_infra::auth::OidcVerifier::new(
            oidc_cfg.issuer_url.clone(),
            oidc_cfg
                .client_id
                .clone()
                .unwrap_or_else(|| oidc_cfg.audience.clone()),
            "groups".to_string(),
            oidc_cfg.jwks_uri.clone(),
        );
        token_verifier_impl = token_verifier_impl.with_oidc(oidc);
    }

    let token_verifier: Arc<dyn dbward_app::ports::TokenVerifier> = Arc::new(token_verifier_impl);
    let role_resolver: Arc<dyn dbward_app::ports::RoleResolver> = Arc::new({
        // H-31: Build bindings from config
        let mut group_bindings: HashMap<String, Vec<String>> = HashMap::new();
        let mut user_bindings: HashMap<String, Vec<String>> = HashMap::new();
        for rb in &cfg.auth.role_bindings {
            for group in &rb.groups {
                group_bindings
                    .entry(group.clone())
                    .or_default()
                    .push(rb.role.clone());
            }
            for subject in &rb.subjects {
                user_bindings
                    .entry(subject.clone())
                    .or_default()
                    .push(rb.role.clone());
            }
        }
        // Also include OIDC role_mappings (group → role)
        if let Some(ref oidc_cfg) = cfg.auth.oidc {
            for mapping in &oidc_cfg.role_mappings {
                if mapping.claim == "groups" {
                    group_bindings
                        .entry(mapping.value.clone())
                        .or_default()
                        .push(mapping.role.clone());
                }
            }
        }
        dbward_infra::auth::ConfigRoleResolver::with_policy_repo(
            vec![],
            group_bindings,
            user_bindings,
            cfg.auth.default_role.clone(),
            Some(policy_repo.clone()),
        )
    });
    let authorizer: Arc<dyn dbward_app::ports::Authorizer> =
        Arc::new(dbward_infra::auth::RbacAuthorizer);

    // H-31: Validate role_bindings role names at startup
    for binding in &cfg.auth.role_bindings {
        if policy_repo
            .get_roles_by_names(std::slice::from_ref(&binding.role))
            .map_or(true, |v| v.is_empty())
        {
            tracing::warn!(role = %binding.role, "role_binding references undefined role; it will be ignored at runtime");
        }
    }
    if let Some(ref oidc_cfg) = cfg.auth.oidc {
        for mapping in &oidc_cfg.role_mappings {
            if policy_repo
                .get_roles_by_names(std::slice::from_ref(&mapping.role))
                .map_or(true, |v| v.is_empty())
            {
                tracing::warn!(role = %mapping.role, "oidc.role_mappings references undefined role; it will be ignored at runtime");
            }
        }
    }
    if let Some(ref default) = cfg.auth.default_role
        && policy_repo
            .get_roles_by_names(std::slice::from_ref(default))
            .map_or(true, |v| v.is_empty())
    {
        tracing::warn!(role = %default, "default_role references undefined role");
    }

    // Result storage
    let result_store: Arc<dyn dbward_app::ports::ResultStore> =
        match cfg.result_storage.backend.as_str() {
            "s3" => Arc::new(dbward_infra::storage::S3ResultStore::new(
                cfg.result_storage.bucket.as_deref().unwrap_or("dbward"),
                cfg.result_storage.region.as_deref().unwrap_or("us-east-1"),
                cfg.result_storage.endpoint.as_deref(),
            )?),
            _ => Arc::new(dbward_infra::storage::LocalResultStore::new(
                &cfg.result_storage.root_dir,
            )?),
        };

    // Services
    let data_path = std::path::Path::new(data);
    let data_dir = data_path.parent().unwrap_or(std::path::Path::new("."));
    let token_signer: Arc<dyn dbward_app::ports::TokenSigner> = Arc::new(
        dbward_infra::Ed25519TokenSigner::load_or_generate(data_dir)?,
    );
    // M-11: Persist public key for external verification
    let pub_key_path = data_dir.join("signing.pub");
    std::fs::write(&pub_key_path, token_signer.public_key_hex())?;

    let result_channel: Arc<dyn dbward_app::ports::ResultChannel> =
        Arc::new(dbward_infra::InMemoryResultChannel::new(
            cfg.result_channel.max_slots,
            cfg.result_channel.slot_ttl_secs,
        ));
    let clock: Arc<dyn dbward_app::ports::Clock> = Arc::new(dbward_infra::UtcClock);
    let id_generator: Arc<dyn dbward_app::ports::IdGenerator> =
        Arc::new(dbward_infra::UuidGenerator);
    let webhook_delivery_repo: Arc<dyn dbward_app::ports::WebhookDeliveryRepo> = Arc::new(
        dbward_infra::sqlite::SqliteWebhookDeliveryRepo::new(conn.clone()),
    );
    let dispatcher = Arc::new(
        dbward_infra::webhook::WebhookDispatcher::with_repo(webhook_repo.clone())
            .with_delivery_repo(webhook_delivery_repo.clone(), id_generator.clone()),
    );
    let webhook_sender: Arc<dyn dbward_app::ports::WebhookSender> = dispatcher.clone();
    let notifier: Arc<dyn dbward_app::ports::Notifier> = dispatcher;
    // Load initial webhooks from DB
    if let Err(e) = notifier.reload() {
        tracing::warn!("failed to load webhooks on startup: {e}");
    }
    let event_dispatcher: Arc<dyn dbward_app::ports::EventDispatcher> =
        Arc::new(dbward_infra::webhook::CompositeEventDispatcher {
            audit: audit_logger.clone(),
            notifier: notifier.clone(),
            result_channel: Some(result_channel.clone()),
            request_notifier: None,
            redaction_mode: match cfg.audit.redaction.as_str() {
                "none" => dbward_infra::webhook::RedactionMode::None,
                "full" => dbward_infra::webhook::RedactionMode::Full,
                _ => dbward_infra::webhook::RedactionMode::Literals,
            },
            clock: clock.clone(),
        });
    let ssrf_validator: Arc<dyn dbward_app::ports::SsrfValidator> =
        Arc::new(dbward_infra::webhook::SsrfGuard);
    let license_checker: Arc<dyn dbward_app::ports::LicenseChecker> = Arc::new(
        dbward_infra::LicenseCheckerImpl::new(dbward_domain::license::License::default()),
    );
    let token_value_generator: Arc<dyn dbward_app::ports::TokenValueGenerator> =
        Arc::new(dbward_infra::SecureTokenGenerator);

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
        webhook_sender,
        event_dispatcher,
        ssrf_validator,
        license_checker,
        clock,
        id_generator,
        token_value_generator,
        webhook_delivery_repo: Some(webhook_delivery_repo),
        metrics: Arc::new(metrics::Metrics::new()),
        default_approval_ttl_secs: Some(cfg.retention.approval_ttl_secs),
        max_persist_bytes: cfg.result_storage.max_persist_bytes,
        auth_mode: cfg.auth.mode.clone(),
        draining: draining.clone(),
    };

    // Dev bootstrap: create tokens and output to stdout
    if dev_bootstrap {
        register_databases(&state, &cfg.databases)?;
        sync_workflows(&state, &cfg.workflows)?;

        let data_dir = std::path::Path::new(data)
            .parent()
            .unwrap_or(std::path::Path::new("."));
        let agent_token_path = data_dir.join("agent-token");

        // Idempotent: skip if already bootstrapped
        if agent_token_path.exists() {
            eprintln!("[bootstrap] tokens already exist, skipping creation");
        } else {
            let admin_token = bootstrap::create_bootstrap_token(&state, "admin", "admin", false)?;
            let dev_token =
                bootstrap::create_bootstrap_token(&state, "developer", "developer", false)?;
            let agent_token = bootstrap::create_bootstrap_token(&state, "agent", "admin", true)?;
            let tokens = serde_json::json!({
                "admin": admin_token,
                "developer": dev_token,
                "agent": agent_token,
            });
            println!("{}", serde_json::to_string(&tokens)?);

            // Write agent token to file for Docker agent container
            std::fs::write(&agent_token_path, &agent_token)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(
                    &agent_token_path,
                    std::fs::Permissions::from_mode(0o600),
                )?;
            }
        }
    } else {
        register_databases(&state, &cfg.databases)?;
        sync_workflows(&state, &cfg.workflows)?;
    }

    // BUG-28: Sync webhooks from config
    sync_webhooks(&state, &cfg.webhooks)?;

    // BUG-31: OIDC verifier initialized above (injected into ApiTokenVerifier)

    let addr: std::net::SocketAddr = listen.parse()?;

    // Parse trusted_proxies at startup (fail fast on invalid config)
    let trusted = middleware::trusted_proxies::parse_trusted_proxies(&cfg.trusted_proxies)
        .map_err(|e| format!("trusted_proxies config: {e}"))?;

    start(addr, state, cfg.retention, trusted).await
}

fn register_databases(
    state: &AppState,
    databases: &[config::DatabaseDef],
) -> Result<(), Box<dyn std::error::Error>> {
    for db in databases {
        for env in &db.environments {
            let db_name = DatabaseName::new(&db.name).map_err(|e| format!("database name: {e}"))?;
            let environment = Environment::new(env).map_err(|e| format!("environment: {e}"))?;
            state.database_registry.register(&db_name, &environment)?;
        }
    }
    Ok(())
}

fn sync_workflows(
    state: &AppState,
    workflows: &[config::WorkflowDef],
) -> Result<(), Box<dyn std::error::Error>> {
    let uc = SyncConfig {
        policy_repo: state.policy_repo.clone(),
        webhook_repo: state.webhook_repo.clone(),
        clock: state.clock.clone(),
        id_gen: state.id_generator.clone(),
    };

    let inputs: Vec<WorkflowInput> = workflows
        .iter()
        .map(|wf| WorkflowInput {
            database: wf.database.clone(),
            environment: wf.environment.clone(),
            operations: wf.operations.clone(),
            steps: wf
                .steps
                .iter()
                .map(|step_val| {
                    let mode = step_val
                        .get("mode")
                        .and_then(|m| m.as_str())
                        .unwrap_or("all")
                        .to_string();
                    let approvers = step_val
                        .get("approvers")
                        .and_then(|a| a.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|a| {
                                    let min =
                                        a.get("min").and_then(|m| m.as_u64()).unwrap_or(1) as u32;
                                    let (selector_type, value) = if let Some(role) =
                                        a.get("role").and_then(|r| r.as_str())
                                    {
                                        ("role", role)
                                    } else if let Some(group) =
                                        a.get("group").and_then(|g| g.as_str())
                                    {
                                        ("group", group)
                                    } else if let Some(user) =
                                        a.get("user").and_then(|u| u.as_str())
                                    {
                                        ("user", user)
                                    } else {
                                        return None;
                                    };
                                    Some(ApproverInput {
                                        selector_type: selector_type.to_string(),
                                        value: value.to_string(),
                                        min,
                                    })
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    WorkflowStepInput { mode, approvers }
                })
                .collect(),
            skip_approval_for: wf.skip_approval_for.clone(),
            require_reason: wf.require_reason,
            allow_self_approve: wf.allow_self_approve,
            allow_same_approver_across_steps: wf.allow_same_approver_across_steps,
            pending_ttl_secs: wf.pending_ttl_secs,
            statement_timeout_secs: wf.statement_timeout_secs,
        })
        .collect();

    uc.sync_workflows(inputs)?;
    Ok(())
}

fn sync_webhooks(
    state: &AppState,
    webhooks: &[config::WebhookDef],
) -> Result<(), Box<dyn std::error::Error>> {
    let uc = SyncConfig {
        policy_repo: state.policy_repo.clone(),
        webhook_repo: state.webhook_repo.clone(),
        clock: state.clock.clone(),
        id_gen: state.id_generator.clone(),
    };

    let inputs: Vec<WebhookInput> = webhooks
        .iter()
        .map(|wh| WebhookInput {
            url: wh.url.clone(),
            events: wh.events.clone(),
            format: wh.format.clone(),
            secret: wh.secret.clone(),
        })
        .collect();

    uc.sync_webhooks(inputs)?;

    // Reload notifier to pick up new webhooks
    if let Err(e) = state.notifier.reload() {
        tracing::warn!("failed to reload webhooks after sync: {e}");
    }
    Ok(())
}

pub fn build_app(state: AppState, trusted: Vec<ipnet::IpNet>) -> Router {
    let trusted_proxies = middleware::trusted_proxies::TrustedProxies(trusted);
    routes::build_router(state).layer(axum::middleware::from_fn_with_state(
        trusted_proxies,
        middleware::trusted_proxies::resolve_client_ip,
    ))
}

pub async fn start(
    addr: std::net::SocketAddr,
    state: AppState,
    retention: config::RetentionConfig,
    trusted: Vec<ipnet::IpNet>,
) -> Result<(), Box<dyn std::error::Error>> {
    let draining = state.draining.clone();
    let result_channel = state.result_channel.clone();

    // Startup recovery: warn about in-flight requests
    let dispatched = state
        .request_repo
        .count_by_status("dispatched")
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, "failed to count dispatched requests on startup");
            0
        });
    let running = state
        .request_repo
        .count_by_status("running")
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, "failed to count running requests on startup");
            0
        });
    if dispatched > 0 || running > 0 {
        tracing::warn!(
            dispatched,
            running,
            "in-flight requests detected on startup"
        );
    }

    // Spawn background tasks
    let (bg_shutdown, mut bg_set) =
        background::spawn_background_tasks(state.clone(), draining.clone(), retention);

    let app = build_app(state, trusted);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "server started");

    let shutdown_fut = async move {
        wait_for_signal().await;
        tracing::info!("shutdown signal received, entering drain mode");
        draining.store(true, Ordering::SeqCst);
        bg_shutdown.cancel();
        result_channel.notify_all().await;
        tracing::info!("draining for 20 seconds...");
        tokio::time::sleep(Duration::from_secs(20)).await;
    };

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_fut)
    .await?;

    // Collect background task results (detect panics)
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while let Ok(Some(result)) = tokio::time::timeout_at(deadline, bg_set.join_next()).await {
        if let Err(e) = result {
            tracing::error!(error = %e, "background task panicked");
        }
    }
    bg_set.abort_all();
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
