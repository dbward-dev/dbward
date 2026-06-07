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

use arc_swap::ArcSwap;
use axum::Router;
use config::{AutoApproveExt, SqlReviewExt};
use dbward_app::ports::ResultStore;
use dbward_app::use_cases::sync_config::{
    ApproverInput, DatabaseInput, ExecutionPolicyInput, GroupInput, NotificationPolicyInput,
    ResultPolicyInput, RoleBindingInput, RoleInput, SyncConfig, UserInput, WebhookInput,
    WorkflowInput, WorkflowStepInput,
};
use dbward_domain::values::{DatabaseName, Environment};

/// Convert a TOML RoleConfig into a domain RoleDefinition.
fn build_role_definition(
    rc: &dbward_config::server::RoleConfig,
) -> dbward_domain::auth::RoleDefinition {
    let perms: Vec<dbward_domain::auth::Permission> = rc
        .permissions
        .iter()
        .map(|s| {
            s.parse()
                .unwrap_or_else(|_| panic!("invalid permission '{}' in role '{}'", s, rc.name))
        })
        .collect();
    let databases = if rc.databases.is_empty() {
        vec![DatabaseName::new("*").unwrap()]
    } else {
        rc.databases
            .iter()
            .map(|d| DatabaseName::new(d).unwrap())
            .collect()
    };
    let environments = if rc.environments.is_empty() {
        vec![Environment::new("*").unwrap()]
    } else {
        rc.environments
            .iter()
            .map(|e| Environment::new(e).unwrap())
            .collect()
    };
    dbward_domain::auth::RoleDefinition {
        name: rc.name.clone(),
        permissions: perms,
        databases,
        environments,
    }
}
use state::AppState;
use tokio::time::Duration;

/// Entry point for the standalone binary.
pub async fn run_from_args(
    listen: &str,
    config_path: &str,
    force_bootstrap: bool,
    license_key: Option<&str>,
    license_file: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Load config (logging depends on it, so errors go to stderr)
    let cfg = match config::ServerConfig::load(std::path::Path::new(config_path)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("fatal: failed to load config '{}': {}", config_path, e);
            return Err(format!("config: {e}").into());
        }
    };

    // Resolve state_dir relative to config file parent
    let config_dir = std::path::Path::new(config_path)
        .parent()
        .unwrap_or(std::path::Path::new("."));
    let state_dir = if std::path::Path::new(&cfg.state_dir).is_absolute() {
        std::path::PathBuf::from(&cfg.state_dir)
    } else {
        config_dir.join(&cfg.state_dir)
    };
    std::fs::create_dir_all(&state_dir)?;
    let db_path = state_dir.join("dbward.db");

    // Write PID file for `dbward server reload`
    std::fs::write(state_dir.join("server.pid"), std::process::id().to_string())?;

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
    let conn = dbward_infra::sqlite::open(db_path.to_str().unwrap_or("dbward.db"))?;

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
    let schema_repo = Arc::new(dbward_infra::sqlite::SqliteSchemaRepo::new(conn.clone()));
    let dry_run_repo = Arc::new(dbward_infra::sqlite::SqliteDryRunRepo::new(conn.clone()));
    let context_repo = Arc::new(dbward_infra::sqlite::SqliteContextRepo::new(conn.clone()));
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

    // token_verifier is finalized after OIDC injection below
    let initial_reloadable = build_reloadable_config_with(&cfg, Some(policy_repo.clone()))
        .map_err(|e| format!("config: {e}"))?;
    let role_resolver = initial_reloadable.role_resolver.clone();
    let authorizer: Arc<dyn dbward_app::ports::Authorizer> =
        Arc::new(dbward_infra::auth::RbacAuthorizer);

    // Role sync handled by sync_all_config below

    // Role validation now handled by config validate() (fail-fast)

    // Result storage
    let result_store: Arc<dyn dbward_app::ports::ResultStore> =
        match cfg.result_storage.backend.as_str() {
            "s3" => {
                let s3_store =
                    dbward_infra::storage::S3ResultStore::new(dbward_infra::storage::S3Config {
                        bucket: cfg
                            .result_storage
                            .bucket
                            .clone()
                            .unwrap_or_else(|| "dbward".into()),
                        region: cfg
                            .result_storage
                            .region
                            .clone()
                            .unwrap_or_else(|| "us-east-1".into()),
                        endpoint: cfg.result_storage.endpoint.clone(),
                        access_key_id: cfg.result_storage.access_key_id.clone(),
                        secret_access_key: cfg.result_storage.secret_access_key.clone(),
                        path_style: cfg.result_storage.path_style,
                        prefix: cfg.result_storage.prefix.clone(),
                    })?;
                s3_store.health_check().await?;
                Arc::new(s3_store)
            }
            _ => {
                let root_dir = match cfg.result_storage.root_dir {
                    Some(ref p) => config_dir.join(p),
                    None => state_dir.join("results"),
                };
                Arc::new(dbward_infra::storage::LocalResultStore::new(
                    root_dir.to_str().unwrap_or("results"),
                )?)
            }
        };

    // Services
    let token_signer: Arc<dyn dbward_app::ports::TokenSigner> = Arc::new(
        dbward_infra::Ed25519TokenSigner::load_or_generate(&state_dir)?,
    );
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
    // Slack integration (opt-in: only if [slack] config section exists)
    let slack_config = cfg.slack.as_ref().and_then(|s| {
        if s.signing_secret.trim().is_empty() {
            tracing::error!("slack.signing_secret is empty — disabling Slack integration");
            None
        } else {
            Some(dbward_infra::slack::SlackConfig {
                bot_token: s.bot_token.clone(),
                signing_secret: s.signing_secret.clone(),
                default_channel: s.channel.clone(),
                channel_overrides: s.channels.clone(),
            })
        }
    });

    let slack_notifier: Option<Arc<dyn dbward_app::ports::Notifier>> =
        slack_config.as_ref().map(|sc| {
            let slack_client = Arc::new(dbward_infra::slack::SlackHttpClient::new(
                sc.bot_token.clone(),
            ));
            let slack_msg_repo = Arc::new(dbward_infra::sqlite::SqliteSlackMessageRepo::new(
                conn.clone(),
            ));
            let user_resolver = Arc::new(dbward_infra::slack::SlackUserResolver::new(
                slack_client.clone(),
                user_repo.clone(),
            ));

            // Background warm-up: resolve Slack UIDs for all known subjects
            let warmup_resolver = user_resolver.clone();
            let warmup_user_repo: Arc<dyn dbward_app::ports::UserRepo> = user_repo.clone();
            tokio::spawn(async move {
                let subjects: Vec<String> = warmup_user_repo
                    .list()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|u| u.id)
                    .collect();
                warmup_resolver.warm_up(subjects).await;
            });

            Arc::new(dbward_infra::slack::SlackNotifier::new(
                slack_client.clone(),
                slack_msg_repo,
                context_repo.clone(),
                request_repo.clone(),
                request_repo.clone(),
                user_resolver,
                role_resolver.clone(),
                sc.clone(),
            )) as Arc<dyn dbward_app::ports::Notifier>
        });

    let slack_client_for_state: Option<Arc<dyn dbward_infra::slack::SlackClient>> =
        slack_config.as_ref().map(|sc| {
            Arc::new(dbward_infra::slack::SlackHttpClient::new(
                sc.bot_token.clone(),
            )) as Arc<dyn dbward_infra::slack::SlackClient>
        });

    let slack_notifier_for_bg = slack_notifier.clone();
    let event_dispatcher: Arc<dyn dbward_app::ports::EventDispatcher> =
        Arc::new(dbward_infra::webhook::CompositeEventDispatcher {
            audit: audit_logger.clone(),
            notifier: notifier.clone(),
            result_channel: Some(result_channel.clone()),
            request_notifier: slack_notifier,
            redaction_mode: match cfg.audit.redaction.as_str() {
                "none" => dbward_infra::webhook::RedactionMode::None,
                "full" => dbward_infra::webhook::RedactionMode::Full,
                _ => dbward_infra::webhook::RedactionMode::Literals,
            },
            clock: clock.clone(),
        });
    let ssrf_validator: Arc<dyn dbward_app::ports::SsrfValidator> = if cfg.allow_private_networks {
        Arc::new(dbward_infra::webhook::PermissiveSsrfGuard)
    } else {
        Arc::new(dbward_infra::webhook::SsrfGuard)
    };
    let license_checker: Arc<dyn dbward_app::ports::LicenseChecker> = {
        #[cfg(feature = "commercial")]
        {
            Arc::new(dbward_commercial_license::LicenseCheckerImpl::new(
                resolve_license(license_key, license_file)
                    .map_err(dbward_app::error::AppError::Internal)?,
                clock.now(),
            ))
        }
        #[cfg(not(feature = "commercial"))]
        {
            if license_key.is_some() || license_file.is_some() {
                tracing::warn!(
                    "license_key/license_file configured but commercial feature not compiled. Ignored."
                );
            }
            Arc::new(dbward_infra::FreePlanChecker)
        }
    };

    // C-10: Inject OIDC verifier (requires commercial feature + Pro license)
    #[cfg(feature = "commercial")]
    if (cfg.auth.mode == "oidc" || cfg.auth.mode == "both")
        && let Some(ref oidc_cfg) = cfg.auth.oidc
    {
        if license_checker.effective_plan() == "free" {
            tracing::warn!(
                "auth.mode = {:?} requires a Pro license. Falling back to token-only auth.",
                cfg.auth.mode
            );
        } else {
            let oidc = dbward_commercial_oidc::OidcVerifier::new(
                oidc_cfg.issuer_url.clone(),
                oidc_cfg
                    .client_id
                    .clone()
                    .unwrap_or_else(|| oidc_cfg.audience.clone()),
                "groups".to_string(),
                oidc_cfg.jwks_uri.clone(),
            );
            token_verifier_impl = token_verifier_impl.with_oidc(Arc::new(oidc));
        }
    }
    #[cfg(not(feature = "commercial"))]
    if cfg.auth.mode == "oidc" || cfg.auth.mode == "both" {
        tracing::warn!(
            "auth.mode = {:?} requires a Pro license (commercial feature not compiled). Using token-only auth.",
            cfg.auth.mode
        );
    }

    let token_verifier: Arc<dyn dbward_app::ports::TokenVerifier> = Arc::new(token_verifier_impl);

    let token_value_generator: Arc<dyn dbward_app::ports::TokenValueGenerator> =
        Arc::new(dbward_infra::SecureTokenGenerator);

    let draining = Arc::new(AtomicBool::new(false));

    // Clone SSRF validator needed for config sync (before it's moved into AppState)
    let sync_ssrf_validator = ssrf_validator.clone();
    let reload_ssrf = ssrf_validator.clone();

    let state = state::AppStateBuilder {
        token_verifier,
        reloadable: Arc::new(ArcSwap::from_pointee(initial_reloadable)),
        authorizer,
        request_reader: request_repo.clone(),
        request_writer: request_repo.clone(),
        approval_repo: request_repo.clone(),
        background_task_repo: request_repo.clone(),
        agent_repo,
        user_repo,
        token_repo,
        webhook_repo,
        policy_repo,
        database_registry,
        schema_repo,
        dry_run_repo,
        context_repo,
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
        max_persist_bytes: cfg.result_storage.max_persist_bytes,
        auth_mode: cfg.auth.mode.clone(),
        storage_backend: cfg.result_storage.backend.clone(),
        draining: draining.clone(),
        slack_config,
        slack_client: slack_client_for_state,
        request_notifier: slack_notifier_for_bg,
    }
    .build();

    // Auto-bootstrap: create tokens on first startup
    bootstrap::auto_bootstrap(&state, &state_dir, force_bootstrap)?;

    // Safety guard: reject if DB has config records but TOML key is absent
    safety_guard(&conn, &cfg)?;

    // Register databases and sync all config-managed resources
    sync_all_config(&state, &cfg, sync_ssrf_validator, conn.clone())?;

    // A7: Record config sync in audit log
    let _ = state
        .audit_logger()
        .record(&dbward_domain::entities::AuditEvent::simple(
            "config_synced",
            "policy",
            "system",
            None,
            state.clock().now(),
            &dbward_domain::entities::AuditContext::System,
        ));

    // BUG-31: OIDC verifier initialized above (injected into ApiTokenVerifier)

    let addr: std::net::SocketAddr = listen.parse()?;

    // Parse trusted_proxies at startup (fail fast on invalid config)
    let trusted = middleware::trusted_proxies::parse_trusted_proxies(&cfg.trusted_proxies)
        .map_err(|e| format!("trusted_proxies config: {e}"))?;

    // Spawn SIGHUP hot reload handler
    #[cfg(unix)]
    {
        let reload_state = state.clone();
        let reload_conn = conn.clone();
        let reload_config_path = config_path.to_string();
        let reload_ssrf_validator = reload_ssrf.clone();
        let allow_private = cfg.allow_private_networks;
        tokio::spawn(async move {
            use tokio::signal::unix::{SignalKind, signal};
            use tokio::time::Instant;

            let mut sig = signal(SignalKind::hangup()).unwrap();
            let reload_mutex = tokio::sync::Mutex::new(());
            let mut last_reload = Instant::now() - Duration::from_secs(10);

            loop {
                sig.recv().await;
                if last_reload.elapsed() < Duration::from_secs(5) {
                    tracing::debug!("config reload debounced");
                    continue;
                }
                let _guard = reload_mutex.lock().await;
                last_reload = Instant::now();

                let new_cfg =
                    match config::ServerConfig::load(std::path::Path::new(&reload_config_path)) {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::warn!("config reload failed (parse): {e}");
                            continue;
                        }
                    };

                if let Err(e) = safety_guard(&reload_conn, &new_cfg) {
                    tracing::error!("config reload rejected (safety guard): {e}");
                    continue;
                }

                let ssrf: Arc<dyn dbward_app::ports::SsrfValidator> = if allow_private {
                    reload_ssrf_validator.clone()
                } else {
                    Arc::new(dbward_infra::webhook::SsrfGuard)
                };

                let uc = build_sync_uc(&reload_state, reload_conn.clone(), ssrf);

                let sync_result = build_sync_inputs_and_run(&uc, &new_cfg);
                match sync_result {
                    Ok(()) => {
                        let new_reloadable = build_reloadable_config(&new_cfg);
                        match new_reloadable {
                            Ok(r) => {
                                reload_state.reloadable.store(Arc::new(r));
                                tracing::info!("config reloaded successfully");
                            }
                            Err(e) => tracing::warn!("config reload failed (build): {e}"),
                        }
                    }
                    Err(e) => tracing::warn!("config reload failed (sync): {e}"),
                }
            }
        });
    }

    start(addr, state, cfg.retention, trusted).await
}

/// Deprecated: use sync_all_config instead. Kept for test compatibility.
pub fn register_databases(
    state: &AppState,
    databases: &[config::DatabaseDef],
) -> Result<(), Box<dyn std::error::Error>> {
    for db in databases {
        for env in &db.environments {
            let db_name = DatabaseName::new(&db.name).map_err(|e| format!("database name: {e}"))?;
            let environment = Environment::new(env).map_err(|e| format!("environment: {e}"))?;
            state.database_registry().register(&db_name, &environment)?;
        }
    }
    Ok(())
}

fn safety_guard(
    conn: &dbward_infra::sqlite::DbConn,
    cfg: &config::ServerConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    // Check: if DB has source='config' records but config has zero entries,
    // it likely means the user forgot to include that section (data loss prevention).
    // An explicit empty array `workflows = []` will have .is_empty() = true but that's
    // intentional. We can only detect "key never appeared" vs "key = []" at the TOML
    // level, but serde gives us the same empty Vec for both. We accept this trade-off:
    // explicit empty = allowed, and accidental omission on a FRESH config also = allowed
    // (no DB records yet). The guard only fires when DB has existing records AND config is empty.
    let checks: &[(&str, bool)] = &[
        ("workflows", cfg.workflows.is_empty()),
        ("execution_policies", cfg.execution_policies.is_empty()),
        ("webhooks", cfg.webhooks.is_empty()),
        ("result_policies", cfg.result_policies.is_empty()),
        (
            "notification_policies",
            cfg.notification_policies.is_empty(),
        ),
        ("databases", cfg.databases.is_empty()),
    ];

    let c = conn.lock();
    for (table, config_empty) in checks {
        if !config_empty {
            continue;
        }
        let count: i64 = c
            .query_row(
                &format!("SELECT COUNT(*) FROM {table} WHERE source = 'config'"),
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);

        if count > 0 {
            return Err(format!(
                "database contains {count} {table} (source='config') but config has no [[{table}]] entries.\n\
                 Run `dbward config export` to export current state, or add [[{table}]] to your config."
            )
            .into());
        }
    }
    Ok(())
}

fn sync_all_config(
    state: &AppState,
    cfg: &config::ServerConfig,
    ssrf_validator: Arc<dyn dbward_app::ports::SsrfValidator>,
    conn: dbward_infra::sqlite::DbConn,
) -> Result<(), Box<dyn std::error::Error>> {
    let uc = build_sync_uc(state, conn, ssrf_validator);
    build_sync_inputs_and_run(&uc, cfg)
}

fn build_sync_uc(
    state: &AppState,
    conn: dbward_infra::sqlite::DbConn,
    ssrf_validator: Arc<dyn dbward_app::ports::SsrfValidator>,
) -> SyncConfig {
    let transaction = Arc::new(dbward_infra::sqlite::SqliteSyncTransaction::new(
        conn.clone(),
    ));
    SyncConfig {
        policy_repo: state.policy_repo().clone(),
        webhook_repo: state.webhook_repo().clone(),
        database_registry: state.database_registry().clone(),
        user_repo: state.user_repo().clone(),
        group_repo: Arc::new(dbward_infra::sqlite::SqliteGroupRepo::new(conn.clone())),
        role_binding_repo: Arc::new(dbward_infra::sqlite::SqliteRoleBindingRepo::new(conn)),
        notifier: state.notifier().clone(),
        clock: state.clock().clone(),
        id_gen: state.id_generator().clone(),
        transaction,
        license_checker: state.license_checker().clone(),
        ssrf_validator,
    }
}

pub fn build_app(state: AppState, trusted: Vec<ipnet::IpNet>) -> Router {
    let trusted_proxies = std::sync::Arc::new(trusted);
    let tp = trusted_proxies.clone();
    routes::build_router(state).layer(axum::middleware::from_fn(move |req, next| {
        let tp = tp.clone();
        async move { middleware::trusted_proxies::resolve_client_ip(tp, req, next).await }
    }))
}

pub async fn start(
    addr: std::net::SocketAddr,
    state: AppState,
    retention: config::RetentionConfig,
    trusted: Vec<ipnet::IpNet>,
) -> Result<(), Box<dyn std::error::Error>> {
    let draining = state.draining.clone();
    let result_channel = state.result_channel().clone();

    // Startup recovery: warn about in-flight requests
    let dispatched = state
        .request_reader()
        .count_by_status("dispatched")
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, "failed to count dispatched requests on startup");
            0
        });
    let running = state
        .request_reader()
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
    let (bg_shutdown, bg_handle) =
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

    // Wait for background supervisor to finish
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    if let Err(e) = tokio::time::timeout_at(deadline, bg_handle).await {
        tracing::warn!(error = %e, "background supervisor did not finish in time");
    }
    tracing::info!("server stopped");
    Ok(())
}

#[cfg(feature = "commercial")]
pub(crate) fn resolve_license(
    key: Option<&str>,
    file: Option<&str>,
) -> Result<dbward_domain::license::License, String> {
    let raw = match (key, file) {
        (Some(k), _) if !k.trim().is_empty() => Some(k.to_string()),
        (_, Some(path)) if !path.trim().is_empty() => match std::fs::read_to_string(path) {
            Ok(content) if !content.trim().is_empty() => Some(content),
            Ok(_) => None,
            Err(e) => {
                return Err(format!("failed to read license file '{path}': {e}"));
            }
        },
        _ => None,
    };

    let Some(raw) = raw else {
        tracing::info!(plan = "free", "License: no key provided, using Free plan");
        return Ok(dbward_domain::license::License::default());
    };

    match dbward_infra::license_key::verify_license_key(&raw) {
        Ok(license) => {
            tracing::info!(
                plan = ?license.plan,
                issued_to = ?license.issued_to,
                expires_at = ?license.expires_at,
                "License loaded"
            );
            Ok(license)
        }
        Err(e) => Err(format!("license key verification failed: {e}")),
    }
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

fn build_sync_inputs_and_run(
    uc: &SyncConfig,
    cfg: &config::ServerConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let databases: Vec<DatabaseInput> = cfg
        .databases
        .iter()
        .map(|d| DatabaseInput {
            name: d.name.clone(),
            environments: d.environments.clone(),
        })
        .collect();
    let users: Vec<UserInput> = cfg
        .users
        .iter()
        .map(|u| UserInput {
            id: u.id.clone(),
            status: u.status.clone(),
        })
        .collect();
    let groups: Vec<GroupInput> = cfg
        .auth
        .groups
        .iter()
        .map(|g| GroupInput {
            name: g.name.clone(),
            members: g.members.clone(),
        })
        .collect();
    let roles: Vec<RoleInput> = cfg
        .auth
        .roles
        .iter()
        .map(|r| RoleInput {
            name: r.name.clone(),
            permissions: r.permissions.clone(),
            databases: r.databases.clone(),
            environments: r.environments.clone(),
        })
        .collect();
    let role_bindings: Vec<RoleBindingInput> = cfg
        .auth
        .role_bindings
        .iter()
        .map(|rb| RoleBindingInput {
            role: rb.role.clone(),
            subjects: rb.subjects.clone(),
            groups: rb.groups.clone(),
        })
        .collect();
    let webhooks: Vec<WebhookInput> = cfg
        .webhooks
        .iter()
        .map(|wh| WebhookInput {
            id: wh.id.clone(),
            url: wh.url.clone(),
            events: wh.events.clone(),
            format: wh.format.clone(),
            secret: wh.secret.clone(),
        })
        .collect();
    let workflows: Vec<WorkflowInput> = cfg
        .workflows
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
            require_reason: wf.require_reason,
            allow_self_approve: wf.allow_self_approve,
            allow_same_approver_across_steps: wf.allow_same_approver_across_steps,
            explain: wf.explain,
            pending_ttl_secs: wf.pending_ttl_secs,
            statement_timeout_secs: wf.statement_timeout_secs,
        })
        .collect();
    let execution_policies: Vec<ExecutionPolicyInput> = cfg
        .execution_policies
        .iter()
        .map(|ep| ExecutionPolicyInput {
            database: ep.database.clone(),
            environment: ep.environment.clone(),
            max_executions: ep.max_executions,
            execution_window_secs: ep.execution_window_secs,
            retry_on_failure: ep.retry_on_failure,
            statement_timeout_secs: ep.statement_timeout_secs,
            max_statement_timeout_secs: ep.max_statement_timeout_secs,
            max_rows: ep.max_rows,
            migration_lease_duration_secs: ep.migration_lease_duration_secs,
            migration_statement_timeout_secs: ep.migration_statement_timeout_secs,
        })
        .collect();
    let result_policies: Vec<ResultPolicyInput> = cfg
        .result_policies
        .iter()
        .map(|rp| ResultPolicyInput {
            database: rp.database.clone(),
            environment: rp.environment.clone(),
            retention_days: rp.retention_days,
            delivery_mode: rp.delivery_mode.clone(),
            access: rp.access.clone(),
        })
        .collect();
    let notification_policies: Vec<NotificationPolicyInput> = cfg
        .notification_policies
        .iter()
        .map(|np| NotificationPolicyInput {
            database: np.database.clone(),
            environment: np.environment.clone(),
            webhooks: np.webhooks.clone(),
            events: np.events.clone(),
        })
        .collect();

    uc.sync_all(
        databases,
        users,
        groups,
        roles,
        role_bindings,
        webhooks,
        workflows,
        execution_policies,
        result_policies,
        notification_policies,
    )
    .map(|_| ())
    .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })
}

fn build_reloadable_config(
    cfg: &config::ServerConfig,
) -> Result<state::ReloadableConfig, Box<dyn std::error::Error>> {
    build_reloadable_config_with(cfg, None)
}

fn build_reloadable_config_with(
    cfg: &config::ServerConfig,
    policy_repo: Option<Arc<dyn dbward_app::ports::PolicyRepo>>,
) -> Result<state::ReloadableConfig, Box<dyn std::error::Error>> {
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
    let resolver = dbward_infra::auth::ConfigRoleResolver::with_policy_repo(
        cfg.auth.roles.iter().map(build_role_definition).collect(),
        group_bindings,
        user_bindings,
        cfg.auth.default_role.clone(),
        policy_repo,
    )
    .with_group_members(
        cfg.auth
            .groups
            .iter()
            .map(|gc| (gc.name.clone(), gc.members.iter().cloned().collect()))
            .collect(),
    );
    let role_resolver: Arc<dyn dbward_app::ports::RoleResolver> = Arc::new(resolver);

    let mut auto_approve_entries = Vec::new();
    for (i, a) in cfg.auto_approve.iter().enumerate() {
        auto_approve_entries.push(
            a.to_entry()
                .map_err(|e| format!("auto_approve[{i}]: {e}"))?,
        );
    }

    Ok(state::ReloadableConfig {
        role_resolver,
        auto_approve_entries,
        sql_review_rules: cfg
            .sql_review
            .to_review_rules()
            .map_err(|e| format!("config: {e}"))?,
        default_approval_ttl_secs: Some(cfg.retention.approval_ttl_secs),
    })
}

#[cfg(test)]
mod safety_guard_tests {
    use super::*;

    fn empty_config() -> config::ServerConfig {
        config::ServerConfig::load(std::path::Path::new("/dev/null")).unwrap_or_else(|_| {
            // Minimal valid config
            toml::from_str(
                r#"
                    state_dir = "/tmp"
                    [auth]
                    mode = "token"
                    "#,
            )
            .unwrap()
        })
    }

    #[test]
    fn safety_guard_rejects_when_db_has_config_records_but_toml_empty() {
        let conn = dbward_infra::sqlite::open_memory().unwrap();
        // Insert a source='config' workflow (source column exists via V14 migration)
        {
            let c = conn.lock();
            c.execute(
                "INSERT INTO workflows (id, database_name, environment, operations_json, steps_json, source) VALUES ('wf-1', 'db', 'prod', '[]', '[]', 'config')",
                [],
            ).unwrap();
        }

        let cfg = empty_config();
        assert!(cfg.workflows.is_empty(), "config should have no workflows");

        let result = safety_guard(&conn, &cfg);
        assert!(result.is_err(), "safety guard should reject");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("workflows"),
            "error should mention workflows: {err}"
        );
    }

    #[test]
    fn safety_guard_allows_when_db_empty() {
        let conn = dbward_infra::sqlite::open_memory().unwrap();
        let cfg = empty_config();
        let result = safety_guard(&conn, &cfg);
        assert!(result.is_ok(), "safety guard should pass on empty DB");
    }

    #[test]
    fn safety_guard_allows_when_config_has_entries() {
        let conn = dbward_infra::sqlite::open_memory().unwrap();
        {
            let c = conn.lock();
            c.execute(
                "INSERT INTO workflows (id, database_name, environment, operations_json, steps_json, source) VALUES ('wf-1', 'db', 'prod', '[]', '[]', 'config')",
                [],
            ).unwrap();
        }

        let cfg: config::ServerConfig = toml::from_str(
            r#"
            state_dir = "/tmp"
            [auth]
            mode = "token"
            [[workflows]]
            database = "db"
            environment = "prod"
            operations = ["execute_select"]
            steps = []
            "#,
        )
        .unwrap();

        let result = safety_guard(&conn, &cfg);
        assert!(
            result.is_ok(),
            "safety guard should pass when config has workflows"
        );
    }
}

#[cfg(all(test, feature = "commercial"))]
mod tests {
    use super::*;

    #[test]
    fn resolve_license_none_returns_free() {
        let license = resolve_license(None, None).unwrap();
        assert_eq!(license.plan, dbward_domain::license::Plan::Free);
    }

    #[test]
    fn resolve_license_empty_string_returns_free() {
        let license = resolve_license(Some(""), None).unwrap();
        assert_eq!(license.plan, dbward_domain::license::Plan::Free);
    }

    #[test]
    fn resolve_license_whitespace_only_returns_free() {
        let license = resolve_license(Some("  \n"), None).unwrap();
        assert_eq!(license.plan, dbward_domain::license::Plan::Free);
    }
}
