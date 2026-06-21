pub mod background;
pub mod bootstrap;
pub mod config;
pub mod http_elicitation;
pub mod mcp_backend;
pub mod metrics;
pub mod middleware;
pub mod routes;
pub mod session;
pub mod session_store;
pub mod state;
pub mod util;

/// Dispatches to both WebhookDispatcher and SlackNotifier.
struct CompositeNotifier {
    webhook: Arc<dyn dbward_app::ports::Notifier>,
    slack: Arc<dyn dbward_app::ports::Notifier>,
}

impl dbward_app::ports::Notifier for CompositeNotifier {
    fn dispatch(&self, event: dbward_app::ports::WebhookEvent) {
        self.webhook.dispatch(event.clone());
        self.slack.dispatch(event);
    }

    fn reload(&self) -> Result<(), dbward_app::error::AppError> {
        self.webhook.reload()
    }
}

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use arc_swap::ArcSwap;
use axum::Router;
use config::{AutoApproveExt, SqlReviewExt};
use dbward_app::ports::ResultStore;
use dbward_app::use_cases::sync_config::SyncConfig;
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
    license_offline: bool,
    license_url: &str,
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
    // initial_reloadable is built after OIDC injection determines final effective_auth_mode
    let pre_reloadable = build_reloadable_config_with(
        &cfg,
        cfg.effective_auth_mode(),
        None,
        Some(policy_repo.clone()),
    )
    .map_err(|e| format!("config: {e}"))?;
    let role_resolver = pre_reloadable.role_resolver.clone();
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

    // Composite notifier: webhook dispatcher + optional Slack notifier
    let notifier: Arc<dyn dbward_app::ports::Notifier> = if let Some(ref sn) = slack_notifier {
        Arc::new(CompositeNotifier {
            webhook: notifier,
            slack: sn.clone(),
        })
    } else {
        notifier
    };

    let ssrf_validator: Arc<dyn dbward_app::ports::SsrfValidator> = if cfg.allow_private_networks {
        Arc::new(dbward_infra::webhook::PermissiveSsrfGuard)
    } else {
        Arc::new(dbward_infra::webhook::SsrfGuard)
    };
    // Server meta repo (for validated_until persistence)
    let server_meta_repo: Option<Arc<dyn dbward_app::ports::ServerMetaRepo>> = Some(Arc::new(
        dbward_infra::sqlite::SqliteServerMetaRepo::new(conn.clone()),
    ));

    // License checker
    #[cfg(feature = "commercial")]
    let (license_checker, license_checker_impl): (
        Arc<dyn dbward_app::ports::LicenseChecker>,
        Option<Arc<dbward_commercial_license::LicenseCheckerImpl>>,
    ) = {
        let validated_until = server_meta_repo
            .as_ref()
            .and_then(|repo| match repo.get("license_validated_until") {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "failed to read license_validated_until from DB");
                    None
                }
            })
            .and_then(|s| {
                chrono::DateTime::parse_from_rfc3339(&s)
                    .map_err(|e| {
                        tracing::warn!(value = %s, error = %e, "invalid license_validated_until in DB, treating as unset");
                    })
                    .ok()
            })
            .map(|dt| dt.with_timezone(&chrono::Utc));

        let persisted_grace_days: Option<u32> = server_meta_repo
            .as_ref()
            .and_then(|repo| match repo.get("license_grace_days") {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "failed to read license_grace_days from DB");
                    None
                }
            })
            .and_then(|s| {
                s.parse().map_err(|e| {
                    tracing::warn!(value = %s, error = %e, "invalid license_grace_days in DB, using default");
                }).ok()
            });

        let license = resolve_license(license_key, license_file)
            .map_err(dbward_app::error::AppError::Internal)?;
        let impl_checker = Arc::new(dbward_commercial_license::LicenseCheckerImpl::new(
            license,
            clock.now(),
            validated_until,
            persisted_grace_days,
            license_offline,
            license_url.to_string(),
        ));

        // Startup checks
        let now = clock.now();
        if impl_checker.is_must_validate_expired(now) {
            impl_checker.force_expire_with_reason("must_validate_expired");
        }
        if impl_checker.is_grace_expired(now) {
            impl_checker.force_expire_with_reason("grace_expired");
        }

        (
            impl_checker.clone() as Arc<dyn dbward_app::ports::LicenseChecker>,
            Some(impl_checker),
        )
    };

    #[cfg(not(feature = "commercial"))]
    let license_checker: Arc<dyn dbward_app::ports::LicenseChecker> = {
        if license_key.is_some() || license_file.is_some() {
            tracing::warn!(
                "license_key/license_file configured but commercial feature not compiled. Ignored."
            );
        }
        Arc::new(dbward_infra::FreePlanChecker)
    };

    // C-10: Inject OIDC verifier (requires commercial feature + Team license)
    let mut effective_auth_mode = cfg.effective_auth_mode().to_string();

    #[cfg(feature = "commercial")]
    if (effective_auth_mode == "oidc" || effective_auth_mode == "both")
        && let Some(ref oidc_cfg) = cfg.auth.oidc
    {
        if license_checker.effective_plan() == "free" {
            if cfg.auth.mode.is_some() {
                return Err(format!(
                    "auth.mode = \"{}\" requires a Team license. \
                     Either provide a valid license or change auth.mode to \"token\".",
                    effective_auth_mode
                )
                .into());
            } else {
                tracing::warn!(
                    "OIDC configured but Team license not available. \
                     Effective auth mode: token-only."
                );
                effective_auth_mode = "token".to_string();
            }
        } else {
            let oidc = dbward_commercial_oidc::OidcVerifier::new(
                oidc_cfg.issuer_url.trim().to_string(),
                oidc_cfg
                    .client_id
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .unwrap_or(oidc_cfg.audience.trim())
                    .to_string(),
                "groups".to_string(),
                oidc_cfg.jwks_uri.as_deref().map(|s| s.trim().to_string()),
            );
            token_verifier_impl = token_verifier_impl.with_oidc(Arc::new(oidc));
        }
    }
    #[cfg(not(feature = "commercial"))]
    if effective_auth_mode == "oidc" || effective_auth_mode == "both" {
        if cfg.auth.mode.is_some() {
            return Err(format!(
                "auth.mode = \"{}\" requires the commercial feature (Team license). \
                 Change auth.mode to \"token\" or use a commercial build.",
                effective_auth_mode
            )
            .into());
        } else {
            tracing::warn!(
                "OIDC configured but commercial feature not available. \
                 Effective auth mode: token-only."
            );
            effective_auth_mode = "token".to_string();
        }
    }

    tracing::info!(auth_mode = %effective_auth_mode, "Authentication configured");

    // Rebuild initial_reloadable with the final effective_auth_mode
    // (may differ from cfg.effective_auth_mode() due to license fallback)
    let initial_reloadable = if effective_auth_mode == cfg.effective_auth_mode() {
        pre_reloadable
    } else {
        build_reloadable_config_with(&cfg, &effective_auth_mode, None, Some(policy_repo.clone()))
            .map_err(|e| format!("config: {e}"))?
    };

    let token_verifier_impl = token_verifier_impl.with_license(license_checker.clone());
    let token_verifier: Arc<dyn dbward_app::ports::TokenVerifier> = Arc::new(token_verifier_impl);

    let token_value_generator: Arc<dyn dbward_app::ports::TokenValueGenerator> =
        Arc::new(dbward_infra::SecureTokenGenerator);

    let draining = Arc::new(AtomicBool::new(false));

    // Clone SSRF validator needed for config sync (before it's moved into AppState)
    let sync_ssrf_validator = ssrf_validator.clone();
    let reload_ssrf = ssrf_validator.clone();

    let audit_crypto = Arc::new(
        dbward_infra::Ed25519AuditCrypto::load_or_generate(&state_dir)
            .map_err(|e| format!("audit crypto init: {e}"))?,
    );

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
        ssrf_validator,
        license_checker,
        #[cfg(feature = "commercial")]
        license_checker_impl,
        server_meta_repo,
        clock,
        id_generator,
        token_value_generator,
        webhook_delivery_repo: Some(webhook_delivery_repo),
        audit_signer: audit_crypto.clone(),
        audit_verifier: audit_crypto.clone(),
        uow: Arc::new(dbward_infra::sqlite::SqliteUnitOfWork::with_signer(
            conn.clone(),
            audit_crypto,
            100, // checkpoint every 100 events
        )),
        metrics: Arc::new(metrics::Metrics::new()),
        max_persist_bytes: cfg.result_storage.max_persist_bytes,
        auth_mode: effective_auth_mode.clone(),
        storage_backend: cfg.result_storage.backend.clone(),
        draining: draining.clone(),
        slack_config,
        slack_client: slack_client_for_state,
        mcp_enabled: cfg.mcp.enabled,
        mcp_allowed_origins: cfg.mcp.allowed_origins.clone(),
        mcp_default_database: cfg
            .databases
            .first()
            .map(|d| d.name.clone())
            .unwrap_or_default(),
        mcp_default_environment: cfg.mcp.default_environment.clone(),
        mcp_elicitation_timeout_secs: cfg.mcp.elicitation_timeout_secs.unwrap_or(300).max(10),
        mcp_replay_buffer_size: cfg.mcp.replay_buffer_size.unwrap_or(100).max(1),
        session_store: Arc::new(session_store::SessionStore::new(
            cfg.mcp.session_ttl_secs.unwrap_or(3600).max(10), // minimum 10s
            cfg.mcp.max_sessions.unwrap_or(1000).max(1),      // minimum 1
        )),
    }
    .build();

    // A2: Legacy purge boundary migration (one-time, on first v0.1.6 startup)
    dbward_infra::sqlite::migrate_legacy_purge_boundary(&conn, &*state.audit_signer);

    // Auto-bootstrap: create tokens on first startup
    bootstrap::auto_bootstrap(&state, &state_dir, force_bootstrap)?;

    // Safety guard: reject if DB has config records but TOML key is absent
    safety_guard(&conn, &cfg)?;

    // Register databases and sync all config-managed resources
    sync_all_config(&state, &cfg, sync_ssrf_validator, conn.clone())?;

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
        let startup_auth_mode = effective_auth_mode.clone();
        // For reload comparison: use config-level effective mode (before license fallback)
        let startup_config_auth_mode = cfg.effective_auth_mode().to_string();
        // Snapshot OIDC connection settings for change detection
        let startup_oidc_issuer = cfg
            .auth
            .oidc
            .as_ref()
            .map(|o| o.issuer_url.trim().to_string());
        let startup_oidc_audience = cfg
            .auth
            .oidc
            .as_ref()
            .map(|o| o.audience.trim().to_string());
        let startup_oidc_client_id = cfg
            .auth
            .oidc
            .as_ref()
            .and_then(|o| o.client_id.as_deref())
            .map(|s| s.trim().to_string());
        let startup_oidc_jwks = cfg
            .auth
            .oidc
            .as_ref()
            .and_then(|o| o.jwks_uri.as_deref())
            .map(|s| s.trim().to_string());
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

                let raw = match std::fs::read_to_string(&reload_config_path) {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!("config reload failed (read): {e}");
                        continue;
                    }
                };
                let new_cfg = match config::ServerConfig::parse_for_reload(
                    &raw,
                    &reload_config_path,
                    &startup_auth_mode,
                ) {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!("config reload failed (parse): {e}");
                        continue;
                    }
                };

                // Detect auth connection changes (compare config-level values,
                // not runtime fallback — avoids permanent mismatch when license forces fallback)
                let new_oidc_issuer = new_cfg
                    .auth
                    .oidc
                    .as_ref()
                    .map(|o| o.issuer_url.trim().to_string());
                let new_oidc_audience = new_cfg
                    .auth
                    .oidc
                    .as_ref()
                    .map(|o| o.audience.trim().to_string());
                let new_oidc_client_id = new_cfg
                    .auth
                    .oidc
                    .as_ref()
                    .and_then(|o| o.client_id.as_deref())
                    .map(|s| s.trim().to_string());
                let new_oidc_jwks = new_cfg
                    .auth
                    .oidc
                    .as_ref()
                    .and_then(|o| o.jwks_uri.as_deref())
                    .map(|s| s.trim().to_string());
                // When startup fell back (e.g., "both" → "token" due to license),
                // only OIDC connection field changes are restart-worthy.
                // auth.mode changes to/from the fallback value are expected.
                let auth_changed = new_oidc_issuer != startup_oidc_issuer
                    || new_oidc_audience != startup_oidc_audience
                    || new_oidc_client_id != startup_oidc_client_id
                    || new_oidc_jwks != startup_oidc_jwks
                    || (startup_auth_mode == startup_config_auth_mode
                        && new_cfg.effective_auth_mode() != startup_config_auth_mode);
                if auth_changed {
                    tracing::warn!(
                        configured = %new_cfg.effective_auth_mode(),
                        active = %startup_auth_mode,
                        "auth.mode change detected but requires restart to take effect"
                    );
                }

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
                        if auth_changed {
                            // Auth connection changes require restart — don't rebuild
                            // role resolver to avoid inconsistent authorization state
                            tracing::info!(
                                "config sync applied (databases, webhooks, policies). \
                                 Role/auth changes skipped until restart."
                            );
                        } else {
                            let new_reloadable = build_reloadable_config_with(
                                &new_cfg,
                                &startup_auth_mode,
                                None,
                                None,
                            );
                            match new_reloadable {
                                Ok(r) => {
                                    reload_state.reloadable.store(Arc::new(r));
                                    tracing::info!("config reloaded successfully");
                                }
                                Err(e) => tracing::warn!("config reload failed (build): {e}"),
                            }
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
        ("users", cfg.users.is_empty()),
        // Note: roles excluded — built-in roles (admin/developer/readonly) are schema-seeded
        // with source='config' and cannot be redefined in TOML.
        ("groups", cfg.auth.groups.is_empty()),
        ("role_bindings", cfg.auth.role_bindings.is_empty()),
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
                 Run `dbward doctor --server <config>` to diagnose, or add [[{table}]] to your config."
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
    let digest = {
        use sha2::{Digest, Sha256};
        let serialized = format!("{cfg:?}");
        format!("{:x}", Sha256::digest(serialized.as_bytes()))
    };
    let mut uc = build_sync_uc(state, conn, ssrf_validator);
    uc.config_digest = digest;
    build_sync_inputs_and_run(&uc, cfg)
}

fn build_sync_uc(
    state: &AppState,
    conn: dbward_infra::sqlite::DbConn,
    ssrf_validator: Arc<dyn dbward_app::ports::SsrfValidator>,
) -> SyncConfig {
    SyncConfig {
        policy_repo: state.policy_repo().clone(),
        webhook_repo: state.webhook_repo().clone(),
        database_registry: state.database_registry().clone(),
        user_repo: Arc::new(dbward_infra::sqlite::SqliteUserRepo::new(conn.clone())),
        group_repo: Arc::new(dbward_infra::sqlite::SqliteGroupRepo::new(conn.clone())),
        role_binding_repo: Arc::new(dbward_infra::sqlite::SqliteRoleBindingRepo::new(
            conn.clone(),
        )),
        token_repo: Arc::new(dbward_infra::sqlite::SqliteTokenRepo::new(conn.clone())),
        request_writer: Arc::new(dbward_infra::sqlite::SqliteRequestRepo::new(conn.clone())),
        uow: state.uow().clone(),
        notifier: state.notifier().clone(),
        clock: state.clock().clone(),
        id_gen: state.id_generator().clone(),
        license_checker: state.license_checker().clone(),
        ssrf_validator,
        config_digest: String::new(),
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

    // Spawn MCP session cleanup (uses same shutdown token)
    state.session_store().spawn_cleanup(bg_shutdown.clone());

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
    use dbward_app::use_cases::sync_config::convert;

    let databases = convert::databases_from_config(&cfg.databases);
    let users = convert::users_from_config(&cfg.users);
    let groups = convert::groups_from_config(&cfg.auth.groups);
    let roles = convert::roles_from_config(&cfg.auth.roles);
    let role_bindings = convert::role_bindings_from_config(&cfg.auth.role_bindings);
    let webhooks = convert::webhooks_from_config(&cfg.webhooks);
    let workflows = convert::workflows_from_config(&cfg.workflows);
    let execution_policies = convert::execution_policies_from_config(&cfg.execution_policies);
    let result_policies = convert::result_policies_from_config(&cfg.result_policies);
    let notification_policies =
        convert::notification_policies_from_config(&cfg.notification_policies);

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

fn build_reloadable_config_with(
    cfg: &config::ServerConfig,
    effective_auth_mode: &str,
    override_role_mappings: Option<&[dbward_config::server::OidcRoleMapping]>,
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
    // Only include OIDC role_mappings when effective mode uses OIDC
    if effective_auth_mode == "oidc" || effective_auth_mode == "both" {
        let mappings: &[dbward_config::server::OidcRoleMapping] = match override_role_mappings {
            Some(m) => m,
            None => cfg.auth.oidc.as_ref().map_or(&[], |o| &o.role_mappings),
        };
        for mapping in mappings {
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
        toml::from_str(
            r#"
            state_dir = "/tmp"
            [auth]
            mode = "token"
            "#,
        )
        .unwrap()
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
