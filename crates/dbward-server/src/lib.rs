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
use config::{AutoApproveExt, SqlReviewExt};
use dbward_app::ports::PolicyRepo;
use dbward_app::ports::ResultStore;
use dbward_app::use_cases::sync_config::{
    ApproverInput, ExecutionPolicyInput, SyncConfig, WebhookInput, WorkflowInput, WorkflowStepInput,
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

    // C-10: OIDC injection moved after license_checker initialization (see below)

    // token_verifier is finalized after OIDC injection below
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
            cfg.auth.roles.iter().map(build_role_definition).collect(),
            group_bindings,
            user_bindings,
            cfg.auth.default_role.clone(),
            Some(policy_repo.clone()),
        )
        .with_group_members(
            cfg.auth
                .groups
                .iter()
                .map(|gc| (gc.name.clone(), gc.members.iter().cloned().collect()))
                .collect(),
        )
    });
    let authorizer: Arc<dyn dbward_app::ports::Authorizer> =
        Arc::new(dbward_infra::auth::RbacAuthorizer);

    // Sync TOML-defined custom roles to PolicyRepo (SQLite)
    {
        let active_names: Vec<String> = cfg.auth.roles.iter().map(|r| r.name.clone()).collect();
        for rc in &cfg.auth.roles {
            let def = build_role_definition(rc);
            if let Err(e) = policy_repo.upsert_config_role(&def) {
                return Err(
                    format!("failed to sync config role '{}' to DB: {}", rc.name, e).into(),
                );
            }
        }
        if let Err(e) = policy_repo.delete_stale_config_roles(&active_names) {
            return Err(format!("failed to clean stale config roles: {}", e).into());
        }
    }

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
            _ => Arc::new(dbward_infra::storage::LocalResultStore::new(
                &cfg.result_storage.root_dir,
            )?),
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
    let ssrf_validator: Arc<dyn dbward_app::ports::SsrfValidator> =
        Arc::new(dbward_infra::webhook::SsrfGuard);
    let license_checker: Arc<dyn dbward_app::ports::LicenseChecker> = {
        #[cfg(feature = "commercial")]
        {
            Arc::new(dbward_commercial_license::LicenseCheckerImpl::new(
                resolve_license(license_key, license_file),
                clock.now(),
            ))
        }
        #[cfg(not(feature = "commercial"))]
        {
            let _ = (license_key, license_file);
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

    let state = AppState {
        token_verifier,
        role_resolver,
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
        default_approval_ttl_secs: Some(cfg.retention.approval_ttl_secs),
        max_persist_bytes: cfg.result_storage.max_persist_bytes,
        auth_mode: cfg.auth.mode.clone(),
        storage_backend: cfg.result_storage.backend.clone(),
        sql_review_rules: cfg
            .sql_review
            .to_review_rules()
            .map_err(|e| format!("config: {e}"))?,
        auto_approve_entries: {
            let mut entries = Vec::new();
            for (i, a) in cfg.auto_approve.iter().enumerate() {
                entries.push(
                    a.to_entry()
                        .map_err(|e| format!("auto_approve[{i}]: {e}"))?,
                );
            }
            entries
        },
        draining: draining.clone(),
        slack_config,
        slack_client: slack_client_for_state,
        request_notifier: slack_notifier_for_bg,
    };

    // Auto-bootstrap: create tokens on first startup
    bootstrap::auto_bootstrap(&state, &state_dir, force_bootstrap)?;

    // Register databases and sync workflows on startup
    register_databases(&state, &cfg.databases)?;
    sync_workflows(&state, &cfg.workflows)?;

    // BUG-28: Sync webhooks from config
    sync_webhooks(&state, &cfg.webhooks)?;

    // Sync execution policies from config
    sync_execution_policies(&state, &cfg.execution_policies)?;

    // A7: Record config sync in audit log
    let _ = state
        .audit_logger
        .record(&dbward_domain::entities::AuditEvent::simple(
            "config_synced",
            "policy",
            "system",
            None,
            state.clock.now(),
            &dbward_domain::entities::AuditContext::System,
        ));

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
    // Count unique database names (not db×env combinations)
    let existing_pairs = state.database_registry.list()?;
    let existing_db_names: std::collections::HashSet<&str> =
        existing_pairs.iter().map(|(db, _)| db.as_str()).collect();
    let mut new_db_names: std::collections::HashSet<&str> = std::collections::HashSet::new();

    for db in databases {
        if !existing_db_names.contains(db.name.as_str()) {
            new_db_names.insert(&db.name);
        }
    }

    let total = existing_db_names.len() as u32 + new_db_names.len() as u32;
    if total > state.license_checker.max_databases() {
        return Err(format!(
            "database limit reached (max {})",
            state.license_checker.max_databases()
        )
        .into());
    }

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
            require_reason: wf.require_reason,
            allow_self_approve: wf.allow_self_approve,
            allow_same_approver_across_steps: wf.allow_same_approver_across_steps,
            explain: wf.explain,
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

fn sync_execution_policies(
    state: &AppState,
    policies: &[config::ExecutionPolicyDef],
) -> Result<(), Box<dyn std::error::Error>> {
    let uc = SyncConfig {
        policy_repo: state.policy_repo.clone(),
        webhook_repo: state.webhook_repo.clone(),
        clock: state.clock.clone(),
        id_gen: state.id_generator.clone(),
    };

    let inputs: Vec<ExecutionPolicyInput> = policies
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
        })
        .collect();

    uc.sync_execution_policies(inputs)?;
    Ok(())
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
    let result_channel = state.result_channel.clone();

    // Startup recovery: warn about in-flight requests
    let dispatched = state
        .request_reader
        .count_by_status("dispatched")
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, "failed to count dispatched requests on startup");
            0
        });
    let running = state
        .request_reader
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

pub(crate) fn resolve_license(
    key: Option<&str>,
    file: Option<&str>,
) -> dbward_domain::license::License {
    let raw = match (key, file) {
        (Some(k), _) if !k.trim().is_empty() => Some(k.to_string()),
        (_, Some(path)) if !path.trim().is_empty() => match std::fs::read_to_string(path) {
            Ok(content) if !content.trim().is_empty() => Some(content),
            Ok(_) => None,
            Err(e) => {
                eprintln!("fatal: failed to read license file '{}': {}", path, e);
                std::process::exit(1);
            }
        },
        _ => None,
    };

    let Some(raw) = raw else {
        tracing::info!(plan = "free", "License: no key provided, using Free plan");
        return dbward_domain::license::License::default();
    };

    match dbward_infra::license_key::verify_license_key(&raw) {
        Ok(license) => {
            tracing::info!(
                plan = ?license.plan,
                issued_to = ?license.issued_to,
                expires_at = ?license.expires_at,
                "License loaded"
            );
            license
        }
        Err(e) => {
            eprintln!("fatal: license key verification failed: {e}");
            std::process::exit(1);
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_license_none_returns_free() {
        let license = resolve_license(None, None);
        assert_eq!(license.plan, dbward_domain::license::Plan::Free);
    }

    #[test]
    fn resolve_license_empty_string_returns_free() {
        let license = resolve_license(Some(""), None);
        assert_eq!(license.plan, dbward_domain::license::Plan::Free);
    }

    #[test]
    fn resolve_license_whitespace_only_returns_free() {
        let license = resolve_license(Some("  \n"), None);
        assert_eq!(license.plan, dbward_domain::license::Plan::Free);
    }
}
