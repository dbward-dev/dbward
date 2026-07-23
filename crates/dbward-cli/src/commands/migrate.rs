use clap::Subcommand;
use serde::Serialize;
use serde_json::Value;

use crate::config::ClientConfig;
use crate::output::CliError;
use crate::output::{CliResponse, OutputMode, ProgressSink, RenderPlan, StderrLine, StdoutRender};
use crate::server_client::{CreateRequest, ServerClient};

use super::helpers::build_request_metadata;
use super::workflow;

#[derive(Subcommand)]
pub enum MigrateAction {
    Up {
        #[arg(long)]
        count: Option<usize>,
        #[arg(long)]
        ticket: Option<String>,
        #[arg(long)]
        repo: Option<String>,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
        #[arg(long = "share-with")]
        share_with: Vec<String>,
    },
    Down {
        #[arg(long, default_value = "1")]
        count: usize,
        #[arg(long)]
        ticket: Option<String>,
        #[arg(long)]
        repo: Option<String>,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    Status {
        #[arg(long)]
        ticket: Option<String>,
        #[arg(long)]
        repo: Option<String>,
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    Create {
        name: String,
    },
    /// Repair schema_migrations metadata (mark-applied or remove a version).
    /// Requires --emergency flag.
    Repair {
        /// Action: "mark-applied" or "remove"
        #[arg(long, required = true)]
        action: String,
        /// Migration version to repair
        #[arg(long, required = true)]
        version: String,
        /// Required safety flag
        #[arg(long)]
        emergency: bool,
        /// Reason for emergency repair (required)
        #[arg(long)]
        reason: Option<String>,
        #[arg(long)]
        ticket: Option<String>,
        #[arg(long)]
        repo: Option<String>,
    },
}

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct MigrateCreateOutput {
    pub path: String,
}

// ---------------------------------------------------------------------------
// Create subcommand (local-only)
// ---------------------------------------------------------------------------

pub fn run_migrate_create(
    config: &ClientConfig,
    db_name: &str,
    name: &str,
) -> Result<CliResponse<MigrateCreateOutput>, CliError> {
    let migrations_dir = config.migrations_dir_for(db_name);
    let migrator = dbward_migrate::LocalMigrator::new(migrations_dir);
    let path = migrator.create(name)?;

    let output = MigrateCreateOutput {
        path: path.display().to_string(),
    };
    let render = RenderPlan::status(format!("Created: {}", path.display()));
    Ok(CliResponse::ok(output, render))
}

// ---------------------------------------------------------------------------
// Main migrate command
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub async fn run_migrate(
    sc: &ServerClient,
    config: &ClientConfig,
    db_name: &str,
    env_str: &str,
    mode: OutputMode,
    action: &MigrateAction,
    yes: bool,
    progress: &ProgressSink,
) -> Result<CliResponse<Value>, CliError> {
    let (operation, detail, metadata, idempotency_key, share_with) = match action {
        MigrateAction::Up {
            count,
            ticket,
            repo,
            idempotency_key,
            share_with,
        } => {
            let migrations_dir = config.migrations_dir_for(db_name);
            let mut d = dbward_migrate::build_migrate_up_detail(&migrations_dir, &[])
                .map_err(|e| CliError::Internal(e.to_string()))?;
            if d.migrations.is_empty() {
                if !migrations_dir.exists() {
                    return Err(CliError::Internal(format!(
                        "migrations directory not found: {}",
                        migrations_dir.display()
                    )));
                }
                let has_sql_files = match std::fs::read_dir(&migrations_dir) {
                    Ok(entries) => entries
                        .filter_map(|e| e.ok())
                        .any(|e| e.path().extension().is_some_and(|ext| ext == "sql")),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
                    Err(e) => {
                        return Err(CliError::Internal(format!(
                            "cannot read migrations directory {}: {e}",
                            migrations_dir.display()
                        )));
                    }
                };
                if has_sql_files {
                    return Err(CliError::Internal(format!(
                        "found .sql files in {} but none matched the expected format.\n\
                         Expected: <timestamp>_<name>.sql with '-- migrate:up' marker inside.\n\
                         Run 'dbward migrate create <name>' to generate a correctly formatted file.",
                        migrations_dir.display()
                    )));
                }
                let render = RenderPlan::status(format!(
                    "No pending migrations found in {}",
                    migrations_dir.display()
                ));
                return Ok(CliResponse::empty(render));
            }
            d.max_count = *count;
            let detail_str = d
                .to_detail_string()
                .map_err(|e| CliError::Internal(e.to_string()))?;
            (
                "migrate_up",
                detail_str,
                build_request_metadata(ticket.as_deref(), repo.as_deref()),
                idempotency_key.as_deref(),
                share_with.as_slice(),
            )
        }
        MigrateAction::Down {
            count,
            ticket,
            repo,
            idempotency_key,
        } => {
            let migrations_dir = config.migrations_dir_for(db_name);
            let all_down = dbward_migrate::list_down_versions(&migrations_dir)
                .map_err(|e| CliError::Internal(e.to_string()))?;
            let mut d = dbward_migrate::build_migrate_down_detail(&migrations_dir, &all_down)
                .map_err(|e| CliError::Internal(e.to_string()))?;
            d.max_count = Some(*count);
            let detail_str = d
                .to_detail_string()
                .map_err(|e| CliError::Internal(e.to_string()))?;
            (
                "migrate_down",
                detail_str,
                build_request_metadata(ticket.as_deref(), repo.as_deref()),
                idempotency_key.as_deref(),
                [].as_slice(),
            )
        }
        MigrateAction::Status {
            ticket,
            repo,
            idempotency_key,
        } => (
            "migrate_status",
            String::new(),
            build_request_metadata(ticket.as_deref(), repo.as_deref()),
            idempotency_key.as_deref(),
            [].as_slice(),
        ),
        MigrateAction::Create { .. } => unreachable!(),
        MigrateAction::Repair {
            action,
            version,
            emergency,
            reason,
            ticket,
            repo,
        } => {
            if !emergency {
                return Err(CliError::Internal(
                    "--emergency flag is required for migrate repair. \
                     This command modifies schema_migrations metadata only, not the actual schema. \
                     Verify DB state manually before use."
                        .into(),
                ));
            }
            if reason.is_none() {
                return Err(CliError::Internal(
                    "--reason is required for emergency repair requests.".into(),
                ));
            }
            let repair_action = match action.as_str() {
                "mark-applied" => "mark_applied",
                "remove" => "remove",
                _ => {
                    return Err(CliError::Internal(format!(
                        "unknown repair action '{action}'. Valid: mark-applied, remove"
                    )));
                }
            };
            let detail = serde_json::json!({
                "action": repair_action,
                "version": version,
            })
            .to_string();
            (
                "migrate_repair",
                detail,
                build_request_metadata(ticket.as_deref(), repo.as_deref()),
                None::<&str>,
                [].as_slice(),
            )
        }
    };

    let sw = if share_with.is_empty() {
        None
    } else {
        Some(share_with)
    };

    let emergency = matches!(action, MigrateAction::Repair { .. });
    let reason = match action {
        MigrateAction::Repair { reason, .. } => reason.as_deref(),
        _ => None,
    };

    // migrate_status is read-only — no confirmation needed
    if operation != "migrate_status" {
        crate::output::confirm_or_reject(mode, yes)?;
    }

    let cancellable = operation != "migrate_status";

    // WHY: ctrl_c() future resolves only once. Pin and share via &mut across
    // two sequential select! blocks so Ctrl-C during either create or wait is caught.
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    // Step 1: Create request (with Ctrl-C escape)
    let cr = tokio::select! {
        result = workflow::create_request(
            sc,
            CreateRequest {
                operation,
                environment: env_str,
                database: db_name,
                detail: &detail,
                emergency,
                allow_ddl: false,
                reason,
                metadata: metadata.as_ref(),
                idempotency_key,
                share_with: sw,
                no_result_store: false,
            },
        ) => result?,
        _ = &mut ctrl_c => {
            let output = serde_json::json!({
                "interrupted": true,
                "message": "If a request was created, check: dbward request list"
            });
            let render = RenderPlan {
                stdout: StdoutRender::None,
                stderr: vec![
                    StderrLine::Warn("Interrupted.".into()),
                    StderrLine::Hint("If a request was created, check: dbward request list".into()),
                ],
            };
            return Ok(CliResponse::ok(output, render)
                .with_issues(130, "interrupted", "operation interrupted by user"));
        }
    };
    let request_id = &cr.request_id;

    // Step 2: Exhaustive status branch
    match cr.status {
        // States that require waiting → proceed to Step 3
        dbward_api_types::requests::RequestStatus::Dispatched
        | dbward_api_types::requests::RequestStatus::Running
        | dbward_api_types::requests::RequestStatus::AutoApproved
        | dbward_api_types::requests::RequestStatus::BreakGlass => {}

        // Already terminal → resolve immediately
        dbward_api_types::requests::RequestStatus::Executed
        | dbward_api_types::requests::RequestStatus::Failed => {
            let result = workflow::resolve_terminal_result(sc, request_id).await?;
            let pretty = serde_json::to_string_pretty(&result).unwrap_or_default();
            let render = RenderPlan {
                stdout: StdoutRender::Raw { value: pretty },
                stderr: vec![],
            };
            return Ok(CliResponse::ok(result, render));
        }

        // Pending approval
        dbward_api_types::requests::RequestStatus::Pending => {
            let output = serde_json::json!({
                "request_id": request_id,
                "status": "pending_approval",
                "approvers": cr.approvers,
            });
            let mut stderr = vec![StderrLine::Status(format!(
                "Request {request_id} requires approval."
            ))];
            if !cr.approvers.is_empty() {
                stderr.push(StderrLine::Info(
                    "Approvers".into(),
                    cr.approvers.join(", "),
                ));
            }
            stderr.push(StderrLine::Hint(format!(
                "Run: dbward request resume {request_id}"
            )));
            let render = RenderPlan {
                stdout: StdoutRender::None,
                stderr,
            };
            return Ok(CliResponse::ok(output, render).with_issues(
                2,
                "pending_approval",
                format!("request {request_id} requires approval"),
            ));
        }

        // Approved but not yet resumed
        dbward_api_types::requests::RequestStatus::Approved => {
            let output = serde_json::json!({
                "request_id": request_id,
                "status": "approved",
            });
            let render = RenderPlan {
                stdout: StdoutRender::None,
                stderr: vec![
                    StderrLine::Status(format!(
                        "Request {request_id} is approved but not yet resumed."
                    )),
                    StderrLine::Hint(format!("Run: dbward request resume {request_id}")),
                ],
            };
            return Ok(CliResponse::ok(output, render).with_issues(
                2,
                "approved_pending_resume",
                format!("request {request_id} is approved but not yet resumed"),
            ));
        }

        // Terminal failure states (idempotency may return these)
        dbward_api_types::requests::RequestStatus::Rejected => {
            let output = serde_json::json!({ "request_id": request_id, "status": "rejected" });
            let render = RenderPlan {
                stdout: StdoutRender::None,
                stderr: vec![StderrLine::Warn(format!(
                    "Request {request_id} was rejected."
                ))],
            };
            return Ok(CliResponse::ok(output, render).with_issues(
                1,
                "rejected",
                "request was rejected",
            ));
        }
        dbward_api_types::requests::RequestStatus::Cancelled => {
            let output = serde_json::json!({ "request_id": request_id, "status": "cancelled" });
            let render = RenderPlan {
                stdout: StdoutRender::None,
                stderr: vec![StderrLine::Warn(format!(
                    "Request {request_id} was already cancelled."
                ))],
            };
            return Ok(CliResponse::ok(output, render).with_issues(
                1,
                "cancelled",
                "request was cancelled",
            ));
        }
        dbward_api_types::requests::RequestStatus::Expired => {
            let output = serde_json::json!({ "request_id": request_id, "status": "expired" });
            let render = RenderPlan {
                stdout: StdoutRender::None,
                stderr: vec![StderrLine::Warn(format!(
                    "Request {request_id} has expired."
                ))],
            };
            return Ok(CliResponse::ok(output, render).with_issues(
                1,
                "expired",
                "request has expired",
            ));
        }
        dbward_api_types::requests::RequestStatus::ExecutionLost => {
            let output =
                serde_json::json!({ "request_id": request_id, "status": "execution_lost" });
            let render = RenderPlan {
                stdout: StdoutRender::None,
                stderr: vec![
                    StderrLine::Warn(format!("Request {request_id} execution was lost.")),
                    StderrLine::Hint(format!("Re-resume: dbward request resume {request_id}")),
                ],
            };
            return Ok(CliResponse::ok(output, render).with_issues(
                1,
                "execution_lost",
                "execution was lost",
            ));
        }

        // Unknown status from newer server
        _ => {
            return Err(CliError::Api {
                code: "server_error".into(),
                message: format!("unexpected status from create_request: {}", cr.status),
            });
        }
    }

    // Step 3: Wait for completion with Ctrl-C
    let result = tokio::select! {
        result = workflow::wait_for_completion(sc, request_id, cr.status, true, progress) => result?,
        _ = &mut ctrl_c => {
            return Ok(workflow::handle_interrupt(sc, request_id, mode, &[], cancellable).await);
        }
    };

    let pretty = serde_json::to_string_pretty(&result).unwrap_or_default();
    let render = RenderPlan {
        stdout: StdoutRender::Raw { value: pretty },
        stderr: vec![],
    };
    Ok(CliResponse::ok(result, render))
}
