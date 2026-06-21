use async_trait::async_trait;
use serde_json::{Value, json};

use dbward_app::error::AppError;
use dbward_app::use_cases::audit_query::AuditListInput;
use dbward_app::use_cases::create_request::{CreateRequestInput as AppCreateInput, RequestChannel};
use dbward_app::use_cases::get_schema::GetSchemaInput;
use dbward_app::use_cases::resume_request::ResumeRequestInput;
use dbward_app::use_cases::stream_result::{StreamResultData, StreamResultInput};
use dbward_domain::auth::AuthUser;
use dbward_domain::entities::{AuditContext, RequestStatus};
use dbward_domain::values::{DatabaseName, Environment, Operation};
use dbward_mcp::ports::{
    CreateRequestInput, CreateRequestOutput, McpBackend, McpError, McpResult,
    RequestStatus as McpStatus, WaitOutput,
};

use crate::state::AppState;

#[derive(Clone)]
pub(crate) struct ServerMcpBackend {
    pub(crate) state: AppState,
    pub(crate) audit_ctx: AuditContext,
}

#[async_trait]
impl McpBackend for ServerMcpBackend {
    async fn create_request(
        &self,
        input: CreateRequestInput,
        user: &AuthUser,
    ) -> McpResult<CreateRequestOutput> {
        let operation = input
            .operation
            .parse::<Operation>()
            .map_err(|e| format!("Invalid operation: {e}"))?;
        let db =
            DatabaseName::new(&input.database).map_err(|e| McpError::Internal(e.to_string()))?;
        let env =
            Environment::new(&input.environment).map_err(|e| McpError::Internal(e.to_string()))?;

        let app_input = AppCreateInput {
            database: db,
            environment: env,
            operation,
            detail: input.detail,
            reason: input.reason,
            emergency: false,
            allow_ddl: false,
            idempotency_key: input.idempotency_key,
            share_with: vec![],
            no_result_store: false,
            metadata_json: "{}".into(),
            channel: RequestChannel::Mcp,
        };

        let ctx = self.audit_ctx.clone();
        let output = self
            .state
            .requests()
            .create()
            .execute(app_input, user, &ctx)
            .map_err(format_app_error)?;

        Ok(CreateRequestOutput {
            request_id: output.id,
            status: match output.status {
                RequestStatus::Pending => McpStatus::Pending,
                RequestStatus::Approved | RequestStatus::Dispatched => McpStatus::Approved,
                RequestStatus::Rejected => McpStatus::Rejected,
                _ => McpStatus::Failed,
            },
        })
    }

    async fn resume_and_wait(
        &self,
        request_id: &str,
        timeout_secs: u64,
        user: &AuthUser,
    ) -> McpResult<WaitOutput> {
        let ctx = self.audit_ctx.clone();
        let resume_output = match self
            .state
            .requests()
            .resume()
            .execute(
                ResumeRequestInput {
                    request_id: request_id.into(),
                },
                user,
                &ctx,
            ) {
            Ok(o) => o,
            Err(AppError::Conflict(_)) => {
                // Already dispatched/running — skip resume, go straight to stream
                return self.stream_result(request_id, timeout_secs, user).await;
            }
            Err(e) => return Err(format_app_error(e)),
        };

        if resume_output.status == RequestStatus::Pending {
            return Ok(WaitOutput::Pending {
                request_id: request_id.into(),
            });
        }

        self.stream_result(request_id, timeout_secs, user).await
    }

    async fn wait_request(
        &self,
        request_id: &str,
        timeout_secs: u64,
        user: &AuthUser,
    ) -> McpResult<WaitOutput> {
        self.stream_result(request_id, timeout_secs, user).await
    }

    async fn list_pending(&self, limit: u32, user: &AuthUser) -> McpResult<Value> {
        use dbward_app::use_cases::list_requests::ListRequestsInput;
        let input = ListRequestsInput {
            limit: Some(limit),
            offset: Some(0),
            status: None,
            user: None,
            pending_for_me: Some(true),
        };
        let output = self
            .state
            .requests()
            .list()
            .execute(input, user)
            .map_err(format_app_error)?;

        Ok(json!(
            output
                .requests
                .iter()
                .map(|r| json!({
                    "id": r.id,
                    "operation": r.operation,
                    "database": r.database,
                    "environment": r.environment,
                    "requester": r.requester,
                    "status": format!("{:?}", r.status),
                    "created_at": r.created_at.to_rfc3339(),
                }))
                .collect::<Vec<_>>()
        ))
    }

    async fn find_similar(&self, sql: &str, limit: u32, user: &AuthUser) -> McpResult<Value> {
        use dbward_domain::auth::Permission;
        self.state
            .authorizer
            .authorize_global(user, Permission::RequestView)
            .map_err(|e| format!("Permission denied: {e}"))?;

        let (requests, _) = self
            .state
            .request_reader()
            .list_visible_to_user(
                &user.subject_id,
                &user.groups,
                &user
                    .roles
                    .iter()
                    .map(|r| r.name.clone())
                    .collect::<Vec<_>>(),
                Some("completed"),
                limit,
                0,
            )
            .map_err(format_app_error)?;

        // Client-side containment filter
        let normalized = sql.to_lowercase();
        let results: Vec<Value> = requests
            .iter()
            .filter(|r| {
                r.detail.to_lowercase().contains(&normalized)
                    || normalized.contains(&r.detail.to_lowercase())
            })
            .take(limit as usize)
            .map(|r| {
                json!({
                    "id": r.id,
                    "operation": format!("{:?}", r.operation),
                    "detail": r.detail,
                    "database": r.database.as_str(),
                    "environment": r.environment.as_str(),
                    "created_at": r.created_at.to_rfc3339(),
                })
            })
            .collect();

        Ok(json!(results))
    }

    async fn preview_impact(
        &self,
        sql: &str,
        database: &str,
        environment: &str,
        user: &AuthUser,
    ) -> McpResult<Value> {
        // preview_impact creates a request with operation "explain"
        let db = DatabaseName::new(database).map_err(|e| McpError::Internal(e.to_string()))?;
        let env = Environment::new(environment).map_err(|e| McpError::Internal(e.to_string()))?;

        let app_input = AppCreateInput {
            database: db,
            environment: env,
            operation: Operation::ExecuteSelect,
            detail: format!("EXPLAIN {sql}"),
            reason: None,
            emergency: false,
            allow_ddl: false,
            idempotency_key: None,
            share_with: vec![],
            no_result_store: true,
            metadata_json: "{}".into(),
            channel: RequestChannel::Mcp,
        };

        let ctx = self.audit_ctx.clone();
        let output = self
            .state
            .requests()
            .create()
            .execute(app_input, user, &ctx)
            .map_err(format_app_error)?;

        // If auto-approved, wait for result
        if output.status != RequestStatus::Pending {
            let resume_input = ResumeRequestInput {
                request_id: output.id.clone(),
            };
            match self
                .state
                .requests()
                .resume()
                .execute(resume_input, user, &ctx)
            {
                Ok(_) | Err(AppError::Conflict(_)) => {}
                Err(e) => {
                    tracing::warn!(error = %e, request_id = %output.id, "resume failed for preview_impact");
                    return Err(format!("resume failed: {e}").into());
                }
            }
            if let WaitOutput::Completed(text) = self.stream_result(&output.id, 30, user).await? {
                return Ok(json!({"plan": text}));
            }
        }

        Ok(json!({"request_id": output.id, "status": "pending_approval"}))
    }

    async fn who_can_approve(&self, request_id: &str, user: &AuthUser) -> McpResult<Value> {
        let output = self
            .state
            .requests()
            .get()
            .execute(request_id, user)
            .map_err(format_app_error)?;

        Ok(json!({
            "request_id": output.request.id,
            "status": format!("{:?}", output.request.status),
            "approval_progress": output.approval_progress,
        }))
    }

    async fn explain_policy_failure(
        &self,
        request_id: Option<&str>,
        _operation: Option<&str>,
        _database: &str,
        _environment: &str,
        user: &AuthUser,
    ) -> McpResult<Value> {
        if let Some(id) = request_id {
            let output = self
                .state
                .requests()
                .get()
                .execute(id, user)
                .map_err(format_app_error)?;

            let trace = output.request.decision_trace_json.unwrap_or_default();
            return Ok(json!({
                "request_id": id,
                "decision_trace": serde_json::from_str::<Value>(&trace).unwrap_or(json!(null)),
            }));
        }

        Ok(json!({"explanation": "Submit a request to see the policy evaluation result."}))
    }

    async fn inspect_schema(
        &self,
        database: &str,
        environment: Option<&str>,
        table: Option<&str>,
        summary: bool,
        user: &AuthUser,
    ) -> McpResult<Value> {
        let input = GetSchemaInput {
            database: database.into(),
            environment: environment.map(String::from),
            table: table.map(String::from),
            summary,
        };

        let output = self
            .state
            .schemas()
            .get()
            .execute(input, user)
            .map_err(format_app_error)?;

        serde_json::to_value(&output).map_err(|e| McpError::Internal(e.to_string()))
    }

    async fn get_request(&self, request_id: &str, user: &AuthUser) -> McpResult<Value> {
        let output = self
            .state
            .requests()
            .get()
            .execute(request_id, user)
            .map_err(format_app_error)?;

        Ok(json!({
            "id": output.request.id,
            "status": format!("{:?}", output.request.status),
            "operation": format!("{:?}", output.request.operation),
            "database": output.request.database.as_str(),
            "environment": output.request.environment.as_str(),
            "requester": output.request.requester,
            "detail": output.detail,
            "reason": output.request.reason,
            "created_at": output.request.created_at.to_rfc3339(),
        }))
    }

    async fn list_databases(&self, user: &AuthUser) -> McpResult<Value> {
        let pairs = self.state.list_databases(user).map_err(format_app_error)?;
        Ok(json!(
            pairs
                .iter()
                .map(|(d, e)| json!({"database": d.as_str(), "environment": e.as_str()}))
                .collect::<Vec<_>>()
        ))
    }

    async fn migrate_status(
        &self,
        database: &str,
        environment: &str,
        user: &AuthUser,
    ) -> McpResult<Value> {
        // migrate_status goes through the request workflow (same as CLI)
        let db = DatabaseName::new(database).map_err(|e| McpError::Internal(e.to_string()))?;
        let env = Environment::new(environment).map_err(|e| McpError::Internal(e.to_string()))?;

        let app_input = AppCreateInput {
            database: db,
            environment: env,
            operation: Operation::MigrateStatus,
            detail: "{}".into(),
            reason: None,
            emergency: false,
            allow_ddl: false,
            idempotency_key: None,
            share_with: vec![],
            no_result_store: true,
            metadata_json: "{}".into(),
            channel: RequestChannel::Mcp,
        };

        let ctx = self.audit_ctx.clone();
        let output = self
            .state
            .requests()
            .create()
            .execute(app_input, user, &ctx)
            .map_err(format_app_error)?;

        if output.status != RequestStatus::Pending {
            let resume_input = ResumeRequestInput {
                request_id: output.id.clone(),
            };
            match self
                .state
                .requests()
                .resume()
                .execute(resume_input, user, &ctx)
            {
                Ok(_) | Err(AppError::Conflict(_)) => {}
                Err(e) => {
                    tracing::warn!(error = %e, request_id = %output.id, "resume failed for migrate_status");
                    return Err(format!("resume failed: {e}").into());
                }
            }
            if let WaitOutput::Completed(text) = self.stream_result(&output.id, 30, user).await? {
                return Ok(serde_json::from_str(&text).unwrap_or(json!({"raw": text})));
            }
        }

        Ok(json!({"request_id": output.id, "status": "pending_approval"}))
    }

    async fn audit_recent(&self, limit: u32, user: &AuthUser) -> McpResult<Value> {
        let input = AuditListInput {
            filter: dbward_app::ports::AuditFilter {
                actor_id: None,
                event_type: None,
                event_category: None,
                outcome: None,
                environment: None,
                database: None,
                since: None,
                until: None,
                limit,
                offset: 0,
            },
        };
        let output = self
            .state
            .admin()
            .audit_query()
            .list(input, user)
            .map_err(format_app_error)?;

        Ok(json!(
            output
                .events
                .iter()
                .map(|e| json!({
                    "id": e.id,
                    "event_type": e.event_type,
                    "actor_id": e.actor_id,
                    "outcome": format!("{:?}", e.outcome),
                    "created_at": e.created_at.to_rfc3339(),
                }))
                .collect::<Vec<_>>()
        ))
    }
}

impl ServerMcpBackend {
    async fn stream_result(
        &self,
        request_id: &str,
        timeout_secs: u64,
        user: &AuthUser,
    ) -> McpResult<WaitOutput> {
        let input = StreamResultInput {
            request_id: request_id.into(),
            timeout_secs: Some(timeout_secs),
        };

        let output = self
            .state
            .requests()
            .stream_result()
            .execute(input, user)
            .await
            .map_err(format_app_error)?;

        match output.data {
            StreamResultData::Result(summary) => {
                let text = if summary.success {
                    summary.result_data.unwrap_or_else(|| {
                        format!(
                            "Execution completed. Rows affected: {}",
                            summary.rows_affected.unwrap_or(0)
                        )
                    })
                } else {
                    summary
                        .error_message
                        .unwrap_or_else(|| "Execution failed.".into())
                };
                Ok(WaitOutput::Completed(text))
            }
            StreamResultData::TerminalPlaceholder { success } => {
                if success {
                    Ok(WaitOutput::Completed(
                        "Execution completed (result not stored).".into(),
                    ))
                } else {
                    Err("Execution failed.".into())
                }
            }
            StreamResultData::Timeout => Ok(WaitOutput::TimedOut {
                request_id: request_id.into(),
            }),
        }
    }
}

fn format_app_error(e: AppError) -> McpError {
    match e {
        AppError::Validation(msg) if msg == "reason_required" => McpError::ReasonRequired {
            message: "reason is required by workflow policy".into(),
            schema: dbward_mcp::ports::reason_elicitation_schema(),
        },
        AppError::NotFound(msg) => McpError::NotFound(msg),
        AppError::Forbidden(err) => McpError::Forbidden(format!("Permission denied: {err}")),
        AppError::Conflict(msg) => McpError::Conflict(msg),
        AppError::Validation(msg) => McpError::Internal(msg),
        AppError::Internal(msg) => McpError::Internal(msg),
        _ => McpError::Internal(e.to_string()),
    }
}
