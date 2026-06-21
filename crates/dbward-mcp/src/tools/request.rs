use serde_json::Value;

use crate::ports::{CreateRequestInput, ElicitResult, McpError, WaitOutput};

use super::ToolContext;

pub(super) async fn execute_query(ctx: &ToolContext<'_>, args: &Value) -> Result<String, String> {
    let sql = require_str(args, "sql")?;
    let db = str_or(args, "database", ctx.default_database);
    let env = str_or(args, "environment", ctx.default_environment);
    let reason = args["reason"].as_str().map(String::from);
    let idempotency_key = args["_idempotency_key"].as_str().map(String::from);

    let make_input = |reason: Option<String>, key: Option<String>| CreateRequestInput {
        operation: "execute".into(),
        environment: env.into(),
        database: db.into(),
        detail: sql.into(),
        reason,
        idempotency_key: key,
    };

    let cr = match ctx
        .backend
        .create_request(
            make_input(reason.clone(), idempotency_key.clone()),
            ctx.user,
        )
        .await
    {
        Ok(cr) => cr,
        Err(McpError::ReasonRequired { message, schema })
            if reason.is_none() && ctx.elicit.supported() =>
        {
            match ctx.elicit.ask(&message, schema).await {
                Ok(ElicitResult::Accept { content }) => {
                    let r = content["reason"]
                        .as_str()
                        .ok_or_else(|| "reason field missing in elicitation response".to_string())?;
                    ctx.backend
                        .create_request(make_input(Some(r.into()), idempotency_key), ctx.user)
                        .await
                        .map_err(|e| e.to_string())?
                }
                _ => return Err(message),
            }
        }
        Err(e) => return Err(e.to_string()),
    };

    if cr.status.is_pending() {
        return Ok(format!(
            "Request {} requires approval. Use dbward_wait_request to wait for completion.",
            cr.request_id
        ));
    }
    if cr.status.is_terminal_failure() {
        return Err(format!("Request {} was {:?}.", cr.request_id, cr.status));
    }
    match ctx
        .backend
        .resume_and_wait(&cr.request_id, 120, ctx.user)
        .await
        .map_err(|e| e.to_string())?
    {
        WaitOutput::Completed(text) => Ok(text),
        WaitOutput::Pending { request_id } => Ok(format!(
            "Request {request_id} requires approval. Use dbward_wait_request to wait for completion."
        )),
        WaitOutput::TimedOut { request_id } => Ok(format!(
            "Request {request_id} is still executing (timed out after 120s). \
             Use dbward_wait_request with request_id '{request_id}' to get the result."
        )),
    }
}

pub(super) async fn wait_request(ctx: &ToolContext<'_>, args: &Value) -> Result<String, String> {
    let request_id = require_str(args, "request_id")?;
    let timeout = args["timeout"].as_u64().unwrap_or(60).min(300);
    let include_result = args["include_result"].as_bool().unwrap_or(true);

    if !include_result {
        let value = ctx.backend.get_request(request_id, ctx.user).await
            .map_err(|e| e.to_string())?;
        return Ok(format_json(value));
    }

    match ctx
        .backend
        .resume_and_wait(request_id, timeout, ctx.user)
        .await
        .map_err(|e| e.to_string())?
    {
        WaitOutput::Completed(text) => Ok(text),
        WaitOutput::Pending { request_id } => {
            Ok(format!("Request {request_id} is still pending approval."))
        }
        WaitOutput::TimedOut { request_id } => Ok(format!(
            "Request {request_id} timed out. Use dbward_wait_request again to retry."
        )),
    }
}

pub(super) async fn list_pending(ctx: &ToolContext<'_>) -> Result<String, String> {
    ctx.backend
        .list_pending(20, ctx.user)
        .await
        .map(format_json)
        .map_err(|e| e.to_string())
}

pub(super) async fn find_similar(ctx: &ToolContext<'_>, args: &Value) -> Result<String, String> {
    let sql = args["sql"].as_str().unwrap_or("").trim();
    if sql.is_empty() {
        return Err("At least 'sql' parameter is required for similarity search".into());
    }
    let limit = args["limit"].as_u64().unwrap_or(5) as u32;
    ctx.backend
        .find_similar(sql, limit, ctx.user)
        .await
        .map(format_json)
        .map_err(|e| e.to_string())
}

pub(super) async fn preview_impact(ctx: &ToolContext<'_>, args: &Value) -> Result<String, String> {
    let sql = require_str(args, "sql")?;
    let db = str_or(args, "database", ctx.default_database);
    let env = str_or(args, "environment", ctx.default_environment);
    ctx.backend
        .preview_impact(sql, db, env, ctx.user)
        .await
        .map(format_json)
        .map_err(|e| e.to_string())
}

pub(super) async fn who_can_approve(ctx: &ToolContext<'_>, args: &Value) -> Result<String, String> {
    let request_id = require_str(args, "request_id")?;
    ctx.backend
        .who_can_approve(request_id, ctx.user)
        .await
        .map(format_json)
        .map_err(|e| e.to_string())
}

pub(super) async fn explain_policy_failure(
    ctx: &ToolContext<'_>,
    args: &Value,
) -> Result<String, String> {
    let request_id = args["request_id"]
        .as_str()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());
    let operation = args["operation"].as_str();
    let db = str_or(args, "database", ctx.default_database);
    let env = str_or(args, "environment", ctx.default_environment);
    ctx.backend
        .explain_policy_failure(request_id, operation, db, env, ctx.user)
        .await
        .map(format_json)
        .map_err(|e| e.to_string())
}

// --- Helpers ---

fn require_str<'a>(args: &'a Value, key: &str) -> Result<&'a str, String> {
    args[key]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("Missing required argument: {key}"))
}

fn str_or<'a>(args: &'a Value, key: &str, default: &'a str) -> &'a str {
    args[key].as_str().unwrap_or(default)
}

fn format_json(value: Value) -> String {
    serde_json::to_string_pretty(&value).unwrap_or_default()
}
