mod helpers;
mod migrate;
mod request;
mod schema;

use std::path::PathBuf;
use std::sync::Arc;

use serde_json::Value;

use super::defs::{normalize_preview_sql, required_arg};
use super::server::{ElicitHandle, jsonrpc_error};

/// Shared context for all MCP tool handlers.
pub(super) struct McpContext {
    pub(super) client: Arc<crate::server_client::ServerClient>,
    pub(super) db_name: String,
    pub(super) migrations_dir: PathBuf,
    pub(super) default_env: String,
    pub(super) elicit: ElicitHandle,
    pub(super) client_supports_elicitation: bool,
}

pub(super) async fn handle_tools_call(
    id: Option<Value>,
    params: &Value,
    ctx: &McpContext,
) -> Value {
    let tool_name = params["name"].as_str().unwrap_or("");
    let args = &params["arguments"];
    let env = args["environment"].as_str().unwrap_or(&ctx.default_env);

    // Guard: environment must be set for tools that need it
    let needs_env = !matches!(
        tool_name,
        "dbward_migrate_create"
            | "dbward_wait_request"
            | "dbward_list_pending"
            | "dbward_who_can_approve"
            | "dbward_find_similar_requests"
            | "dbward_inspect_schema"
            | "dbward_explain_policy_failure"
    );
    if needs_env && env.is_empty() {
        return jsonrpc_error(
            id,
            -32602,
            "environment is required. Set DBWARD_ENV or default_environment in config.",
        );
    }

    let result = match tool_name {
        "dbward_execute_query" => {
            request::handle_execute_query(
                &ctx.client,
                args,
                env,
                &ctx.db_name,
                &ctx.elicit,
                ctx.client_supports_elicitation,
            )
            .await
        }
        "dbward_migrate_status" => {
            migrate::handle_migrate_status(
                &ctx.client,
                args,
                env,
                &ctx.db_name,
                &ctx.elicit,
                ctx.client_supports_elicitation,
            )
            .await
        }
        "dbward_migrate_up" => {
            migrate::handle_migrate_up(
                &ctx.client,
                args,
                env,
                &ctx.db_name,
                &ctx.migrations_dir,
                &ctx.elicit,
                ctx.client_supports_elicitation,
            )
            .await
        }
        "dbward_migrate_down" => {
            migrate::handle_migrate_down(
                &ctx.client,
                args,
                env,
                &ctx.db_name,
                &ctx.migrations_dir,
                &ctx.elicit,
                ctx.client_supports_elicitation,
            )
            .await
        }
        "dbward_migrate_create" => migrate::handle_migrate_create(args, &ctx.migrations_dir),
        "dbward_wait_request" => request::handle_wait_request(&ctx.client, args).await,
        "dbward_list_pending" => request::handle_list_pending(&ctx.client).await,
        "dbward_who_can_approve" => {
            let req_id = match required_arg(args, "request_id") {
                Ok(value) => value,
                Err(message) => return jsonrpc_error(id, -32602, message),
            };
            request::handle_who_can_approve(&ctx.client, req_id).await
        }
        "dbward_find_similar_requests" => request::handle_find_similar(&ctx.client, args).await,
        "dbward_preview_impact" => {
            let sql = match required_arg(args, "sql") {
                Ok(value) => value,
                Err(message) => return jsonrpc_error(id, -32602, message),
            };
            let preview_sql = match normalize_preview_sql(sql) {
                Ok(sql) => sql,
                Err(message) => return jsonrpc_error(id, -32602, message),
            };
            schema::handle_preview_impact(
                &ctx.client,
                &preview_sql,
                env,
                &ctx.db_name,
                args,
                &ctx.elicit,
                ctx.client_supports_elicitation,
            )
            .await
        }
        "dbward_explain_policy_failure" => {
            request::handle_explain_policy(&ctx.client, args, env, &ctx.db_name).await
        }
        "dbward_inspect_schema" => {
            schema::handle_inspect_schema(&ctx.client, args, env, &ctx.db_name).await
        }
        _ => Err(format!("Unknown tool: {tool_name}")),
    };

    match result {
        Ok(text) => serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "content": [{"type": "text", "text": text}]
            }
        }),
        Err(e) => serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "content": [{"type": "text", "text": format!("Error: {e}")}],
                "isError": true
            }
        }),
    }
}
