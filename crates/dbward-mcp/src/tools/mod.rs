mod migrate;
mod request;
mod schema;

use serde_json::Value;

use crate::ports::{ElicitationTransport, McpBackend};
use dbward_domain::auth::AuthUser;

/// Context for tool execution.
pub struct ToolContext<'a> {
    pub backend: &'a dyn McpBackend,
    pub elicit: &'a dyn ElicitationTransport,
    pub user: &'a AuthUser,
    pub default_database: &'a str,
    pub default_environment: &'a str,
}

/// Dispatch a tool call by name. Returns (content_text, is_error).
/// Returns None if tool_name is unknown (caller should return JSON-RPC error).
pub async fn dispatch(
    ctx: &ToolContext<'_>,
    tool_name: &str,
    args: &Value,
) -> Option<(String, bool)> {
    let result = match tool_name {
        "dbward_execute_query" => request::execute_query(ctx, args).await,
        "dbward_wait_request" => request::wait_request(ctx, args).await,
        "dbward_list_pending" => request::list_pending(ctx).await,
        "dbward_find_similar_requests" => request::find_similar(ctx, args).await,
        "dbward_who_can_approve" => request::who_can_approve(ctx, args).await,
        "dbward_explain_policy_failure" => request::explain_policy_failure(ctx, args).await,
        "dbward_inspect_schema" => schema::inspect_schema(ctx, args).await,
        "dbward_migrate_status" => migrate::migrate_status(ctx, args).await,
        _ => return None,
    };

    Some(match result {
        Ok(text) => (text, false),
        Err(text) => (text, true),
    })
}
