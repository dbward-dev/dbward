use serde_json::Value;

use super::ToolContext;

pub(super) async fn inspect_schema(ctx: &ToolContext<'_>, args: &Value) -> Result<String, String> {
    let db = args["database"].as_str().unwrap_or(ctx.default_database);
    let table = args["table"].as_str();
    let value = ctx
        .backend
        .inspect_schema(db, None, table, true, ctx.user)
        .await
        .map_err(|e| e.to_string())?;
    Ok(serde_json::to_string_pretty(&value).unwrap_or_default())
}
