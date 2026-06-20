use serde_json::Value;

use super::ToolContext;

pub(super) async fn migrate_status(ctx: &ToolContext<'_>, args: &Value) -> Result<String, String> {
    let db = args["database"].as_str().unwrap_or(ctx.default_database);
    let env = args["environment"]
        .as_str()
        .unwrap_or(ctx.default_environment);
    let value = ctx.backend.migrate_status(db, env, ctx.user).await?;
    Ok(serde_json::to_string_pretty(&value).unwrap_or_default())
}
