use serde_json::Value;

use super::ToolContext;
use super::request::with_elicitation;

pub(super) async fn migrate_status(ctx: &ToolContext<'_>, args: &Value) -> Result<String, String> {
    let db = args["database"].as_str().unwrap_or(ctx.default_database);
    let env = args["environment"]
        .as_str()
        .unwrap_or(ctx.default_environment);
    let reason = args["reason"].as_str().map(String::from);

    with_elicitation(ctx, reason, |r| {
        ctx.backend.migrate_status(db, env, r, ctx.user)
    })
    .await
    .map(|v| serde_json::to_string_pretty(&v).unwrap_or_default())
}
