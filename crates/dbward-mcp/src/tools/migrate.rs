use serde_json::Value;

use crate::ports::{ElicitResult, McpError};

use super::ToolContext;

pub(super) async fn migrate_status(ctx: &ToolContext<'_>, args: &Value) -> Result<String, String> {
    let db = args["database"].as_str().unwrap_or(ctx.default_database);
    let env = args["environment"]
        .as_str()
        .unwrap_or(ctx.default_environment);
    let reason = args["reason"].as_str().map(String::from);

    match ctx
        .backend
        .migrate_status(db, env, reason.as_deref(), ctx.user)
        .await
    {
        Ok(v) => Ok(serde_json::to_string_pretty(&v).unwrap_or_default()),
        Err(McpError::ReasonRequired { message, schema })
            if reason.is_none() && ctx.elicit.supported() =>
        {
            match ctx.elicit.ask(&message, schema).await {
                Ok(ElicitResult::Accept { content }) => {
                    let r = content["reason"]
                        .as_str()
                        .ok_or("reason field missing in elicitation response")?;
                    ctx.backend
                        .migrate_status(db, env, Some(r), ctx.user)
                        .await
                        .map(|v| serde_json::to_string_pretty(&v).unwrap_or_default())
                        .map_err(|e| e.to_string())
                }
                _ => Err(message),
            }
        }
        Err(e) => Err(e.to_string()),
    }
}
