use serde_json::Value;

use crate::server_client::ServerClient;

pub(super) async fn handle_preflight(
    client: &ServerClient,
    sql: &str,
    env: &str,
    db_name: &str,
    args: &Value,
) -> Result<String, String> {
    let db = args["database"].as_str().unwrap_or(db_name);
    let include_explain = args["include_explain"].as_bool().unwrap_or(true);
    let timeout = args["explain_timeout_ms"].as_u64().unwrap_or(5000);

    match client.preflight(db, env, sql, include_explain, timeout).await {
        Ok(result) => Ok(serde_json::to_string_pretty(&result).unwrap_or_default()),
        Err(e) => Err(format!("preflight failed: {e}")),
    }
}
