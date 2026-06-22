use serde_json::Value;

use super::super::server::ElicitHandle;
use super::request::submit_and_wait;

pub(super) async fn handle_inspect_schema(
    client: &crate::server_client::ServerClient,
    args: &Value,
    env: &str,
    db_name: &str,
) -> Result<String, String> {
    let db = args["database"].as_str().unwrap_or(db_name);
    let table = args["table"].as_str().unwrap_or("");

    // Use server schema API (same source as MCP resource)
    let path = if table.is_empty() {
        if env.is_empty() {
            format!("/api/schemas/{db}")
        } else {
            format!("/api/schemas/{db}?environment={env}")
        }
    } else {
        // Simple percent-encode for query param safety
        let encoded: String = table
            .bytes()
            .flat_map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' => {
                    vec![b as char]
                }
                _ => format!("%{b:02X}").chars().collect(),
            })
            .collect();
        if env.is_empty() {
            format!("/api/schemas/{db}?table={encoded}")
        } else {
            format!("/api/schemas/{db}?environment={env}&table={encoded}")
        }
    };

    match client.get_json_with_status(&path).await {
        Ok((200, resp)) => Ok(serde_json::to_string_pretty(&resp).unwrap_or_default()),
        Ok((403, _)) => Err(format!("Access denied to schema for database '{db}'.")),
        Ok((404, resp)) => {
            let error = resp["error"].as_str().unwrap_or("not found");
            Err(error.to_string())
        }
        Ok((status, resp)) => {
            let error = resp["error"].as_str().unwrap_or("unknown error");
            Err(format!("Schema request failed ({status}): {error}"))
        }
        Err(e) => Err(e.to_string()),
    }
}

pub(super) async fn handle_preview_impact(
    client: &crate::server_client::ServerClient,
    sql: &str,
    env: &str,
    db_name: &str,
    args: &Value,
    elicit: &ElicitHandle,
    client_supports_elicitation: bool,
) -> Result<String, String> {
    let db = args["database"].as_str().unwrap_or(db_name);
    let reason = args["reason"].as_str();
    let explain_sql = format!("EXPLAIN {sql}");
    submit_and_wait(
        client,
        "execute_query",
        env,
        db,
        &explain_sql,
        reason,
        elicit,
        client_supports_elicitation,
    )
    .await
}
