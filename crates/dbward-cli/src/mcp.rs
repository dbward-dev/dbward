use std::io::{self, BufRead, Write};

use serde_json::{Value, json};

use dbward_core::ClientConfig;

pub async fn run_stdio(
    config: ClientConfig,
    database: Option<&str>,
    client: crate::server_client::ServerClient,
) -> Result<(), dbward_core::Error> {
    let db_name = config.resolve_database_name(database)?;
    let migrations_dir = config.migrations_dir_for(&db_name);

    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = line.map_err(dbward_core::Error::Io)?;
        if line.trim().is_empty() {
            continue;
        }

        let request: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let err_resp = json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": {"code": -32700, "message": format!("Parse error: {e}")}
                });
                writeln!(stdout, "{err_resp}").map_err(dbward_core::Error::Io)?;
                stdout.flush().map_err(dbward_core::Error::Io)?;
                continue;
            }
        };

        let id = request.get("id").cloned();
        let method = request["method"].as_str().unwrap_or("");

        if method == "notifications/initialized" {
            continue;
        }

        let response = match method {
            "initialize" => handle_initialize(id.clone()),
            "tools/list" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {"tools": tools_definitions()}
            }),
            "tools/call" => {
                handle_tools_call(
                    id.clone(),
                    &request["params"],
                    &client,
                    &db_name,
                    &migrations_dir,
                )
                .await
            }
            _ => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": -32601, "message": format!("Method not found: {method}")}
            }),
        };

        writeln!(stdout, "{response}").map_err(dbward_core::Error::Io)?;
        stdout.flush().map_err(dbward_core::Error::Io)?;
    }

    Ok(())
}

fn handle_initialize(id: Option<Value>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "protocolVersion": "2024-11-05",
            "serverInfo": {"name": "dbward", "version": env!("CARGO_PKG_VERSION")},
            "capabilities": {"tools": {}}
        }
    })
}

async fn handle_tools_call(
    id: Option<Value>,
    params: &Value,
    client: &crate::server_client::ServerClient,
    db_name: &str,
    migrations_dir: &std::path::Path,
) -> Value {
    let tool_name = params["name"].as_str().unwrap_or("");
    let args = &params["arguments"];
    let env = args["environment"].as_str().unwrap_or("development");

    let result = match tool_name {
        "dbward_execute_query" => {
            let sql = args["sql"].as_str().unwrap_or("");
            let db = args["database"].as_str().unwrap_or(db_name);
            let reason = args["reason"].as_str();
            if sql.is_empty() {
                Err("sql parameter is required".to_string())
            } else {
                submit_and_wait(client, "execute_query", env, db, sql, reason).await
            }
        }
        "dbward_migrate_status" => {
            let db = args["database"].as_str().unwrap_or(db_name);
            submit_and_wait(client, "migrate_status", env, db, "", None).await
        }
        "dbward_migrate_up" => {
            let count = args["count"].as_u64().map(|n| n as usize);
            let db = args["database"].as_str().unwrap_or(db_name);
            match dbward_migrate::build_migration_approval_detail(
                migrations_dir,
                count.unwrap_or(0),
            ) {
                Ok(detail) => {
                    submit_and_wait(
                        client,
                        "migrate_up",
                        env,
                        db,
                        &detail,
                        args["reason"].as_str(),
                    )
                    .await
                }
                Err(e) => Err(e.to_string()),
            }
        }
        "dbward_migrate_down" => {
            let count = args["count"].as_u64().map(|n| n as usize);
            let db = args["database"].as_str().unwrap_or(db_name);
            match dbward_migrate::build_migration_approval_detail(
                migrations_dir,
                count.unwrap_or(1),
            ) {
                Ok(detail) => {
                    submit_and_wait(
                        client,
                        "migrate_down",
                        env,
                        db,
                        &detail,
                        args["reason"].as_str(),
                    )
                    .await
                }
                Err(e) => Err(e.to_string()),
            }
        }
        "dbward_migrate_create" => {
            let name = args["name"].as_str().unwrap_or("unnamed");
            let migrator = dbward_migrate::Migrator::new_local(migrations_dir.to_path_buf());
            match migrator.create(name) {
                Ok(path) => Ok(format!("Created: {}", path.display())),
                Err(e) => Err(e.to_string()),
            }
        }
        "dbward_check_request" => {
            let req_id = args["request_id"].as_str().unwrap_or("");
            let timeout = args["timeout"].as_u64().unwrap_or(30);
            check_request(client, req_id, timeout).await
        }
        "dbward_get_result" => {
            let req_id = args["request_id"].as_str().unwrap_or("");
            get_result(client, req_id).await
        }
        _ => Err(format!("Unknown tool: {tool_name}")),
    };

    match result {
        Ok(text) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "content": [{"type": "text", "text": text}]
            }
        }),
        Err(e) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "content": [{"type": "text", "text": format!("Error: {e}")}],
                "isError": true
            }
        }),
    }
}

/// Submit request, if dispatched wait for result, if pending return request_id.
async fn submit_and_wait(
    client: &crate::server_client::ServerClient,
    operation: &str,
    environment: &str,
    database: &str,
    detail: &str,
    reason: Option<&str>,
) -> Result<String, String> {
    let (req_id, status, _token) = client
        .create_request(crate::server_client::CreateRequest {
            operation,
            environment,
            database,
            detail,
            emergency: false,
            reason,
            metadata: None,
            idempotency_key: None,
            share_with: None,
        })
        .await
        .map_err(|e| e.to_string())?;

    match status.as_str() {
        "dispatched" | "break_glass" => {
            let resp = client
                .wait_for_result(&req_id)
                .await
                .map_err(|e| e.to_string())?;
            format_result(&resp)
        }
        "pending" => Ok(format!(
            "Request {req_id} requires approval. \
                 Use dbward_check_request to check status, \
                 then dbward_get_result to retrieve the result."
        )),
        _ => Err(format!("unexpected status: {status}")),
    }
}

fn format_result(resp: &Value) -> Result<String, String> {
    if resp["success"].as_bool() == Some(false) {
        let err = resp["error"].as_str().unwrap_or("unknown error");
        return Err(format!("Execution failed: {err}"));
    }
    let result = &resp["result"];
    if result.is_null() {
        Ok("Executed successfully.".to_string())
    } else if let Some(text) = result.as_str() {
        Ok(text.to_string())
    } else {
        // For structured results, include truncation info as part of the JSON
        // so AI consumers can parse it programmatically
        Ok(serde_json::to_string_pretty(result).unwrap_or_default())
    }
}

async fn check_request(
    client: &crate::server_client::ServerClient,
    request_id: &str,
    timeout: u64,
) -> Result<String, String> {
    if request_id.is_empty() {
        return Err("request_id is required".to_string());
    }
    let resp = client
        .get_request_with_wait(request_id, timeout)
        .await
        .map_err(|e| e.to_string())?;
    let status = resp["status"].as_str().unwrap_or("unknown");
    match status {
        "pending" => Ok(format!("Request {request_id} is still pending approval.")),
        "approved" | "auto_approved" | "dispatched" => Ok(format!(
            "Request {request_id} is approved. Agent will execute it. \
             Use dbward_get_result to retrieve the result."
        )),
        "executed" => Ok(format!(
            "Request {request_id} executed. Use dbward_get_result to see the result."
        )),
        "rejected" => Ok(format!("Request {request_id} was rejected.")),
        "failed" => Ok(format!("Request {request_id} execution failed.")),
        _ => Ok(format!("Request {request_id} status: {status}")),
    }
}

async fn get_result(
    client: &crate::server_client::ServerClient,
    request_id: &str,
) -> Result<String, String> {
    if request_id.is_empty() {
        return Err("request_id is required".to_string());
    }
    let resp = client
        .get_request(request_id)
        .await
        .map_err(|e| e.to_string())?;
    let status = resp["status"].as_str().unwrap_or("unknown");
    match status {
        "approved" | "auto_approved" | "dispatched" | "break_glass" | "running" => {
            let result = client
                .wait_for_result(request_id)
                .await
                .map_err(|e| e.to_string())?;
            format_result(&result)
        }
        "executed" => {
            let result = client
                .get_terminal_result(request_id)
                .await
                .map_err(|e| e.to_string())?;
            format_result(&result)
        }
        "failed" => {
            let result = client
                .get_terminal_result(request_id)
                .await
                .map_err(|e| e.to_string())?;
            format_result(&result)
        }
        _ => Ok(format!(
            "Request {request_id} is not yet approved (status: {status})."
        )),
    }
}

fn tools_definitions() -> Value {
    json!([
        {
            "name": "dbward_execute_query",
            "description": "Execute a SQL query. The query is submitted for approval and executed by an agent.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "sql": {"type": "string", "description": "SQL statement to execute"},
                    "database": {"type": "string", "description": "Target database name"},
                    "environment": {"type": "string", "description": "Environment (development/staging/production)"},
                    "reason": {"type": "string", "description": "Reason for execution (required by some workflows)"}
                },
                "required": ["sql"]
            }
        },
        {
            "name": "dbward_migrate_status",
            "description": "Show migration status (applied/pending)",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "database": {"type": "string", "description": "Target database name"},
                    "environment": {"type": "string", "description": "Environment"}
                }
            }
        },
        {
            "name": "dbward_migrate_up",
            "description": "Apply pending database migrations",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "count": {"type": "integer", "description": "Max migrations to apply"},
                    "database": {"type": "string", "description": "Target database name"},
                    "environment": {"type": "string", "description": "Environment"}
                }
            }
        },
        {
            "name": "dbward_migrate_down",
            "description": "Rollback database migrations",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "count": {"type": "integer", "description": "Migrations to rollback", "default": 1},
                    "database": {"type": "string", "description": "Target database name"},
                    "environment": {"type": "string", "description": "Environment"}
                }
            }
        },
        {
            "name": "dbward_migrate_create",
            "description": "Create a new migration file (local only, no server needed)",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Migration name (e.g. create_users)"}
                },
                "required": ["name"]
            }
        },
        {
            "name": "dbward_check_request",
            "description": "Check request status. Waits up to timeout seconds for status change.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "request_id": {"type": "string", "description": "Request ID to check"},
                    "timeout": {"type": "integer", "description": "Seconds to wait for status change (default 30, max 60)", "default": 30}
                },
                "required": ["request_id"]
            }
        },
        {
            "name": "dbward_get_result",
            "description": "Get the execution result of a completed request",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "request_id": {"type": "string", "description": "Request ID"}
                },
                "required": ["request_id"]
            }
        }
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_response_has_protocol_version() {
        let resp = handle_initialize(Some(json!(1)));
        assert_eq!(resp["result"]["protocolVersion"], "2024-11-05");
        assert_eq!(resp["result"]["serverInfo"]["name"], "dbward");
    }

    #[test]
    fn tools_definitions_include_all_tools() {
        let defs = tools_definitions();
        let names: Vec<&str> = defs
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"dbward_execute_query"));
        assert!(names.contains(&"dbward_migrate_create"));
        assert!(names.contains(&"dbward_check_request"));
        assert!(names.contains(&"dbward_get_result"));
    }
}
