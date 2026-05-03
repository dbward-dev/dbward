use std::io::{self, BufRead, Write};

use serde_json::{Value, json};

use dbward_core::{Config, Engine, Role};
use dbward_migrate::Migrator;

pub async fn run_stdio(config: Config, database: Option<&str>) -> Result<(), dbward_core::Error> {
    let resolved = config.resolve_database(database)?;
    let migrations_dir = resolved.migrations_dir.clone();
    let mut engine = Engine::new(&resolved, config.environment.clone()).await?;
    // MCP uses stdout for JSON-RPC, so audit log goes to stderr
    engine.set_audit_logger(dbward_core::AuditLogger::stderr());
    let migrator = Migrator::new(engine.driver().clone(), migrations_dir);

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

        // Notifications have no id and expect no response
        if method == "notifications/initialized" {
            continue;
        }

        let response = match method {
            "initialize" => handle_initialize(id.clone()),
            "tools/list" => handle_tools_list(id.clone()),
            "tools/call" => {
                handle_tools_call(id.clone(), &request["params"], &mut engine, &migrator, &config)
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

fn handle_tools_list(id: Option<Value>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {"tools": tools_definitions()}
    })
}

async fn handle_tools_call(
    id: Option<Value>,
    params: &Value,
    engine: &mut Engine,
    migrator: &Migrator,
    config: &Config,
) -> Value {
    let tool_name = params["name"].as_str().unwrap_or("");
    let args = &params["arguments"];

    let result = match tool_name {
        "dbward_migrate_status" => call_migrate_status(migrator).await,
        "dbward_migrate_up" => {
            let count = args["count"].as_u64().map(|n| n as usize);
            call_migrate_up(migrator, count).await
        }
        "dbward_migrate_down" => {
            let count = args["count"].as_u64().map(|n| n as usize);
            call_migrate_down(migrator, count).await
        }
        "dbward_migrate_create" => {
            let name = args["name"].as_str().unwrap_or("unnamed");
            call_migrate_create(migrator, name)
        }
        "dbward_execute_query" => {
            let sql = args["sql"].as_str().unwrap_or("");
            call_execute_query(engine, sql, config.role).await
        }
        "dbward_audit_search" => {
            Ok("Audit search is only available in server mode.".to_string())
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

async fn call_migrate_status(migrator: &Migrator) -> Result<String, String> {
    let statuses = migrator.status().await.map_err(|e| e.to_string())?;
    if statuses.is_empty() {
        return Ok("No migration files found.".to_string());
    }
    let lines: Vec<String> = statuses
        .iter()
        .map(|s| {
            let mark = if s.applied { "[x]" } else { "[ ]" };
            format!("{mark} {}_{}", s.version, s.name)
        })
        .collect();
    Ok(lines.join("\n"))
}

async fn call_migrate_up(migrator: &Migrator, count: Option<usize>) -> Result<String, String> {
    let result = migrator.up(count).await.map_err(|e| e.to_string())?;
    if result.applied.is_empty() {
        Ok("No pending migrations.".to_string())
    } else {
        Ok(format!(
            "Applied {} migration(s):\n{}",
            result.applied.len(),
            result.applied.join("\n")
        ))
    }
}

async fn call_migrate_down(migrator: &Migrator, count: Option<usize>) -> Result<String, String> {
    let result = migrator.down(count).await.map_err(|e| e.to_string())?;
    if result.rolled_back.is_empty() {
        Ok("Nothing to rollback.".to_string())
    } else {
        Ok(format!(
            "Rolled back:\n{}",
            result.rolled_back.join("\n")
        ))
    }
}

fn call_migrate_create(migrator: &Migrator, name: &str) -> Result<String, String> {
    let path = migrator.create(name).map_err(|e| e.to_string())?;
    Ok(format!("Created: {}", path.display()))
}

async fn call_execute_query(
    engine: &mut Engine,
    sql: &str,
    role: Role,
) -> Result<String, String> {
    if sql.is_empty() {
        return Err("sql parameter is required".to_string());
    }
    let result = engine
        .execute_query("mcp_user", role, sql)
        .await
        .map_err(|e| e.to_string())?;

    if result.rows.is_empty() {
        Ok(format!("Rows affected: {}", result.rows_affected))
    } else {
        serde_json::to_string_pretty(&result.rows).map_err(|e| e.to_string())
    }
}

fn tools_definitions() -> Value {
    tools_definitions_base()
}

fn tools_definitions_base() -> Value {
    json!([
        {
            "name": "dbward_migrate_status",
            "description": "Show migration status (applied/pending)",
            "inputSchema": {"type": "object", "properties": {}}
        },
        {
            "name": "dbward_migrate_up",
            "description": "Apply pending database migrations",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "count": {"type": "integer", "description": "Max migrations to apply"}
                }
            }
        },
        {
            "name": "dbward_migrate_down",
            "description": "Rollback database migrations",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "count": {"type": "integer", "description": "Migrations to rollback", "default": 1}
                }
            }
        },
        {
            "name": "dbward_migrate_create",
            "description": "Create a new migration file",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Migration name (e.g. create_users)"}
                },
                "required": ["name"]
            }
        },
        {
            "name": "dbward_execute_query",
            "description": "Execute a SQL query (SELECT/INSERT/UPDATE/DELETE). DDL is rejected.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "sql": {"type": "string", "description": "SQL statement to execute"}
                },
                "required": ["sql"]
            }
        },
        {
            "name": "dbward_audit_search",
            "description": "Search audit log (server mode only)",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "user": {"type": "string", "description": "Filter by user"},
                    "operation": {"type": "string", "description": "Filter by operation"},
                    "limit": {"type": "integer", "description": "Max results", "default": 20}
                }
            }
        }
    ])
}

fn tools_definitions_server() -> Value {
    let mut tools: Vec<Value> = serde_json::from_value(tools_definitions_base()).unwrap();
    tools.push(json!({
        "name": "dbward_check_request",
        "description": "Check the status of a pending approval request. Returns status and execution_token if approved.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "request_id": {"type": "string", "description": "Request ID to check"}
            },
            "required": ["request_id"]
        }
    }));
    tools.push(json!({
        "name": "dbward_resume_execution",
        "description": "Resume execution of an approved request. Verifies the execution token and runs the operation locally.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "request_id": {"type": "string", "description": "Request ID to resume"}
            },
            "required": ["request_id"]
        }
    }));
    json!(tools)
}

pub async fn run_stdio_server_mode(
    config: Config,
    database: Option<&str>,
    client: crate::server_client::ServerClient,
    public_key: ed25519_dalek::VerifyingKey,
) -> Result<(), dbward_core::Error> {
    let resolved = config.resolve_database(database)?;
    let migrations_dir = resolved.migrations_dir.clone();
    let mut engine = Engine::new(&resolved, config.environment.clone()).await?;
    engine.set_audit_logger(dbward_core::AuditLogger::stderr());
    let migrator = Migrator::new(engine.driver().clone(), migrations_dir);
    let env_str = config.environment.to_string();

    // Track pending requests for resume
    let mut pending_requests: std::collections::HashMap<String, PendingRequest> =
        std::collections::HashMap::new();

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
                "result": {"tools": tools_definitions_server()}
            }),
            "tools/call" => {
                handle_tools_call_server_async(
                    id.clone(),
                    &request["params"],
                    &mut engine,
                    &migrator,
                    &config,
                    &client,
                    &public_key,
                    &env_str,
                    &mut pending_requests,
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

struct PendingRequest {
    operation: String,
    environment: String,
    detail: String,
}

async fn handle_tools_call_server_async(
    id: Option<Value>,
    params: &Value,
    engine: &mut Engine,
    migrator: &Migrator,
    config: &Config,
    client: &crate::server_client::ServerClient,
    public_key: &ed25519_dalek::VerifyingKey,
    env_str: &str,
    pending: &mut std::collections::HashMap<String, PendingRequest>,
) -> Value {
    let tool_name = params["name"].as_str().unwrap_or("");
    let args = &params["arguments"];

    let result = match tool_name {
        "dbward_migrate_create" => {
            let name = args["name"].as_str().unwrap_or("unnamed");
            call_migrate_create(migrator, name)
        }
        "dbward_check_request" => {
            let req_id = args["request_id"].as_str().unwrap_or("");
            check_request(client, req_id).await
        }
        "dbward_resume_execution" => {
            let req_id = args["request_id"].as_str().unwrap_or("");
            resume_execution(client, public_key, engine, migrator, config, pending, req_id).await
        }
        "dbward_execute_query" => {
            let sql = args["sql"].as_str().unwrap_or("");
            if sql.is_empty() {
                Err("sql parameter is required".to_string())
            } else {
                server_flow_async(client, "execute_query", env_str, sql, pending).await
            }
        }
        "dbward_migrate_up" => {
            let count = args["count"].as_u64().map(|n| n as usize);
            let detail = format!("count:{}", count.unwrap_or(0));
            server_flow_async(client, "migrate_up", env_str, &detail, pending).await
        }
        "dbward_migrate_down" => {
            let count = args["count"].as_u64().map(|n| n as usize);
            let detail = format!("count:{}", count.unwrap_or(1));
            server_flow_async(client, "migrate_down", env_str, &detail, pending).await
        }
        "dbward_migrate_status" => {
            server_flow_async(client, "migrate_status", env_str, "", pending).await
        }
        "dbward_audit_search" => {
            Ok("Audit search via server: not yet implemented.".to_string())
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

/// Non-blocking: create request, if auto_approved execute immediately, if pending return request_id.
async fn server_flow_async(
    client: &crate::server_client::ServerClient,
    operation: &str,
    environment: &str,
    detail: &str,
    pending: &mut std::collections::HashMap<String, PendingRequest>,
) -> Result<String, String> {
    let (req_id, status, _token) = client
        .create_request(operation, environment, detail, false, None)
        .await
        .map_err(|e| e.to_string())?;

    match status.as_str() {
        "auto_approved" => {
            // Store for resume_execution
            pending.insert(
                req_id.clone(),
                PendingRequest {
                    operation: operation.to_string(),
                    environment: environment.to_string(),
                    detail: detail.to_string(),
                },
            );
            Ok(format!(
                "Request {req_id} auto-approved. Call dbward_resume_execution with request_id=\"{req_id}\" to execute."
            ))
        }
        "pending" => {
            pending.insert(
                req_id.clone(),
                PendingRequest {
                    operation: operation.to_string(),
                    environment: environment.to_string(),
                    detail: detail.to_string(),
                },
            );
            Ok(format!(
                "Request {req_id} requires approval. A team member must approve it. \
                 Then call dbward_check_request to check status, and dbward_resume_execution to execute."
            ))
        }
        _ => Err(format!("unexpected status: {status}")),
    }
}

async fn check_request(
    client: &crate::server_client::ServerClient,
    request_id: &str,
) -> Result<String, String> {
    if request_id.is_empty() {
        return Err("request_id is required".to_string());
    }
    // poll_request with 0 timeout = single check
    let resp = client
        .get_request(request_id)
        .await
        .map_err(|e| e.to_string())?;
    let status = resp["status"].as_str().unwrap_or("unknown");
    match status {
        "pending" => Ok(format!("Request {request_id} is still pending approval.")),
        "approved" | "auto_approved" => Ok(format!(
            "Request {request_id} is approved. Call dbward_resume_execution with request_id=\"{request_id}\" to execute."
        )),
        "rejected" => Ok(format!("Request {request_id} was rejected.")),
        "executed" => Ok(format!("Request {request_id} was already executed.")),
        _ => Ok(format!("Request {request_id} status: {status}")),
    }
}

async fn resume_execution(
    client: &crate::server_client::ServerClient,
    public_key: &ed25519_dalek::VerifyingKey,
    engine: &mut Engine,
    migrator: &Migrator,
    config: &Config,
    pending: &mut std::collections::HashMap<String, PendingRequest>,
    request_id: &str,
) -> Result<String, String> {
    if request_id.is_empty() {
        return Err("request_id is required".to_string());
    }

    let pr = pending
        .get(request_id)
        .ok_or_else(|| format!("request {request_id} not found in this session"))?;

    // Fetch current state + token
    let resp = client
        .get_request(request_id)
        .await
        .map_err(|e| e.to_string())?;

    let status = resp["status"].as_str().unwrap_or("");
    if status != "approved" && status != "auto_approved" {
        return Err(format!("request is {status}, not approved"));
    }

    let token: dbward_core::token::ExecutionToken =
        serde_json::from_value(resp["execution_token"].clone())
            .map_err(|e| format!("missing execution_token: {e}"))?;

    dbward_core::token::verify_token(
        &token,
        public_key,
        &pr.operation,
        &pr.environment,
        &token.database,
        &pr.detail,
    )
    .map_err(|e| e.to_string())?;

    // Execute
    let result = match pr.operation.as_str() {
        "execute_query" => call_execute_query(engine, &pr.detail, config.role).await,
        "migrate_up" => {
            let count = pr.detail.strip_prefix("count:").and_then(|s| s.parse().ok());
            let count = if count == Some(0) { None } else { count };
            call_migrate_up(migrator, count).await
        }
        "migrate_down" => {
            let count = pr.detail.strip_prefix("count:").and_then(|s| s.parse().ok());
            call_migrate_down(migrator, count).await
        }
        "migrate_status" => call_migrate_status(migrator).await,
        _ => Err(format!("unknown operation: {}", pr.operation)),
    };

    let success = result.is_ok();
    let _ = client.complete_request(request_id, success).await;
    pending.remove(request_id);

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_response_has_protocol_version() {
        let resp = handle_initialize(Some(json!(1)));
        assert_eq!(resp["jsonrpc"], "2.0");
        assert_eq!(resp["id"], 1);
        assert_eq!(resp["result"]["protocolVersion"], "2024-11-05");
        assert_eq!(resp["result"]["serverInfo"]["name"], "dbward");
    }

    #[test]
    fn tools_list_returns_tools_array() {
        let resp = handle_tools_list(Some(json!(2)));
        assert_eq!(resp["id"], 2);
        let tools = resp["result"]["tools"].as_array().unwrap();
        assert!(!tools.is_empty());
        // Every tool should have name and description
        for tool in tools {
            assert!(tool["name"].is_string());
            assert!(tool["description"].is_string());
        }
    }

    #[test]
    fn tools_definitions_include_core_tools() {
        let defs = tools_definitions();
        let names: Vec<&str> = defs.as_array().unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"dbward_migrate_status"));
        assert!(names.contains(&"dbward_execute_query"));
    }
}
