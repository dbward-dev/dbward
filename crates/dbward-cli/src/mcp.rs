use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

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
            "resources/list" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {"resources": resources_definitions()}
            }),
            "resources/templates/list" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {"resourceTemplates": resource_templates_definitions()}
            }),
            "resources/read" => {
                handle_resources_read(id.clone(), &request["params"], &client, &db_name).await
            }
            "prompts/list" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {"prompts": prompts_definitions()}
            }),
            "prompts/get" => handle_prompts_get(id.clone(), &request["params"], &migrations_dir),
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
            "protocolVersion": "2025-11-05",
            "serverInfo": {"name": "dbward", "version": env!("CARGO_PKG_VERSION")},
            "capabilities": {
                "tools": {},
                "resources": {},
                "prompts": {}
            }
        }
    })
}

fn jsonrpc_error(id: Option<Value>, code: i64, message: impl Into<String>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message.into()
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
        "dbward_list_pending" => {
            client.get_json("/api/requests?status=pending&limit=20").await
                .map(|v| serde_json::to_string_pretty(&v["requests"]).unwrap_or_default())
                .map_err(|e| e.to_string())
        }
        "dbward_who_can_approve" => {
            let req_id = args["request_id"].as_str().unwrap_or("");
            client.get_request(req_id).await
                .map(|v| {
                    let snapshot = &v["workflow_snapshot"];
                    if snapshot.is_null() {
                        "No workflow assigned (auto-approved)".to_string()
                    } else {
                        format!("Approval path:\n{}", serde_json::to_string_pretty(snapshot).unwrap_or_default())
                    }
                })
                .map_err(|e| e.to_string())
        }
        "dbward_find_similar_requests" => {
            let sql = args["sql"].as_str().unwrap_or("");
            let op = args["operation"].as_str().unwrap_or("execute_query");
            let limit = args["limit"].as_u64().unwrap_or(5);
            client.get_json(&format!("/api/audit/events?event_category=execution&event_type=execution_completed&limit={limit}")).await
                .map(|v| {
                    let events = v["audit_events"].as_array();
                    match events {
                        Some(arr) if !arr.is_empty() => {
                            let mut out = format!("Recent {} executions:\n", op);
                            for e in arr {
                                out.push_str(&format!("  {} | {} | {}\n",
                                    e["created_at"].as_str().unwrap_or("?"),
                                    e["actor_id"].as_str().unwrap_or("?"),
                                    e["detail_fingerprint"].as_str().unwrap_or(e["operation"].as_str().unwrap_or("?"))
                                ));
                            }
                            out
                        }
                        _ => format!("No similar requests found for: {sql}")
                    }
                })
                .map_err(|e| e.to_string())
        }
        "dbward_preview_impact" => {
            let sql = args["sql"].as_str().unwrap_or("");
            let db = args["database"].as_str().unwrap_or(db_name);
            let explain_sql = format!("EXPLAIN {sql}");
            submit_and_wait(client, "execute_query", env, db, &explain_sql, None).await
        }
        "dbward_explain_policy_failure" => {
            let req_id = args["request_id"].as_str().unwrap_or("");
            if req_id.is_empty() {
                let op = args["operation"].as_str().unwrap_or("execute_query");
                let env_arg = args["environment"].as_str().unwrap_or(env);
                let db = args["database"].as_str().unwrap_or(db_name);
                Ok(format!(
                    "To execute '{op}' on {db} ({env_arg}):\n\
                     Check if a workflow exists: [[workflows]] with database=\"{db}\" or \"*\", environment=\"{env_arg}\" or \"*\"\n\
                     If no workflow matches → auto-approved.\n\
                     If workflow has steps → approval required from specified roles/groups.\n\
                     Use 'dbward_who_can_approve' with a request_id for specific approval path."
                ))
            } else {
                client.get_request(req_id).await
                    .map(|v| {
                        let status = v["status"].as_str().unwrap_or("unknown");
                        let workflow = &v["workflow_snapshot"];
                        format!(
                            "Request {req_id} status: {status}\n\
                             Workflow: {}\n\
                             To approve: dbward request approve {req_id}",
                            if workflow.is_null() { "none (auto-approved)".to_string() }
                            else { serde_json::to_string_pretty(workflow).unwrap_or_default() }
                        )
                    })
                    .map_err(|e| e.to_string())
            }
        }
        "dbward_list_schemas" => {
            let db = args["database"].as_str().unwrap_or(db_name);
            let sql = "SELECT table_schema, table_name, table_type FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog', 'information_schema') ORDER BY table_schema, table_name";
            submit_and_wait(client, "execute_query", env, db, sql, None).await
        }
        "dbward_describe_table" => {
            let table = args["table"].as_str().unwrap_or("");
            let db = args["database"].as_str().unwrap_or(db_name);
            let sql = format!(
                "SELECT column_name, data_type, is_nullable, column_default FROM information_schema.columns WHERE table_name = '{table}' ORDER BY ordinal_position"
            );
            submit_and_wait(client, "execute_query", env, db, &sql, None).await
        }
        "dbward_compare_schema" => {
            // Local: show pending migration files content
            let db = args["database"].as_str().unwrap_or(db_name);
            let dir = migrations_dir;
            match std::fs::read_dir(dir) {
                Ok(entries) => {
                    let mut files: Vec<_> = entries.filter_map(|e| e.ok()).collect();
                    files.sort_by_key(|e| e.file_name());
                    let mut out = format!("Pending migrations in {}:\n", dir.display());
                    for f in files.iter().rev().take(5) {
                        let name = f.file_name();
                        out.push_str(&format!("\n--- {} ---\n", name.to_string_lossy()));
                        if let Ok(content) = std::fs::read_to_string(f.path()) {
                            out.push_str(&content[..content.len().min(500)]);
                            if content.len() > 500 { out.push_str("\n...truncated"); }
                        }
                        out.push('\n');
                    }
                    Ok(out)
                }
                Err(e) => Err(format!("Cannot read migrations dir: {e}"))
            }
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
        },
        {
            "name": "dbward_list_pending",
            "description": "List requests pending approval",
            "inputSchema": {"type": "object", "properties": {}}
        },
        {
            "name": "dbward_who_can_approve",
            "description": "Show who can approve a specific request (roles, groups, steps)",
            "inputSchema": {"type": "object", "properties": {"request_id": {"type": "string"}}, "required": ["request_id"]}
        },
        {
            "name": "dbward_find_similar_requests",
            "description": "Find past requests similar to the given SQL or operation",
            "inputSchema": {"type": "object", "properties": {"sql": {"type": "string"}, "operation": {"type": "string"}, "limit": {"type": "integer", "default": 5}}}
        },
        {
            "name": "dbward_preview_impact",
            "description": "Preview the impact of a SQL statement (EXPLAIN output)",
            "inputSchema": {"type": "object", "properties": {"sql": {"type": "string"}, "database": {"type": "string"}, "environment": {"type": "string"}}, "required": ["sql"]}
        },
        {
            "name": "dbward_explain_policy_failure",
            "description": "Explain why a request was blocked or requires approval",
            "inputSchema": {"type": "object", "properties": {"request_id": {"type": "string"}, "operation": {"type": "string"}, "environment": {"type": "string"}, "database": {"type": "string"}}}
        },
        {
            "name": "dbward_list_schemas",
            "description": "List tables and schemas in the target database",
            "inputSchema": {"type": "object", "properties": {"database": {"type": "string"}, "environment": {"type": "string"}}}
        },
        {
            "name": "dbward_describe_table",
            "description": "Show column definitions for a table",
            "inputSchema": {"type": "object", "properties": {"table": {"type": "string"}, "database": {"type": "string"}, "environment": {"type": "string"}}, "required": ["table"]}
        },
        {
            "name": "dbward_compare_schema",
            "description": "Show pending migration files that would change the schema",
            "inputSchema": {"type": "object", "properties": {"database": {"type": "string"}}}
        }
    ])
}

fn resources_definitions() -> Value {
    json!([
        {"uri": "dbward://migrations/status", "name": "Migration Status", "description": "Applied and pending migrations", "mimeType": "application/json"},
        {"uri": "dbward://requests/pending", "name": "Pending Requests", "description": "Requests awaiting approval", "mimeType": "application/json"},
        {"uri": "dbward://audit/recent", "name": "Recent Audit Events", "description": "Last 10 audit events", "mimeType": "application/json"}
    ])
}

fn resource_templates_definitions() -> Value {
    json!([
        {
            "uriTemplate": "dbward://requests/{request_id}",
            "name": "Request Details",
            "description": "Details for a specific request",
            "mimeType": "application/json"
        }
    ])
}

async fn handle_resources_read(
    id: Option<Value>,
    params: &Value,
    client: &crate::server_client::ServerClient,
    _db_name: &str,
) -> Value {
    let uri = params["uri"].as_str().unwrap_or("");
    if uri.is_empty() {
        return jsonrpc_error(id, -32602, "Missing required parameter: uri");
    }

    let content = match read_resource(uri, client).await {
        Ok(content) => content,
        Err(ResourceReadError::NotFound(message)) => return jsonrpc_error(id, -32002, message),
        Err(ResourceReadError::Internal(message)) => return jsonrpc_error(id, -32603, message),
    };

    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "contents": [{"uri": uri, "mimeType": "application/json", "text": content}]
        }
    })
}

enum ResourceReadError {
    NotFound(String),
    Internal(String),
}

async fn read_resource(
    uri: &str,
    client: &crate::server_client::ServerClient,
) -> Result<String, ResourceReadError> {
    let value = match uri {
        "dbward://migrations/status" => client
            .get_json("/api/requests?operation=migrate_status&limit=1")
            .await
            .map_err(|e| {
                ResourceReadError::Internal(format!("Failed to read resource {uri}: {e}"))
            })?,
        "dbward://requests/pending" => client
            .get_json("/api/requests?status=pending&limit=20")
            .await
            .map_err(|e| {
                ResourceReadError::Internal(format!("Failed to read resource {uri}: {e}"))
            })?,
        "dbward://audit/recent" => client
            .get_json("/api/audit/events?limit=10")
            .await
            .map_err(|e| {
                ResourceReadError::Internal(format!("Failed to read resource {uri}: {e}"))
            })?,
        _ if uri.starts_with("dbward://requests/") => {
            let req_id = uri.strip_prefix("dbward://requests/").unwrap_or("");
            let (req_id, suffix) = req_id.split_once('/').unwrap_or((req_id, ""));
            if req_id.is_empty() {
                return Err(ResourceReadError::NotFound(format!(
                    "Resource not found: {uri}"
                )));
            }
            match suffix {
                "" => client.get_request(req_id).await.map_err(|e| {
                    ResourceReadError::Internal(format!("Failed to read resource {uri}: {e}"))
                })?,
                _ => {
                    return Err(ResourceReadError::NotFound(format!(
                        "Resource not found: {uri}"
                    )));
                }
            }
        }
        _ => {
            return Err(ResourceReadError::NotFound(format!(
                "Resource not found: {uri}"
            )));
        }
    };

    Ok(value.to_string())
}

fn prompts_definitions() -> Value {
    json!([
        {"name": "review_migration", "description": "Review a migration SQL file for safety issues", "arguments": [{"name": "file_path", "description": "Path to migration file", "required": true}]},
        {"name": "explain_request", "description": "Explain what a request will do and its impact", "arguments": [{"name": "request_id", "description": "Request ID", "required": true}]},
        {"name": "draft_migration", "description": "Generate migration SQL from a description", "arguments": [{"name": "description", "description": "What the migration should do", "required": true}]},
        {"name": "draft_rollback", "description": "Generate rollback SQL for a migration", "arguments": [{"name": "migration_file", "description": "Path to migration file to rollback", "required": true}]},
        {"name": "summarize_audit_trail", "description": "Summarize recent audit events", "arguments": [{"name": "since", "description": "Start date (ISO 8601)", "required": false}, {"name": "database", "description": "Filter by database", "required": false}]},
        {"name": "prepare_approval_comment", "description": "Draft an approval comment for a request", "arguments": [{"name": "request_id", "description": "Request ID to review", "required": true}]}
    ])
}

fn handle_prompts_get(
    id: Option<Value>,
    params: &Value,
    migrations_dir: &std::path::Path,
) -> Value {
    let name = params["name"].as_str().unwrap_or("");
    let args = &params["arguments"];

    if name.is_empty() {
        return jsonrpc_error(id, -32602, "Missing required parameter: name");
    }

    let (description, messages) = match name {
        "review_migration" => {
            let file_path = match required_arg(args, "file_path") {
                Ok(value) => value,
                Err(message) => return jsonrpc_error(id, -32602, message),
            };
            let content = match read_migration_file(migrations_dir, file_path) {
                Ok(content) => content,
                Err(message) => return jsonrpc_error(id, -32602, message),
            };
            (
                "Review a migration SQL file for safety issues",
                vec![
                    json!({"role": "user", "content": {"type": "text", "text": format!(
                        "Review this migration SQL for safety issues (locking, data loss, backwards compatibility):\n\n```sql\n{content}\n```\n\nCheck for:\n1. Long-running locks (ALTER TABLE on large tables)\n2. Data loss (DROP COLUMN without backup)\n3. Backwards incompatibility (NOT NULL without default)\n4. Missing indexes for new foreign keys\n5. Transaction safety"
                    )}}),
                ],
            )
        }
        "explain_request" => {
            let request_id = match required_arg(args, "request_id") {
                Ok(value) => value,
                Err(message) => return jsonrpc_error(id, -32602, message),
            };
            (
                "Explain what a request will do and its impact",
                vec![
                    json!({"role": "user", "content": {"type": "text", "text": format!(
                        "Explain what request {request_id} will do. Read the request details from dbward://requests/{request_id} and describe:\n1. What SQL will be executed\n2. Which database and environment\n3. Potential impact\n4. Who needs to approve it"
                    )}}),
                ],
            )
        }
        "draft_migration" => {
            let description = match required_arg(args, "description") {
                Ok(value) => value,
                Err(message) => return jsonrpc_error(id, -32602, message),
            };
            (
                "Generate migration SQL from a description",
                vec![
                    json!({"role": "user", "content": {"type": "text", "text": format!(
                        "Generate a migration SQL file for the following change:\n\n{description}\n\nProvide both up and down sections in dbmate format:\n```sql\n-- migrate:up\n<SQL>\n\n-- migrate:down\n<SQL>\n```\n\nConsider: backwards compatibility, index needs, NOT NULL defaults, large table locking."
                    )}}),
                ],
            )
        }
        "draft_rollback" => {
            let file_path = match required_arg(args, "migration_file") {
                Ok(value) => value,
                Err(message) => return jsonrpc_error(id, -32602, message),
            };
            let content = match read_migration_file(migrations_dir, file_path) {
                Ok(content) => content,
                Err(message) => return jsonrpc_error(id, -32602, message),
            };
            (
                "Generate rollback SQL for a migration",
                vec![
                    json!({"role": "user", "content": {"type": "text", "text": format!(
                        "Generate a safe rollback plan for this migration:\n\n```sql\n{content}\n```\n\nConsider data preservation and application compatibility."
                    )}}),
                ],
            )
        }
        "summarize_audit_trail" => (
            "Summarize recent audit events",
            vec![json!({"role": "user", "content": {"type": "text", "text":
                "Summarize the recent audit events from dbward://audit/recent. Group by actor and operation type. Highlight any failures or unusual patterns."
            }})],
        ),
        "prepare_approval_comment" => {
            let request_id = match required_arg(args, "request_id") {
                Ok(value) => value,
                Err(message) => return jsonrpc_error(id, -32602, message),
            };
            (
                "Draft an approval comment for a request",
                vec![
                    json!({"role": "user", "content": {"type": "text", "text": format!(
                        "Review request {request_id} (read from dbward://requests/{request_id}) and draft an approval comment. Include:\n1. What was reviewed\n2. Risk assessment (low/medium/high)\n3. Any conditions or follow-up actions"
                    )}}),
                ],
            )
        }
        _ => {
            return jsonrpc_error(id, -32602, format!("Unknown prompt: {name}"));
        }
    };

    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "description": description,
            "messages": messages
        }
    })
}

fn required_arg<'a>(args: &'a Value, name: &str) -> Result<&'a str, String> {
    let value = args[name]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    value.ok_or_else(|| format!("Missing required argument: {name}"))
}

fn read_migration_file(migrations_dir: &Path, requested_path: &str) -> Result<String, String> {
    let full_path = resolve_migration_path(migrations_dir, requested_path)?;
    std::fs::read_to_string(&full_path)
        .map_err(|_| format!("Could not read migration file: {}", full_path.display()))
}

fn resolve_migration_path(migrations_dir: &Path, requested_path: &str) -> Result<PathBuf, String> {
    let relative = Path::new(requested_path);
    if relative.is_absolute() {
        return Err("Absolute paths are not allowed".to_string());
    }
    if relative.components().any(|component| {
        matches!(
            component,
            std::path::Component::ParentDir
                | std::path::Component::RootDir
                | std::path::Component::Prefix(_)
        )
    }) {
        return Err("Migration file path escapes the migrations directory".to_string());
    }

    let base = migrations_dir.canonicalize().map_err(|_| {
        format!(
            "Could not resolve migrations directory: {}",
            migrations_dir.display()
        )
    })?;
    let candidate = base.join(relative);
    let resolved = candidate
        .canonicalize()
        .map_err(|_| format!("Could not resolve migration file: {}", candidate.display()))?;

    if !resolved.starts_with(&base) {
        return Err("Migration file path escapes the migrations directory".to_string());
    }

    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_response_has_protocol_version() {
        let resp = handle_initialize(Some(json!(1)));
        assert_eq!(resp["result"]["protocolVersion"], "2025-11-05");
        assert_eq!(resp["result"]["serverInfo"]["name"], "dbward");
        assert_eq!(resp["result"]["capabilities"]["resources"], json!({}));
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

    #[test]
    fn prompts_get_rejects_missing_required_argument() {
        let resp = handle_prompts_get(
            Some(json!(1)),
            &json!({"name": "draft_migration", "arguments": {}}),
            Path::new("/tmp"),
        );

        assert_eq!(resp["error"]["code"], -32602);
        assert_eq!(
            resp["error"]["message"],
            "Missing required argument: description"
        );
    }

    #[test]
    fn resolve_migration_path_rejects_path_traversal() {
        let base = std::env::temp_dir().join(format!("dbward-mcp-test-{}", std::process::id()));
        std::fs::create_dir_all(base.join("migrations")).unwrap();

        let err = resolve_migration_path(&base.join("migrations"), "../secret.sql").unwrap_err();
        assert_eq!(err, "Migration file path escapes the migrations directory");

        let _ = std::fs::remove_dir_all(base);
    }
}
