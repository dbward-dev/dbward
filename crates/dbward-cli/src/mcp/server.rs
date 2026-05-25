use super::defs::*;
use std::collections::HashMap;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;

use crate::config::ClientConfig;

/// Elicitation result from client
enum ElicitResult {
    Accept { content: Value },
    Decline,
    Cancel,
}

/// Channel for workers to request elicitation
struct ElicitHandle {
    tx: mpsc::Sender<ElicitMsg>,
    id_counter: Arc<AtomicU64>,
}

struct ElicitMsg {
    id: u64,
    message: String,
    schema: Value,
    response_tx: oneshot::Sender<ElicitResult>,
}

impl ElicitHandle {
    async fn ask(&self, message: &str, schema: Value) -> Result<ElicitResult, String> {
        let id = self.id_counter.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(ElicitMsg {
                id,
                message: message.to_string(),
                schema,
                response_tx: tx,
            })
            .await
            .map_err(|_| "elicitation channel closed".to_string())?;
        tokio::time::timeout(Duration::from_secs(300), rx)
            .await
            .map_err(|_| "elicitation timed out".to_string())?
            .map_err(|_| "elicitation response dropped".to_string())
    }
}

enum IncomingMsg {
    Request(Value),
    ParseError(String),
}

pub async fn run_stdio(
    config: ClientConfig,
    database: Option<&str>,
    client: crate::server_client::ServerClient,
) -> Result<(), crate::error::CliError> {
    let db_name = config.resolve_database_name(database)?;
    let migrations_dir = config.migrations_dir_for(&db_name);
    let client = Arc::new(client);

    let (outgoing_tx, mut outgoing_rx) = mpsc::channel::<Value>(64);
    let (incoming_tx, mut incoming_rx) = mpsc::channel::<IncomingMsg>(64);
    let (elicit_tx, mut elicit_rx) = mpsc::channel::<ElicitMsg>(8);
    let elicit_id_counter = Arc::new(AtomicU64::new(1));

    let mut client_supports_elicitation = false;
    let mut pending_elicitations: HashMap<u64, oneshot::Sender<ElicitResult>> = HashMap::new();

    let reader = tokio::spawn(async move {
        let stdin = tokio::io::stdin();
        let mut lines = BufReader::new(stdin).lines();
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    if line.trim().is_empty() {
                        continue;
                    }
                    let msg = match serde_json::from_str::<Value>(&line) {
                        Ok(value) => IncomingMsg::Request(value),
                        Err(err) => IncomingMsg::ParseError(err.to_string()),
                    };
                    if incoming_tx.send(msg).await.is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
    });

    let writer = tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        while let Some(msg) = outgoing_rx.recv().await {
            stdout.write_all(msg.to_string().as_bytes()).await?;
            stdout.write_all(b"\n").await?;
            stdout.flush().await?;
        }
        Ok::<(), std::io::Error>(())
    });

    let mut workers = JoinSet::new();
    let mut pending_cleanup = tokio::time::interval(Duration::from_secs(30));

    loop {
        tokio::select! {
            Some(joined) = workers.join_next(), if !workers.is_empty() => {
                match joined {
                    Ok(response) => {
                        if outgoing_tx.send(response).await.is_err() {
                            break;
                        }
                    }
                    Err(err) => {
                        workers.abort_all();
                        return Err(crate::error::CliError::Server(format!("MCP worker task failed: {err}")));
                    }
                }
            }
            msg = incoming_rx.recv() => {
                let Some(msg) = msg else { break; };

                let request = match msg {
                    IncomingMsg::Request(request) => request,
                    IncomingMsg::ParseError(err) => {
                        if outgoing_tx.send(json!({
                            "jsonrpc": "2.0",
                            "id": null,
                            "error": {"code": -32700, "message": format!("Parse error: {err}")}
                        })).await.is_err() {
                            break;
                        }
                        continue;
                    }
                };

                let id = request.get("id").cloned();
                let method = request["method"].as_str().unwrap_or("").to_string();

                // Check if this is a response (to our elicitation request)
                if id.is_some() && request.get("method").is_none() {
                    let resp_id = id.as_ref().and_then(|v| v.as_u64()).unwrap_or(0);
                    if let Some(tx) = pending_elicitations.remove(&resp_id) {
                        let result = &request["result"];
                        let elicit_result = if request.get("error").is_some() {
                            ElicitResult::Cancel
                        } else {
                            let action = result["action"].as_str().unwrap_or("cancel");
                            match action {
                                "accept" => ElicitResult::Accept { content: result["content"].clone() },
                                "decline" => ElicitResult::Decline,
                                _ => ElicitResult::Cancel,
                            }
                        };
                        let _ = tx.send(elicit_result);
                        continue;
                    }
                }

                // Notifications from client
                if id.is_none() || method == "notifications/initialized" || method == "notifications/cancelled" {
                    continue;
                }

                // Check initialize for elicitation support
                if method == "initialize" {
                    let caps = &request["params"]["capabilities"];
                    client_supports_elicitation = caps.get("elicitation").is_some();
                    let _ = outgoing_tx.send(handle_initialize(id)).await;
                    continue;
                }

                // Sync handlers (no spawn needed)
                match method.as_str() {
                    "tools/list" => {
                        let _ = outgoing_tx.send(json!({"jsonrpc": "2.0", "id": id, "result": {"tools": tools_definitions()}})).await;
                    }
                    "resources/list" => {
                        let _ = outgoing_tx.send(json!({"jsonrpc": "2.0", "id": id, "result": {"resources": resources_definitions()}})).await;
                    }
                    "resources/templates/list" => {
                        let _ = outgoing_tx.send(json!({"jsonrpc": "2.0", "id": id, "result": {"resourceTemplates": resource_templates_definitions()}})).await;
                    }
                    "prompts/list" => {
                        let _ = outgoing_tx.send(json!({"jsonrpc": "2.0", "id": id, "result": {"prompts": prompts_definitions()}})).await;
                    }
                    "prompts/get" => {
                        let resp = handle_prompts_get(id.clone(), &request["params"], &migrations_dir);
                        let _ = outgoing_tx.send(resp).await;
                    }
                    "resources/subscribe" => {
                        let _ = outgoing_tx.send(json!({"jsonrpc": "2.0", "id": id, "result": {}})).await;
                    }
                    // Async handlers (spawn worker)
                    "tools/call" | "resources/read" => {
                        let c = client.clone();
                        let db = db_name.clone();
                        let mdir = migrations_dir.clone();
                        let params = request["params"].clone();
                        let id = id.clone();
                        let method = method.clone();
                        let elicit = ElicitHandle {
                            tx: elicit_tx.clone(),
                            id_counter: elicit_id_counter.clone(),
                        };
                        let supports_elicit = client_supports_elicitation;
                        workers.spawn(async move {
                            if method == "tools/call" {
                                handle_tools_call(id.clone(), &params, &c, &db, &mdir, &elicit, supports_elicit).await
                            } else {
                                handle_resources_read(id.clone(), &params, &c, &db).await
                            }
                        });
                    }
                    _ => {
                        let _ = outgoing_tx.send(json!({
                            "jsonrpc": "2.0", "id": id,
                            "error": {"code": -32601, "message": format!("Method not found: {method}")}
                        })).await;
                    }
                }
            }
            // Elicitation requests from workers
            Some(elicit_msg) = elicit_rx.recv() => {
                let elicit_id = elicit_msg.id;
                pending_elicitations.insert(elicit_id, elicit_msg.response_tx);
                if outgoing_tx.send(json!({
                    "jsonrpc": "2.0",
                    "id": elicit_id,
                    "method": "elicitation/create",
                    "params": {
                        "message": elicit_msg.message,
                        "requestedSchema": elicit_msg.schema
                    }
                })).await.is_err() {
                    if let Some(tx) = pending_elicitations.remove(&elicit_id) {
                        let _ = tx.send(ElicitResult::Cancel);
                    }
                    break;
                }
            }
            _ = pending_cleanup.tick() => {
                pending_elicitations.retain(|_, tx| !tx.is_closed());
            }
        }
    }

    workers.abort_all();
    while workers.join_next().await.is_some() {}

    for (_, tx) in pending_elicitations.drain() {
        let _ = tx.send(ElicitResult::Cancel);
    }

    drop(elicit_tx);
    drop(outgoing_tx);
    drop(incoming_rx);

    let _ = reader.await;
    match writer.await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => return Err(crate::error::CliError::Io(err)),
        Err(err) => {
            return Err(crate::error::CliError::Server(format!(
                "MCP writer task failed: {err}"
            )));
        }
    }

    Ok(())
}

pub(crate) fn handle_initialize(id: Option<Value>) -> Value {
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

pub(crate) fn jsonrpc_error(id: Option<Value>, code: i64, message: impl Into<String>) -> Value {
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
    elicit: &ElicitHandle,
    client_supports_elicitation: bool,
) -> Value {
    let tool_name = params["name"].as_str().unwrap_or("");
    let args = &params["arguments"];
    let env = args["environment"].as_str().unwrap_or("development");

    let result = match tool_name {
        "dbward_execute_query" => {
            let sql = args["sql"].as_str().unwrap_or("");
            let db = args["database"].as_str().unwrap_or(db_name);
            let mut reason = args["reason"].as_str().map(|s| s.to_string());

            if sql.is_empty() {
                Err("sql parameter is required".to_string())
            } else {
                // Elicitation: ask for reason on production if not provided
                if env == "production" && reason.is_none() && client_supports_elicitation {
                    match elicit.ask(
                        "Production execution requires a reason.",
                        json!({
                            "type": "object",
                            "properties": {
                                "reason": {"type": "string", "description": "Why is this execution needed?"},
                                "ticket": {"type": "string", "description": "Related ticket (optional)"}
                            },
                            "required": ["reason"]
                        }),
                    ).await {
                        Ok(ElicitResult::Accept { content }) => {
                            reason = content["reason"].as_str().map(|s| s.to_string());
                        }
                        Ok(ElicitResult::Decline) => return json!({
                            "jsonrpc": "2.0", "id": id,
                            "result": {"content": [{"type": "text", "text": "User declined to provide reason."}], "isError": true}
                        }),
                        Ok(ElicitResult::Cancel) | Err(_) => return json!({
                            "jsonrpc": "2.0", "id": id,
                            "result": {"content": [{"type": "text", "text": "Cancelled."}], "isError": true}
                        }),
                    }
                }
                submit_and_wait(client, "execute_query", env, db, sql, reason.as_deref()).await
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
            let migrator = dbward_migrate::LocalMigrator::new(migrations_dir.to_path_buf());
            match migrator.create(name) {
                Ok(path) => Ok(format!("Created: {}", path.display())),
                Err(e) => Err(e.to_string()),
            }
        }
        "dbward_wait_request" => {
            let req_id = args["request_id"].as_str().unwrap_or("");
            let timeout = args["timeout"].as_u64().unwrap_or(60);
            let include_result = args["include_result"].as_bool().unwrap_or(true);
            wait_request(client, req_id, timeout, include_result).await
        }
        "dbward_list_pending" => client
            .list_pending_for_me(Some(20))
            .await
            .map(|v| serde_json::to_string_pretty(&v["requests"]).unwrap_or_default())
            .map_err(|e| e.to_string()),
        "dbward_who_can_approve" => {
            let req_id = match required_arg(args, "request_id") {
                Ok(value) => value,
                Err(message) => return jsonrpc_error(id, -32602, message),
            };
            client
                .get_request(req_id)
                .await
                .map(|v| {
                    if let Some(progress) = v.get("approval_progress") {
                        format_approval_progress(req_id, &v["status"], progress)
                    } else {
                        "No workflow configured (break-glass)".to_string()
                    }
                })
                .map_err(|e| e.to_string())
        }
        "dbward_find_similar_requests" => {
            let sql = args["sql"].as_str().unwrap_or("");
            let op = args["operation"].as_str().unwrap_or("execute_select");
            let limit = args["limit"].as_u64().unwrap_or(5).clamp(1, 20);
            let fetch_limit = limit * 4;
            client
                .get_json(&format!(
                    "/api/requests?limit={fetch_limit}&status=executed"
                ))
                .await
                .map(|v| {
                    let requests = v["requests"].as_array();
                    match requests {
                        Some(arr) if !arr.is_empty() => {
                            let sql_terms = normalized_similarity_terms(sql);
                            let matches: Vec<&Value> = arr
                                .iter()
                                .filter(|r| {
                                    r["operation"].as_str().unwrap_or("") == op
                                        && if sql_terms.is_empty() {
                                            matches_normalized(
                                                r["detail"].as_str().unwrap_or(""),
                                                sql,
                                            )
                                        } else {
                                            matches_similarity_terms(
                                                r["detail"].as_str().unwrap_or(""),
                                                &sql_terms,
                                            )
                                        }
                                })
                                .take(limit as usize)
                                .collect();
                            if matches.is_empty() {
                                return format!("No similar requests found for: {sql}");
                            }
                            let mut out = format!("Recent similar {op} requests:\n");
                            for r in matches {
                                out.push_str(&format!(
                                    "  {} | id={} | {}\n",
                                    r["created_at"].as_str().unwrap_or("?"),
                                    r["id"].as_str().unwrap_or("?"),
                                    r["detail"]
                                        .as_str()
                                        .map(|d| if d.len() > 60 { &d[..60] } else { d })
                                        .unwrap_or("?"),
                                ));
                            }
                            out
                        }
                        _ => format!("No similar requests found for: {sql}"),
                    }
                })
                .map_err(|e| e.to_string())
        }
        "dbward_preview_impact" => {
            let sql = match required_arg(args, "sql") {
                Ok(value) => value,
                Err(message) => return jsonrpc_error(id, -32602, message),
            };
            let db = args["database"].as_str().unwrap_or(db_name);
            let preview_sql = match normalize_preview_sql(sql) {
                Ok(sql) => sql,
                Err(message) => return jsonrpc_error(id, -32602, message),
            };
            let explain_sql = format!("EXPLAIN {preview_sql}");
            submit_and_wait(client, "execute_query", env, db, &explain_sql, None).await
        }
        "dbward_explain_policy_failure" => {
            let req_id = args["request_id"].as_str().unwrap_or("");
            if req_id.is_empty() {
                let op = args["operation"].as_str().unwrap_or("execute_select");
                let env_arg = args["environment"].as_str().unwrap_or(env);
                let db = args["database"].as_str().unwrap_or(db_name);
                Ok(format!(
                    "To execute '{op}' on {db} ({env_arg}):\n\
                     Check if a workflow exists: [[workflows]] with database=\"{db}\" or \"*\", environment=\"{env_arg}\" or \"*\"\n\
                     If no workflow matches → rejected (fail-closed).\n\
                     If workflow has steps → approval required from specified roles/groups.\n\
                     Use 'dbward_who_can_approve' with a request_id for specific approval path."
                ))
            } else {
                client
                    .get_request(req_id)
                    .await
                    .map(|v| {
                        let status = v["status"].as_str().unwrap_or("unknown");
                        let workflow = v
                            .get("approval_progress")
                            .map(|progress| {
                                format_approval_progress(req_id, &v["status"], progress)
                            })
                            .unwrap_or_else(|| "none (auto-approved)".to_string());
                        format!(
                            "Request {req_id} status: {status}\n\
                             Workflow: {}\n\
                             To approve: dbward request approve {req_id}",
                            workflow
                        )
                    })
                    .map_err(|e| e.to_string())
            }
        }
        "dbward_inspect_schema" => {
            let db = args["database"].as_str().unwrap_or(db_name);
            let table = args["table"].as_str().unwrap_or("");

            // Use server schema API (same source as MCP resource)
            let path = if table.is_empty() {
                format!("/api/schemas/{db}")
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
                format!("/api/schemas/{db}?table={encoded}")
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
    use crate::commands::workflow;

    const TIMEOUT: Duration = Duration::from_secs(120);

    // 1. Create request OUTSIDE timeout (request_id is always preserved)
    let cr = match workflow::create_request(
        client,
        crate::server_client::CreateRequest {
            operation,
            environment,
            database,
            detail,
            emergency: false,
            reason,
            metadata: None,
            idempotency_key: None,
            share_with: None,
            no_store: false,
        },
    )
    .await
    {
        Ok(cr) => cr,
        Err(e) => return Err(rewrite_error(&e.to_string())),
    };

    // 2. Pending → return immediately with request_id
    if cr.status == "pending" {
        return Ok(format!(
            "Request {} requires approval. \
             Use dbward_wait_request to wait for completion.",
            cr.request_id
        ));
    }

    // 3. Wait with timeout (request_id preserved on timeout)
    match tokio::time::timeout(
        TIMEOUT,
        workflow::wait_for_completion(client, &cr.request_id, &cr.status, false),
    )
    .await
    {
        Ok(Ok(result)) => format_result(&result),
        Ok(Err(e)) => Err(rewrite_error(&e.to_string())),
        Err(_) => Ok(format!(
            "Request {} is still executing (timed out after 120s). \
             Use dbward_wait_request with request_id '{}' to get the result.",
            cr.request_id, cr.request_id
        )),
    }
}

/// Rewrite known server validation errors to actionable MCP messages.
fn rewrite_error(msg: &str) -> String {
    if msg.contains("reason is required") {
        "This workflow requires a reason. Pass the 'reason' parameter.".into()
    } else if msg.contains("not registered") {
        format!("{msg} Use dbward_inspect_schema to see available databases.")
    } else {
        msg.to_string()
    }
}

fn format_result(resp: &Value) -> Result<String, String> {
    if resp["success"].as_bool() == Some(false) {
        let err = resp["error"].as_str().unwrap_or("unknown error");
        return Err(format!("Execution failed: {err}"));
    }
    let result = &resp["result"];
    if !result.is_null() {
        if let Some(text) = result.as_str() {
            return Ok(text.to_string());
        }
        return Ok(serde_json::to_string_pretty(result).unwrap_or_default());
    }
    // Stream format: result_data is a JSON string
    if let Some(data) = resp["result_data"].as_str() {
        if let Ok(parsed) = serde_json::from_str::<Value>(data) {
            return Ok(serde_json::to_string_pretty(&parsed).unwrap_or_default());
        }
        return Ok(data.to_string());
    }
    if let Some(affected) = resp["rows_affected"].as_u64() {
        return Ok(format!("Rows affected: {affected}"));
    }
    Ok("Executed successfully.".to_string())
}

async fn wait_request(
    client: &crate::server_client::ServerClient,
    request_id: &str,
    timeout: u64,
    include_result: bool,
) -> Result<String, String> {
    if request_id.is_empty() {
        return Err("request_id is required".to_string());
    }

    // Status-only: no long-poll, return immediately
    if !include_result {
        let resp = client
            .get_request(request_id)
            .await
            .map_err(|e| e.to_string())?;
        let status = resp["status"].as_str().unwrap_or("unknown");
        return Ok(format!("Request {request_id} status: {status}"));
    }

    let resp = client
        .get_request_with_wait(request_id, timeout)
        .await
        .map_err(|e| e.to_string())?;
    let status = resp["status"].as_str().unwrap_or("unknown");

    match status {
        "pending" => Ok(format!("Request {request_id} is still pending approval.")),
        "approved" | "auto_approved" | "break_glass" | "dispatched" | "running" => {
            // Dispatch if needed, then wait for result
            if status == "approved" || status == "auto_approved" || status == "break_glass" {
                let _ = client.dispatch(request_id).await;
            }
            match tokio::time::timeout(
                std::time::Duration::from_secs(timeout),
                crate::commands::workflow::wait_and_resolve(client, request_id, false),
            )
            .await
            {
                Ok(Ok(result)) => format_result(&result),
                Ok(Err(e)) => Err(e.to_string()),
                Err(_) => Ok(format!(
                    "Request {request_id} is still executing (timed out after {timeout}s). Call dbward_wait_request again to continue waiting."
                )),
            }
        }
        "executed" | "failed" => {
            let result = crate::commands::workflow::resolve_terminal_result(client, request_id)
                .await
                .map_err(|e| e.to_string())?;
            format_result(&result)
        }
        "rejected" => Ok(format!("Request {request_id} was rejected.")),
        "cancelled" => Ok(format!("Request {request_id} was cancelled.")),
        "expired" => Ok(format!("Request {request_id} has expired.")),
        "execution_lost" => Ok(format!(
            "Request {request_id} execution was lost (agent lease expired). It can be re-dispatched."
        )),
        _ => Ok(format!("Request {request_id} status: {status}")),
    }
}
