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
pub(super) enum ElicitResult {
    Accept { content: Value },
    Decline,
    Cancel,
}

/// Channel for workers to request elicitation
pub(super) struct ElicitHandle {
    pub(super) tx: mpsc::Sender<ElicitMsg>,
    pub(super) id_counter: Arc<AtomicU64>,
}

pub(super) struct ElicitMsg {
    pub(super) id: String,
    pub(super) message: String,
    pub(super) schema: Value,
    pub(super) response_tx: oneshot::Sender<ElicitResult>,
}

impl ElicitHandle {
    pub(super) async fn ask(&self, message: &str, schema: Value) -> Result<ElicitResult, String> {
        let seq = self.id_counter.fetch_add(1, Ordering::Relaxed);
        let id = format!("elicit-{}", seq);
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
    let default_env: String = std::env::var("DBWARD_ENV")
        .ok()
        .filter(|v| !v.is_empty())
        .or(config.default_environment.clone())
        .unwrap_or_default();
    let client = Arc::new(client);

    let (outgoing_tx, mut outgoing_rx) = mpsc::channel::<Value>(64);
    let (incoming_tx, mut incoming_rx) = mpsc::channel::<IncomingMsg>(64);
    let (elicit_tx, mut elicit_rx) = mpsc::channel::<ElicitMsg>(8);
    let elicit_id_counter = Arc::new(AtomicU64::new(1));

    let mut client_supports_elicitation = false;
    let mut pending_elicitations: HashMap<String, oneshot::Sender<ElicitResult>> = HashMap::new();

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
                    let resp_id = id.as_ref().and_then(|v| v.as_str()).unwrap_or("").to_string();
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
                    if outgoing_tx.send(handle_initialize(&request["params"], id)).await.is_err() {
                        break;
                    }
                    continue;
                }

                // Sync handlers (no spawn needed)
                match method.as_str() {
                    "tools/list" => {
                        if outgoing_tx.send(json!({"jsonrpc": "2.0", "id": id, "result": {"tools": tools_definitions()}})).await.is_err() { break; }
                    }
                    "resources/list" => {
                        if outgoing_tx.send(json!({"jsonrpc": "2.0", "id": id, "result": {"resources": resources_definitions()}})).await.is_err() { break; }
                    }
                    "resources/templates/list" => {
                        if outgoing_tx.send(json!({"jsonrpc": "2.0", "id": id, "result": {"resourceTemplates": resource_templates_definitions()}})).await.is_err() { break; }
                    }
                    "prompts/list" => {
                        if outgoing_tx.send(json!({"jsonrpc": "2.0", "id": id, "result": {"prompts": prompts_definitions()}})).await.is_err() { break; }
                    }
                    "prompts/get" => {
                        let resp = handle_prompts_get(id.clone(), &request["params"], &migrations_dir);
                        if outgoing_tx.send(resp).await.is_err() { break; }
                    }
                    "resources/subscribe" => {
                        if outgoing_tx.send(json!({"jsonrpc": "2.0", "id": id, "result": {}})).await.is_err() { break; }
                    }
                    // Async handlers (spawn worker)
                    "tools/call" => {
                        let c = client.clone();
                        let db = db_name.clone();
                        let mdir = migrations_dir.clone();
                        let params = request["params"].clone();
                        let id = id.clone();
                        let denv = default_env.clone();
                        let elicit = ElicitHandle {
                            tx: elicit_tx.clone(),
                            id_counter: elicit_id_counter.clone(),
                        };
                        let supports_elicit = client_supports_elicitation;
                        workers.spawn(async move {
                            let ctx = super::tools::McpContext {
                                client: c,
                                db_name: db,
                                migrations_dir: mdir,
                                default_env: denv,
                                elicit,
                                client_supports_elicitation: supports_elicit,
                            };
                            super::tools::handle_tools_call(id, &params, &ctx).await
                        });
                    }
                    "resources/read" => {
                        let c = client.clone();
                        let db = db_name.clone();
                        let params = request["params"].clone();
                        let id = id.clone();
                        workers.spawn(async move {
                            handle_resources_read(id, &params, &c, &db).await
                        });
                    }
                    _ => {
                        if outgoing_tx.send(json!({
                            "jsonrpc": "2.0", "id": id,
                            "error": {"code": -32601, "message": format!("Method not found: {method}")}
                        })).await.is_err() { break; }
                    }
                }
            }
            // Elicitation requests from workers
            Some(elicit_msg) = elicit_rx.recv() => {
                let elicit_id = elicit_msg.id.clone();
                pending_elicitations.insert(elicit_id.clone(), elicit_msg.response_tx);
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

pub(crate) fn handle_initialize(params: &Value, id: Option<Value>) -> Value {
    let client_version = params["protocolVersion"].as_str().unwrap_or("2024-11-05");
    let negotiated = dbward_mcp::protocol::SUPPORTED_PROTOCOL_VERSIONS
        .iter()
        .find(|&&v| v == client_version)
        .unwrap_or(&dbward_mcp::protocol::SUPPORTED_PROTOCOL_VERSIONS[0]);

    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "protocolVersion": negotiated,
            "serverInfo": {"name": "dbward", "version": env!("CARGO_PKG_VERSION")},
            "capabilities": {
                "tools": {},
                "resources": {},
                "prompts": {}
            }
        }
    })
}

pub(super) fn jsonrpc_error(id: Option<Value>, code: i64, message: impl Into<String>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message.into()
        }
    })
}
