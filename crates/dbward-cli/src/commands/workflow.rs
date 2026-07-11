use serde_json::Value;

use crate::error::CliError;
use crate::server_client::{CreateRequest, ServerClient};

const REQUEST_STATUS_WAIT_SECS: u64 = 30;

/// Outcome of a request lifecycle orchestration.
pub enum Outcome {
    /// Request completed (executed or failed). Contains the terminal payload.
    Completed { request_id: String, result: Value },
    /// Request requires approval before execution.
    Pending {
        request_id: String,
        approvers: Vec<String>,
    },
    /// Request is approved but not yet resumed (caller should resume or inform user).
    #[allow(dead_code)]
    Approved { request_id: String },
}

use dbward_api_types::requests::RequestStatus;

/// Result of request creation (before orchestration).
pub struct CreateResult {
    pub request_id: String,
    pub status: RequestStatus,
    pub approvers: Vec<String>,
}

/// Create a request and return the initial status. No orchestration.
pub async fn create_request(
    sc: &ServerClient,
    params: CreateRequest<'_>,
) -> Result<CreateResult, CliError> {
    let (id, status, approvers) = sc.create_request(params).await?;
    Ok(CreateResult {
        request_id: id,
        status,
        approvers,
    })
}

/// Wait for an already-created request to reach terminal state.
/// Handles resume if needed (approved status).
pub async fn wait_for_completion(
    sc: &ServerClient,
    request_id: &str,
    status: RequestStatus,
    verbose: bool,
) -> Result<Value, CliError> {
    match status {
        RequestStatus::Dispatched | RequestStatus::Running => {
            wait_and_resolve(sc, request_id, verbose).await
        }
        RequestStatus::Approved | RequestStatus::AutoApproved | RequestStatus::BreakGlass => {
            sc.resume(request_id)
                .await
                .map_err(|e| CliError::Server(e.body.clone()))?;
            wait_and_resolve(sc, request_id, verbose).await
        }
        RequestStatus::Executed | RequestStatus::Failed => {
            resolve_terminal_result(sc, request_id).await
        }
        _ => Err(CliError::Server(format!(
            "unexpected status for wait: {}",
            status
        ))),
    }
}

/// Submit a request and orchestrate through to completion.
///
/// This handles the common pattern: create → status branch → resume → wait → resolve.
/// ctrl+c handling, save_result, and process::exit are the caller's responsibility.
pub async fn submit_and_orchestrate(
    sc: &ServerClient,
    params: CreateRequest<'_>,
    verbose: bool,
) -> Result<Outcome, CliError> {
    let cr = create_request(sc, params).await?;

    match cr.status {
        RequestStatus::Dispatched | RequestStatus::BreakGlass | RequestStatus::Running => {
            let result = wait_and_resolve(sc, &cr.request_id, verbose).await?;
            Ok(Outcome::Completed {
                request_id: cr.request_id,
                result,
            })
        }
        RequestStatus::Executed | RequestStatus::Failed => {
            let result = resolve_terminal_result(sc, &cr.request_id).await?;
            Ok(Outcome::Completed {
                request_id: cr.request_id,
                result,
            })
        }
        RequestStatus::Approved | RequestStatus::AutoApproved => {
            sc.resume(&cr.request_id)
                .await
                .map_err(|e| CliError::Server(e.body.clone()))?;
            let result = wait_and_resolve(sc, &cr.request_id, verbose).await?;
            Ok(Outcome::Completed {
                request_id: cr.request_id,
                result,
            })
        }
        RequestStatus::Pending => Ok(Outcome::Pending {
            request_id: cr.request_id,
            approvers: cr.approvers,
        }),
        _ => Err(CliError::Server(format!(
            "unexpected status: {}",
            cr.status
        ))),
    }
}

/// Wait for an already-dispatched request to complete.
///
/// Assumes the request has been dispatched. Handles stream failure by falling back
/// to polling, and re-dispatches if the dispatch lease expired (status reverted to approved).
pub async fn wait_and_resolve(
    sc: &ServerClient,
    request_id: &str,
    verbose: bool,
) -> Result<Value, CliError> {
    if verbose {
        eprintln!("Waiting for agent to execute...");
    }

    let _progress_guard = if verbose {
        Some(spawn_progress_reporter(sc.clone(), request_id.to_string()))
    } else {
        None
    };

    loop {
        match sc.stream_result(request_id).await {
            Ok(v) => break Ok(v),
            Err(_) => {
                if let Some(v) = poll_until_terminal(sc, request_id).await? {
                    break Ok(v);
                }
                // poll_until_terminal returned None means it re-dispatched; retry stream
            }
        }
    }
}

/// Get the terminal result for a request that is already in executed/failed state.
pub async fn resolve_terminal_result(
    sc: &ServerClient,
    request_id: &str,
) -> Result<Value, CliError> {
    let req = sc.get_request(request_id).await?;
    resolve_from_request(sc, request_id, &req).await
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Spawn a background task that prints progress updates.
/// Returns a guard that aborts the task on drop.
fn spawn_progress_reporter(sc: ServerClient, request_id: String) -> AbortOnDrop {
    AbortOnDrop(tokio::spawn(async move {
        let mut last_key = String::new();
        let start = std::time::Instant::now();
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            let req = match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                sc.get_request(&request_id),
            )
            .await
            {
                Ok(Ok(r)) => r,
                _ => continue,
            };
            let status = RequestStatus::from_json(&req["status"]);
            let queue_hint = req["queue_hint"].as_str().unwrap_or("").to_string();
            let key = format!("{status}:{queue_hint}");
            let elapsed = start.elapsed().as_secs();
            if key != last_key {
                match status {
                    RequestStatus::Dispatched => match queue_hint.as_str() {
                        "no_agents" => eprintln!(
                            "  → queued — no agents online. Contact your admin  [{}s]",
                            elapsed
                        ),
                        "agents_saturated" => {
                            eprintln!("  → queued — all agents at capacity  [{}s]", elapsed)
                        }
                        "agents_draining" => {
                            eprintln!(
                                "  → queued — all agents draining (shutting down)  [{}s]",
                                elapsed
                            )
                        }
                        _ => eprintln!("  → queued (waiting for agent)  [{}s]", elapsed),
                    },
                    RequestStatus::Running => {
                        let agent = req["claimed_by"].as_str().unwrap_or("agent");
                        eprintln!("  → executing by {}  [{}s]", agent, elapsed);
                    }
                    RequestStatus::ExecutionLost => {
                        eprintln!("  → execution_lost (agent disconnected)");
                        break;
                    }
                    RequestStatus::Approved => {
                        eprintln!("  → resume expired (no agent picked up)");
                        break;
                    }
                    _ => {}
                }
                last_key = key;
            }
        }
    }))
}

/// Poll the request until it reaches a terminal state or re-dispatches.
/// Returns Some(result) if terminal, None if re-dispatched (caller should retry stream).
async fn poll_until_terminal(
    sc: &ServerClient,
    request_id: &str,
) -> Result<Option<Value>, CliError> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(300);
    let mut req = sc.get_request(request_id).await?;

    loop {
        if std::time::Instant::now() > deadline {
            return Err(CliError::Server(format!(
                "Timed out waiting for execution (5m). Check status: dbward request show {request_id}"
            )));
        }
        let remaining_secs = deadline
            .saturating_duration_since(std::time::Instant::now())
            .as_secs();
        let status = RequestStatus::from_json(&req["status"]);
        match status {
            RequestStatus::Executed | RequestStatus::Failed => {
                return resolve_from_request(sc, request_id, &req).await.map(Some);
            }
            RequestStatus::Dispatched | RequestStatus::Running => {
                let wait = remaining_secs.min(REQUEST_STATUS_WAIT_SECS);
                req = sc.get_request_with_wait(request_id, wait).await?;
            }
            RequestStatus::Approved | RequestStatus::AutoApproved | RequestStatus::BreakGlass => {
                // Stream failed and resume lease expired. Re-resume.
                match sc.resume(request_id).await {
                    Ok(_) => {
                        // Re-dispatched successfully; return None to retry stream
                        return Ok(None);
                    }
                    Err(e) => {
                        return Err(CliError::Server(format!(
                            "request {request_id} is approved but resume failed: {}. Run: dbward request resume {request_id}",
                            e.body
                        )));
                    }
                }
            }
            RequestStatus::Pending => {
                return Err(CliError::Server(format!(
                    "Request {request_id} requires approval. Check status: dbward request show {request_id}"
                )));
            }
            _ => {
                return Err(CliError::Server(format!(
                    "unexpected status: {status}. Try: dbward request resume {request_id}"
                )));
            }
        }
    }
}

/// Resolve the terminal payload from a request JSON.
async fn resolve_from_request(
    sc: &ServerClient,
    request_id: &str,
    req: &Value,
) -> Result<Value, CliError> {
    let status = RequestStatus::from_json(&req["status"]);

    if let Some(payload) = terminal_payload_from_request(req) {
        return Ok(payload);
    }

    match status {
        RequestStatus::Executed | RequestStatus::Failed => {
            match sc.get_result_content(request_id, None).await {
                Ok(result) => Ok(result),
                Err(err) if is_missing_result_content_error(&err) => {
                    Ok(synthesized_terminal_payload(status.as_str(), request_id))
                }
                Err(err) => Err(err),
            }
        }
        _ => Err(CliError::Server(format!(
            "unexpected status: {status}. Try: dbward request resume {request_id}"
        ))),
    }
}

/// Extract terminal payload from embedded execution_result/execution_error fields.
fn terminal_payload_from_request(req: &Value) -> Option<Value> {
    let status = RequestStatus::from_json(&req["status"]);

    if let Some(err) = req.get("execution_error") {
        return Some(serde_json::json!({"success": false, "error": err}));
    }
    if let Some(result) = req.get("execution_result") {
        return Some(serde_json::json!({
            "success": status != RequestStatus::Failed,
            "result": result
        }));
    }

    None
}

fn is_missing_result_content_error(err: &CliError) -> bool {
    match err {
        CliError::Server(msg) => msg.contains("result not stored for this request"),
        _ => false,
    }
}

fn synthesized_terminal_payload(status: &str, request_id: &str) -> Value {
    match status {
        "failed" => serde_json::json!({
            "success": false,
            "error": format!(
                "Request {request_id} failed. Result not available (relay expired, no storage configured). Check: dbward request result {request_id}"
            )
        }),
        _ => serde_json::json!({
            "success": true,
            "error": format!(
                "Request {request_id} executed successfully but result is no longer available. Check: dbward request result {request_id}"
            ),
            "result": Value::Null
        }),
    }
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_payload_prefers_embedded_execution_error() {
        let req = serde_json::json!({
            "status": "failed",
            "execution_error": "boom",
        });

        let payload = terminal_payload_from_request(&req).unwrap();

        assert_eq!(payload["success"], false);
        assert_eq!(payload["error"], "boom");
    }

    #[test]
    fn terminal_payload_extracts_execution_result() {
        let req = serde_json::json!({
            "status": "executed",
            "execution_result": {"rows": []},
        });

        let payload = terminal_payload_from_request(&req).unwrap();

        assert_eq!(payload["success"], true);
        assert_eq!(payload["result"], serde_json::json!({"rows": []}));
    }

    #[test]
    fn terminal_payload_returns_none_when_no_embedded_data() {
        let req = serde_json::json!({
            "status": "executed",
        });

        assert!(terminal_payload_from_request(&req).is_none());
    }

    #[test]
    fn synthesized_terminal_payload_marks_failed_requests_unsuccessful() {
        let payload = synthesized_terminal_payload("failed", "req-123");

        assert_eq!(payload["success"], false);
        assert!(
            payload["error"]
                .as_str()
                .unwrap_or_default()
                .contains("req-123")
        );
    }

    #[test]
    fn synthesized_terminal_payload_marks_executed_requests_successful() {
        let payload = synthesized_terminal_payload("executed", "req-123");

        assert_eq!(payload["success"], true);
        assert!(payload["result"].is_null());
    }

    #[tokio::test]
    async fn wait_and_resolve_fallback_on_stream_failure() {
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 4096];
                let _ = tokio::io::AsyncReadExt::read(&mut socket, &mut buf).await;
                let req_str = String::from_utf8_lossy(&buf);

                let response = if req_str.contains("/result/stream") {
                    "HTTP/1.1 500 Internal Server Error\r\ncontent-length: 0\r\n\r\n".to_string()
                } else if req_str.contains("GET") && req_str.contains("/api/requests/") {
                    let body = serde_json::json!({
                        "id": "test-req", "status": "executed",
                        "operation": "execute_query", "environment": "dev",
                        "database": "app", "detail": "SELECT 1",
                        "created_by": "alice", "created_at": "2026-01-01T00:00:00Z",
                        "updated_at": "2026-01-01T00:00:00Z",
                        "resolved_at": null, "reason": null,
                        "metadata": {}, "idempotency_key": null, "expires_at": null,
                    })
                    .to_string();
                    format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    )
                } else {
                    "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n".to_string()
                };
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });

        let client = ServerClient::new(&format!("http://{addr}"), "test-token");
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            wait_and_resolve(&client, "test-req", false),
        )
        .await;

        server.abort();
        assert!(
            result.is_ok(),
            "wait_and_resolve should not hang on stream failure"
        );
    }

    #[tokio::test]
    async fn poll_until_terminal_redispatches_on_approved() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = call_count.clone();

        let server = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 4096];
                let _ = tokio::io::AsyncReadExt::read(&mut socket, &mut buf).await;
                let req_str = String::from_utf8_lossy(&buf);

                let n = call_count_clone.fetch_add(1, Ordering::SeqCst);
                let response = if req_str.contains("/result/stream") {
                    // Stream always fails
                    "HTTP/1.1 500 Internal Server Error\r\ncontent-length: 0\r\n\r\n".to_string()
                } else if req_str.contains("POST") && req_str.contains("/resume") {
                    // Resume succeeds
                    let body = r#"{"status":"dispatched"}"#;
                    format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    )
                } else if req_str.contains("GET") && req_str.contains("/api/requests/") {
                    // First GET returns "approved" (triggers re-dispatch), subsequent returns "executed"
                    let status = if n <= 2 { "approved" } else { "executed" };
                    let body = serde_json::json!({
                        "id": "test-req", "status": status,
                        "operation": "execute_query", "environment": "dev",
                        "database": "app", "detail": "SELECT 1",
                        "created_by": "alice", "created_at": "2026-01-01T00:00:00Z",
                        "updated_at": "2026-01-01T00:00:00Z",
                        "resolved_at": null, "reason": null,
                        "metadata": {}, "idempotency_key": null, "expires_at": null,
                    })
                    .to_string();
                    format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    )
                } else {
                    "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n".to_string()
                };
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });

        let client = ServerClient::new(&format!("http://{addr}"), "test-token");
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            wait_and_resolve(&client, "test-req", false),
        )
        .await;

        server.abort();
        assert!(result.is_ok(), "should complete after re-dispatch");
        // Verify dispatch was called (call_count includes stream + get + dispatch + stream + get)
        assert!(
            call_count.load(Ordering::SeqCst) >= 3,
            "should have made multiple calls including dispatch"
        );
    }
}
