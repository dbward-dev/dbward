use std::time::Duration;

use dbward_api_types::requests::RequestStatus;
use serde_json::{Value, json};

use super::super::defs::{
    format_approval_progress, matches_normalized, matches_similarity_terms,
    normalized_similarity_terms,
};
use super::super::server::ElicitHandle;
use super::super::server::ElicitResult;
use super::helpers::{format_result, rewrite_error};

#[allow(clippy::too_many_arguments)]
pub(super) async fn submit_and_wait(
    client: &crate::server_client::ServerClient,
    operation: &str,
    environment: &str,
    database: &str,
    detail: &str,
    reason: Option<&str>,
    elicit: &ElicitHandle,
    supports_elicit: bool,
) -> Result<String, String> {
    use crate::commands::workflow;

    // 1. Create request OUTSIDE timeout (request_id is always preserved)
    let cr = match workflow::create_request(
        client,
        crate::server_client::CreateRequest {
            operation,
            environment,
            database,
            detail,
            emergency: false,
            allow_ddl: false,
            reason,
            metadata: None,
            idempotency_key: None,

            share_with: None,
            no_result_store: false,
        },
    )
    .await
    {
        Ok(cr) => cr,
        Err(e) => {
            let err_str = e.to_string();
            // Reactive elicitation: if reason_required and we can elicit
            if err_str.contains("reason is required") && reason.is_none() && supports_elicit {
                match elicit
                    .ask(
                        "This workflow requires a reason. Why is this operation needed?",
                        json!({
                            "type": "object",
                            "properties": {
                                "reason": {"type": "string", "description": "Why is this operation needed?"}
                            },
                            "required": ["reason"]
                        }),
                    )
                    .await
                {
                    Ok(ElicitResult::Accept { content }) => {
                        if let Some(r) = content["reason"].as_str() {
                            // Retry once with reason
                            let cr2 = workflow::create_request(
                                client,
                                crate::server_client::CreateRequest {
                                    operation,
                                    environment,
                                    database,
                                    detail,
                                    emergency: false,
            allow_ddl: false,
                                    reason: Some(r),
                                    metadata: None,
                                    idempotency_key: None,
                                    share_with: None,
                                    no_result_store: false,
                                },
                            )
                            .await
                            .map_err(|e2| rewrite_error(&e2.to_string()))?;
                            // Continue with cr2 below
                            return submit_and_wait_resume(client, &cr2).await;
                        }
                        return Err(rewrite_error(&err_str));
                    }
                    _ => return Err(rewrite_error(&err_str)),
                }
            }
            return Err(rewrite_error(&err_str));
        }
    };

    submit_and_wait_resume(client, &cr).await
}

/// Continue submit_and_wait after successful request creation.
async fn submit_and_wait_resume(
    client: &crate::server_client::ServerClient,
    cr: &crate::commands::workflow::CreateResult,
) -> Result<String, String> {
    use crate::commands::workflow;

    const TIMEOUT: Duration = Duration::from_secs(120);

    // 2. Pending → return immediately with request_id
    if cr.status == RequestStatus::Pending {
        return Ok(format!(
            "Request {} requires approval. \
             Use dbward_wait_request to wait for completion.",
            cr.request_id
        ));
    }

    // 3. Wait with timeout (request_id preserved on timeout)
    match tokio::time::timeout(
        TIMEOUT,
        workflow::wait_for_completion(client, &cr.request_id, cr.status, false),
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

pub(super) async fn handle_execute_query(
    client: &crate::server_client::ServerClient,
    args: &Value,
    env: &str,
    db_name: &str,
    elicit: &ElicitHandle,
    client_supports_elicitation: bool,
) -> Result<String, String> {
    let sql = args["sql"].as_str().unwrap_or("");
    let db = args["database"].as_str().unwrap_or(db_name);
    let reason = args["reason"].as_str().map(|s| s.to_string());

    if sql.is_empty() {
        Err("sql parameter is required".to_string())
    } else {
        submit_and_wait(
            client,
            "execute_query",
            env,
            db,
            sql,
            reason.as_deref(),
            elicit,
            client_supports_elicitation,
        )
        .await
    }
}

pub(super) async fn handle_list_pending(
    client: &crate::server_client::ServerClient,
) -> Result<String, String> {
    client
        .list_pending_for_me(Some(20))
        .await
        .map(|v| serde_json::to_string_pretty(&v["requests"]).unwrap_or_default())
        .map_err(|e| e.to_string())
}

pub(super) async fn handle_who_can_approve(
    client: &crate::server_client::ServerClient,
    request_id: &str,
) -> Result<String, String> {
    client
        .get_request(request_id)
        .await
        .map(|v| {
            if let Some(progress) = v.get("approval_progress") {
                format_approval_progress(request_id, &v["status"], progress)
            } else {
                "No workflow configured (break-glass)".to_string()
            }
        })
        .map_err(|e| e.to_string())
}

pub(super) async fn handle_find_similar(
    client: &crate::server_client::ServerClient,
    args: &Value,
) -> Result<String, String> {
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
                                    matches_normalized(r["detail"].as_str().unwrap_or(""), sql)
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

pub(super) async fn handle_explain_policy(
    client: &crate::server_client::ServerClient,
    args: &Value,
    env: &str,
    db_name: &str,
) -> Result<String, String> {
    let req_id = args["request_id"].as_str().unwrap_or("");
    if req_id.is_empty() {
        let op = args["operation"].as_str().unwrap_or("execute_select");
        let db = args["database"].as_str().unwrap_or(db_name);
        Ok(format!(
            "To execute '{op}' on {db} ({env}):\n\
             Check if a workflow exists: [[workflows]] with database=\"{db}\" or \"*\", environment=\"{env}\" or \"*\"\n\
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
                    .map(|progress| format_approval_progress(req_id, &v["status"], progress))
                    .unwrap_or_else(|| "none (auto-approved)".to_string());
                format!(
                    "Request {req_id} status: {status}\n\
                     Workflow: {}\n\
                     To approve: dbward request approve {req_id}\n\
                     If you match multiple approver groups, specify: dbward request approve {req_id} --as <selector>",
                    workflow
                )
            })
            .map_err(|e| e.to_string())
    }
}

pub(super) async fn handle_wait_request(
    client: &crate::server_client::ServerClient,
    args: &Value,
) -> Result<String, String> {
    let request_id = args["request_id"].as_str().unwrap_or("");
    let timeout = args["timeout"].as_u64().unwrap_or(60);
    let include_result = args["include_result"].as_bool().unwrap_or(true);

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
    let status: RequestStatus =
        serde_json::from_value(resp["status"].clone()).unwrap_or(RequestStatus::Unknown);

    match status {
        RequestStatus::Pending => Ok(format!("Request {request_id} is still pending approval.")),
        RequestStatus::Approved
        | RequestStatus::AutoApproved
        | RequestStatus::BreakGlass
        | RequestStatus::Dispatched
        | RequestStatus::Running => {
            // Resume if needed, then wait for result
            if matches!(
                status,
                RequestStatus::Approved | RequestStatus::AutoApproved | RequestStatus::BreakGlass
            ) && let Err(e) = client.resume(request_id).await
                // 409 Conflict = already resumed by another actor — continue waiting
                && e.status != 409
            {
                return Ok(format!(
                    "Failed to resume request {request_id}: {}",
                    e.error_message.as_deref().unwrap_or(&e.body)
                ));
            }
            match tokio::time::timeout(
                Duration::from_secs(timeout),
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
        RequestStatus::Executed | RequestStatus::Failed => {
            let result = crate::commands::workflow::resolve_terminal_result(client, request_id)
                .await
                .map_err(|e| e.to_string())?;
            format_result(&result)
        }
        RequestStatus::Rejected => Ok(format!("Request {request_id} was rejected.")),
        RequestStatus::Cancelled => Ok(format!("Request {request_id} was cancelled.")),
        RequestStatus::Expired => Ok(format!("Request {request_id} has expired.")),
        RequestStatus::ExecutionLost => Ok(format!(
            "Request {request_id} execution was lost (agent lease expired). It can be re-resumed."
        )),
        _ => Ok(format!("Request {request_id} status: {}", status)),
    }
}
