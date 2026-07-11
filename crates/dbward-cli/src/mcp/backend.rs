use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};

use dbward_domain::auth::AuthUser;
use dbward_mcp::ports::{
    CreateRequestInput, CreateRequestOutput, McpBackend, McpError, McpResult, RequestStatus,
    WaitOutput,
};

use crate::commands::workflow;
use crate::server_client::ServerClient;

/// CLI implementation of McpBackend — routes all operations through ServerClient (HTTP).
#[allow(dead_code)]
pub(crate) struct CliMcpBackend {
    pub(crate) client: Arc<ServerClient>,
    pub(crate) default_env: String,
    pub(crate) default_db: String,
}

#[async_trait]
impl McpBackend for CliMcpBackend {
    async fn create_request(
        &self,
        input: CreateRequestInput,
        _user: &AuthUser,
    ) -> McpResult<CreateRequestOutput> {
        let cr = workflow::create_request(
            &self.client,
            crate::server_client::CreateRequest {
                operation: &input.operation,
                environment: &input.environment,
                database: &input.database,
                detail: &input.detail,
                emergency: false,
                allow_ddl: false,
                reason: input.reason.as_deref(),
                metadata: None,
                idempotency_key: input.idempotency_key.as_deref(),
                share_with: None,
                no_result_store: false,
            },
        )
        .await
        .map_err(|e| McpError::Internal(e.to_string()))?;

        let status = match cr.status {
            dbward_api_types::requests::RequestStatus::Pending => RequestStatus::Pending,
            dbward_api_types::requests::RequestStatus::Approved
            | dbward_api_types::requests::RequestStatus::AutoApproved
            | dbward_api_types::requests::RequestStatus::BreakGlass
            | dbward_api_types::requests::RequestStatus::Dispatched
            | dbward_api_types::requests::RequestStatus::Running => RequestStatus::Approved,
            dbward_api_types::requests::RequestStatus::Rejected => RequestStatus::Rejected,
            _ => RequestStatus::Failed,
        };

        Ok(CreateRequestOutput {
            request_id: cr.request_id,
            status,
        })
    }

    async fn resume_and_wait(
        &self,
        request_id: &str,
        timeout_secs: u64,
        _user: &AuthUser,
    ) -> McpResult<WaitOutput> {
        // Resume — skip on 409 Conflict (already dispatched/running)
        match self.client.resume(request_id).await {
            Ok(_) => {}
            Err(e) if e.status == 409 => {
                // Already dispatched/running — proceed to wait
            }
            Err(e) => {
                return Err(format!(
                    "resume failed ({}): {}",
                    e.status,
                    e.error_message.unwrap_or(e.body)
                )
                .into());
            }
        }

        // Wait with timeout
        match tokio::time::timeout(
            Duration::from_secs(timeout_secs),
            workflow::wait_for_completion(
                &self.client,
                request_id,
                dbward_api_types::requests::RequestStatus::Approved,
                false,
            ),
        )
        .await
        {
            Ok(Ok(result)) => {
                let text = serde_json::to_string_pretty(&result).unwrap_or_default();
                Ok(WaitOutput::Completed(text))
            }
            Ok(Err(e)) => Err(McpError::Internal(e.to_string())),
            Err(_) => Ok(WaitOutput::TimedOut {
                request_id: request_id.into(),
            }),
        }
    }

    async fn wait_request(
        &self,
        request_id: &str,
        timeout_secs: u64,
        _user: &AuthUser,
    ) -> McpResult<WaitOutput> {
        // Resume + wait
        self.resume_and_wait(request_id, timeout_secs, _user).await
    }

    async fn list_pending(&self, limit: u32, _user: &AuthUser) -> McpResult<Value> {
        self.client
            .list_pending_for_me(Some(limit))
            .await
            .map_err(|e| McpError::Internal(e.to_string()))
    }

    async fn find_similar(&self, sql: &str, limit: u32, _user: &AuthUser) -> McpResult<Value> {
        let path = format!("/api/requests?status=completed&limit={limit}&operation=execute_query");
        let requests = self
            .client
            .get_json(&path)
            .await
            .map_err(|e| McpError::Internal(e.to_string()))?;

        // Client-side containment filter
        let normalized = sql.to_lowercase();
        if let Some(items) = requests["items"].as_array() {
            let filtered: Vec<&Value> = items
                .iter()
                .filter(|r| {
                    let detail = r["detail"].as_str().unwrap_or("").to_lowercase();
                    detail.contains(&normalized) || normalized.contains(&detail)
                })
                .take(limit as usize)
                .collect();
            Ok(json!(filtered))
        } else {
            Ok(requests)
        }
    }

    async fn who_can_approve(&self, request_id: &str, _user: &AuthUser) -> McpResult<Value> {
        self.client
            .get_request(request_id)
            .await
            .map_err(|e| McpError::Internal(e.to_string()))
    }

    async fn explain_policy_failure(
        &self,
        request_id: Option<&str>,
        _operation: Option<&str>,
        _database: &str,
        _environment: &str,
        _user: &AuthUser,
    ) -> McpResult<Value> {
        if let Some(id) = request_id {
            return self
                .client
                .get_request(id)
                .await
                .map_err(|e| McpError::Internal(e.to_string()));
        }
        Ok(json!({"explanation": "Submit a request to see the policy evaluation result."}))
    }

    async fn inspect_schema(
        &self,
        database: &str,
        _environment: Option<&str>,
        table: Option<&str>,
        _summary: bool,
        _user: &AuthUser,
    ) -> McpResult<Value> {
        let path = if let Some(t) = table {
            format!("/api/schemas/{database}?table={t}")
        } else {
            format!("/api/schemas/{database}")
        };
        self.client
            .get_json(&path)
            .await
            .map_err(|e| McpError::Internal(e.to_string()))
    }

    async fn get_request(&self, request_id: &str, _user: &AuthUser) -> McpResult<Value> {
        self.client
            .get_request(request_id)
            .await
            .map_err(|e| McpError::Internal(e.to_string()))
    }

    async fn list_databases(&self, _user: &AuthUser) -> McpResult<Value> {
        self.client
            .get_json("/api/databases")
            .await
            .map_err(|e| McpError::Internal(e.to_string()))
    }

    async fn migrate_status(
        &self,
        database: &str,
        environment: &str,
        reason: Option<String>,
        _user: &AuthUser,
    ) -> McpResult<Value> {
        let input = CreateRequestInput {
            operation: "migrate_status".into(),
            environment: environment.into(),
            database: database.into(),
            detail: "{}".into(),
            reason,
            idempotency_key: None,
        };
        let cr = self.create_request(input, _user).await?;
        if cr.status.is_pending() {
            return Ok(json!({"request_id": cr.request_id, "status": "pending_approval"}));
        }
        match self.resume_and_wait(&cr.request_id, 30, _user).await? {
            WaitOutput::Completed(text) => {
                Ok(serde_json::from_str(&text).unwrap_or(json!({"raw": text})))
            }
            _ => Ok(json!({"request_id": cr.request_id, "status": "in_progress"})),
        }
    }

    async fn audit_recent(&self, limit: u32, _user: &AuthUser) -> McpResult<Value> {
        let path = format!("/api/audit/events?limit={limit}");
        self.client
            .get_json(&path)
            .await
            .map_err(|e| McpError::Internal(e.to_string()))
    }
}
