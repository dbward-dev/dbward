use serde_json::Value;

use crate::ports::McpBackend;
use dbward_domain::auth::AuthUser;

/// Read a resource by URI. Returns the content string.
pub async fn read_resource(
    uri: &str,
    backend: &dyn McpBackend,
    user: &AuthUser,
    _default_database: &str,
    _default_environment: &str,
) -> Result<String, ResourceError> {
    match uri {
        "dbward://migrations/status" => {
            // Read-only: return database list (actual migration status requires tool call)
            let value = backend
                .list_databases(user)
                .await
                .map_err(ResourceError::Internal)?;
            Ok(serde_json::to_string_pretty(&value).unwrap_or_default())
        }
        "dbward://requests/pending" => {
            let value = backend
                .list_pending(20, user)
                .await
                .map_err(ResourceError::Internal)?;
            Ok(serde_json::to_string_pretty(&value).unwrap_or_default())
        }
        "dbward://audit/recent" => {
            let value = backend
                .audit_recent(10, user)
                .await
                .map_err(ResourceError::Internal)?;
            Ok(serde_json::to_string_pretty(&value).unwrap_or_default())
        }
        _ if uri.starts_with("dbward://requests/") => {
            let req_id = uri.strip_prefix("dbward://requests/").unwrap_or("");
            if req_id.is_empty() || !is_valid_identifier(req_id) {
                return Err(ResourceError::NotFound(format!(
                    "Resource not found: {uri}"
                )));
            }
            let value = backend
                .get_request(req_id, user)
                .await
                .map_err(ResourceError::Internal)?;
            Ok(serde_json::to_string_pretty(&value).unwrap_or_default())
        }
        _ if uri.starts_with("dbward://schema/") => {
            let path = uri.strip_prefix("dbward://schema/").unwrap_or("");
            let (db, table) = match path.split_once('/') {
                Some((d, t)) => (d, Some(t)),
                None => (path, None),
            };
            if db.is_empty() || !is_valid_identifier(db) {
                return Err(ResourceError::NotFound(format!(
                    "Resource not found: {uri}"
                )));
            }
            if let Some(t) = table
                && !is_valid_identifier(t)
            {
                return Err(ResourceError::NotFound(format!(
                    "Resource not found: {uri}"
                )));
            }
            let value = backend
                .inspect_schema(db, None, table, table.is_none(), user)
                .await
                .map_err(ResourceError::Internal)?;
            Ok(serde_json::to_string_pretty(&value).unwrap_or_default())
        }
        _ => Err(ResourceError::NotFound(format!(
            "Resource not found: {uri}"
        ))),
    }
}

pub enum ResourceError {
    NotFound(String),
    Internal(String),
}

impl ResourceError {
    pub fn json_rpc_code(&self) -> i32 {
        match self {
            Self::NotFound(_) => crate::protocol::RESOURCE_NOT_FOUND,
            Self::Internal(_) => crate::protocol::INTERNAL_ERROR,
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::NotFound(m) | Self::Internal(m) => m,
        }
    }
}

/// Defense-in-depth: validate URI path segments are safe identifiers.
fn is_valid_identifier(s: &str) -> bool {
    !s.is_empty()
        && !s.contains("..")
        && s.chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
}

/// Resolve URI from template parameters (for resource templates).
pub fn resolve_template_uri(template: &str, params: &Value) -> Option<String> {
    let _ = (template, params);
    None // templates are resolved client-side per MCP spec
}
