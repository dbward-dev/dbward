use serde_json::Value;

use crate::ports::{CreateRequestInput, ElicitResult, McpError, McpResult, WaitOutput};

use super::ToolContext;

pub(super) async fn execute_query(ctx: &ToolContext<'_>, args: &Value) -> Result<String, String> {
    let sql = require_str(args, "sql")?;
    let db = str_or(args, "database", ctx.default_database);
    let env = str_or(args, "environment", ctx.default_environment);
    let reason = args["reason"].as_str().map(String::from);
    let idempotency_key = args["_idempotency_key"].as_str().map(String::from);

    let make_input = |reason: Option<String>, key: Option<String>| CreateRequestInput {
        operation: "execute".into(),
        environment: env.into(),
        database: db.into(),
        detail: sql.into(),
        reason,
        idempotency_key: key,
    };

    let cr = match ctx
        .backend
        .create_request(
            make_input(reason.clone(), idempotency_key.clone()),
            ctx.user,
        )
        .await
    {
        Ok(cr) => cr,
        Err(McpError::ReasonRequired { message, schema })
            if reason.is_none() && ctx.elicit.supported() =>
        {
            match ctx.elicit.ask(&message, schema).await {
                Ok(ElicitResult::Accept { content }) => {
                    let r = content["reason"].as_str().ok_or_else(|| {
                        "reason field missing in elicitation response".to_string()
                    })?;
                    ctx.backend
                        .create_request(make_input(Some(r.into()), idempotency_key), ctx.user)
                        .await
                        .map_err(|e| e.to_string())?
                }
                _ => return Err(message),
            }
        }
        Err(e) => return Err(e.to_string()),
    };

    if cr.status.is_pending() {
        return Ok(format!(
            "Request {} requires approval. Use dbward_wait_request to wait for completion.",
            cr.request_id
        ));
    }
    if cr.status.is_terminal_failure() {
        return Err(format!("Request {} was {:?}.", cr.request_id, cr.status));
    }
    match ctx
        .backend
        .resume_and_wait(&cr.request_id, 120, ctx.user)
        .await
        .map_err(|e| e.to_string())?
    {
        WaitOutput::Completed(text) => Ok(text),
        WaitOutput::Pending { request_id } => Ok(format!(
            "Request {request_id} requires approval. Use dbward_wait_request to wait for completion."
        )),
        WaitOutput::TimedOut { request_id } => Ok(format!(
            "Request {request_id} is still executing (timed out after 120s). \
             Use dbward_wait_request with request_id '{request_id}' to get the result."
        )),
    }
}

pub(super) async fn wait_request(ctx: &ToolContext<'_>, args: &Value) -> Result<String, String> {
    let request_id = require_str(args, "request_id")?;
    let timeout = args["timeout"].as_u64().unwrap_or(60).min(300);
    let include_result = args["include_result"].as_bool().unwrap_or(true);

    if !include_result {
        let value = ctx
            .backend
            .get_request(request_id, ctx.user)
            .await
            .map_err(|e| e.to_string())?;
        return Ok(format_json(value));
    }

    match ctx
        .backend
        .resume_and_wait(request_id, timeout, ctx.user)
        .await
        .map_err(|e| e.to_string())?
    {
        WaitOutput::Completed(text) => Ok(text),
        WaitOutput::Pending { request_id } => {
            Ok(format!("Request {request_id} is still pending approval."))
        }
        WaitOutput::TimedOut { request_id } => Ok(format!(
            "Request {request_id} timed out. Use dbward_wait_request again to retry."
        )),
    }
}

pub(super) async fn list_pending(ctx: &ToolContext<'_>) -> Result<String, String> {
    ctx.backend
        .list_pending(20, ctx.user)
        .await
        .map(format_json)
        .map_err(|e| e.to_string())
}

pub(super) async fn find_similar(ctx: &ToolContext<'_>, args: &Value) -> Result<String, String> {
    let sql = args["sql"].as_str().unwrap_or("").trim();
    if sql.is_empty() {
        return Err("At least 'sql' parameter is required for similarity search".into());
    }
    let limit = args["limit"].as_u64().unwrap_or(5) as u32;
    ctx.backend
        .find_similar(sql, limit, ctx.user)
        .await
        .map(format_json)
        .map_err(|e| e.to_string())
}

pub(super) async fn who_can_approve(ctx: &ToolContext<'_>, args: &Value) -> Result<String, String> {
    let request_id = require_str(args, "request_id")?;
    ctx.backend
        .who_can_approve(request_id, ctx.user)
        .await
        .map(format_json)
        .map_err(|e| e.to_string())
}

pub(super) async fn explain_policy_failure(
    ctx: &ToolContext<'_>,
    args: &Value,
) -> Result<String, String> {
    let request_id = args["request_id"]
        .as_str()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());
    let operation = args["operation"].as_str();
    let db = str_or(args, "database", ctx.default_database);
    let env = str_or(args, "environment", ctx.default_environment);
    ctx.backend
        .explain_policy_failure(request_id, operation, db, env, ctx.user)
        .await
        .map(format_json)
        .map_err(|e| e.to_string())
}

// --- Helpers ---

/// Elicitation retry helper. Calls the backend operation, and if it returns
/// `ReasonRequired` with elicitation supported, asks the client for a reason
/// and retries once with the provided reason.
pub(super) async fn with_elicitation<'a, F, Fut>(
    ctx: &ToolContext<'a>,
    reason: Option<String>,
    f: F,
) -> Result<Value, String>
where
    F: Fn(Option<String>) -> Fut,
    Fut: std::future::Future<Output = McpResult<Value>>,
{
    match f(reason.clone()).await {
        Ok(v) => Ok(v),
        Err(McpError::ReasonRequired { message, schema })
            if reason.is_none() && ctx.elicit.supported() =>
        {
            match ctx.elicit.ask(&message, schema).await {
                Ok(ElicitResult::Accept { content }) => {
                    let r = content["reason"]
                        .as_str()
                        .ok_or("elicitation response missing 'reason' field")?;
                    f(Some(r.to_string())).await.map_err(|e| e.to_string())
                }
                _ => Err(message),
            }
        }
        Err(e) => Err(e.to_string()),
    }
}

fn require_str<'a>(args: &'a Value, key: &str) -> Result<&'a str, String> {
    args[key]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("Missing required argument: {key}"))
}

fn str_or<'a>(args: &'a Value, key: &str, default: &'a str) -> &'a str {
    args[key].as_str().unwrap_or(default)
}

fn format_json(value: Value) -> String {
    serde_json::to_string_pretty(&value).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::{ElicitResult, ElicitationTransport, McpError, McpResult};
    use async_trait::async_trait;
    use serde_json::{Value, json};
    use std::sync::atomic::{AtomicU32, Ordering};

    struct MockElicit {
        result: ElicitResult,
    }

    #[async_trait]
    impl ElicitationTransport for MockElicit {
        fn supported(&self) -> bool {
            true
        }
        async fn ask(&self, _message: &str, _schema: Value) -> Result<ElicitResult, String> {
            Ok(self.result.clone())
        }
    }

    struct NoElicit;

    #[async_trait]
    impl ElicitationTransport for NoElicit {
        fn supported(&self) -> bool {
            false
        }
        async fn ask(&self, _: &str, _: Value) -> Result<ElicitResult, String> {
            Err("not supported".into())
        }
    }

    fn make_ctx<'a>(elicit: &'a dyn ElicitationTransport) -> ToolContext<'a> {
        use dbward_domain::auth::{AuthUser, SubjectType};
        static USER: std::sync::LazyLock<AuthUser> = std::sync::LazyLock::new(|| AuthUser {
            subject_id: "u1".into(),
            subject_type: SubjectType::User,
            groups: vec![],
            roles: vec![],
            token_id: None,
        });
        static BACKEND: std::sync::LazyLock<DummyBackend> =
            std::sync::LazyLock::new(|| DummyBackend);
        ToolContext {
            backend: &*BACKEND,
            elicit,
            user: &USER,
            default_database: "app",
            default_environment: "dev",
        }
    }

    /// Minimal backend that satisfies the trait (never actually called in these tests).
    struct DummyBackend;

    #[async_trait]
    impl crate::ports::McpBackend for DummyBackend {
        async fn create_request(
            &self,
            _: crate::ports::CreateRequestInput,
            _: &dbward_domain::auth::AuthUser,
        ) -> McpResult<crate::ports::CreateRequestOutput> {
            unimplemented!()
        }
        async fn resume_and_wait(
            &self,
            _: &str,
            _: u64,
            _: &dbward_domain::auth::AuthUser,
        ) -> McpResult<crate::ports::WaitOutput> {
            unimplemented!()
        }
        async fn wait_request(
            &self,
            _: &str,
            _: u64,
            _: &dbward_domain::auth::AuthUser,
        ) -> McpResult<crate::ports::WaitOutput> {
            unimplemented!()
        }
        async fn list_pending(
            &self,
            _: u32,
            _: &dbward_domain::auth::AuthUser,
        ) -> McpResult<Value> {
            unimplemented!()
        }
        async fn find_similar(
            &self,
            _: &str,
            _: u32,
            _: &dbward_domain::auth::AuthUser,
        ) -> McpResult<Value> {
            unimplemented!()
        }
        async fn who_can_approve(
            &self,
            _: &str,
            _: &dbward_domain::auth::AuthUser,
        ) -> McpResult<Value> {
            unimplemented!()
        }
        async fn explain_policy_failure(
            &self,
            _: Option<&str>,
            _: Option<&str>,
            _: &str,
            _: &str,
            _: &dbward_domain::auth::AuthUser,
        ) -> McpResult<Value> {
            unimplemented!()
        }
        async fn inspect_schema(
            &self,
            _: &str,
            _: Option<&str>,
            _: Option<&str>,
            _: bool,
            _: &dbward_domain::auth::AuthUser,
        ) -> McpResult<Value> {
            unimplemented!()
        }
        async fn list_databases(&self, _: &dbward_domain::auth::AuthUser) -> McpResult<Value> {
            unimplemented!()
        }
        async fn get_request(
            &self,
            _: &str,
            _: &dbward_domain::auth::AuthUser,
        ) -> McpResult<Value> {
            unimplemented!()
        }
        async fn migrate_status(
            &self,
            _: &str,
            _: &str,
            _: Option<String>,
            _: &dbward_domain::auth::AuthUser,
        ) -> McpResult<Value> {
            unimplemented!()
        }
        async fn audit_recent(
            &self,
            _: u32,
            _: &dbward_domain::auth::AuthUser,
        ) -> McpResult<Value> {
            unimplemented!()
        }
    }

    #[tokio::test]
    async fn with_elicitation_passes_through_on_success() {
        let elicit = MockElicit {
            result: ElicitResult::Accept {
                content: json!({"reason": "test"}),
            },
        };
        let ctx = make_ctx(&elicit);
        let result = with_elicitation(&ctx, None, |_r| async { Ok(json!({"ok": true})) }).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap()["ok"], true);
    }

    #[tokio::test]
    async fn with_elicitation_retries_with_reason_on_accept() {
        let call_count = AtomicU32::new(0);
        let elicit = MockElicit {
            result: ElicitResult::Accept {
                content: json!({"reason": "because"}),
            },
        };
        let ctx = make_ctx(&elicit);
        let result = with_elicitation(&ctx, None, |r| {
            let n = call_count.fetch_add(1, Ordering::Relaxed);
            async move {
                if n == 0 && r.is_none() {
                    Err(McpError::ReasonRequired {
                        message: "reason required".into(),
                        schema: json!({}),
                    })
                } else {
                    assert_eq!(r.as_deref(), Some("because"));
                    Ok(json!({"retried": true}))
                }
            }
        })
        .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap()["retried"], true);
        assert_eq!(call_count.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn with_elicitation_returns_error_when_not_supported() {
        let elicit = NoElicit;
        let ctx = make_ctx(&elicit);
        let result = with_elicitation(&ctx, None, |_r| async {
            Err(McpError::ReasonRequired {
                message: "reason required".into(),
                schema: json!({}),
            })
        })
        .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("reason required"));
    }

    #[tokio::test]
    async fn with_elicitation_returns_error_on_decline() {
        let elicit = MockElicit {
            result: ElicitResult::Decline,
        };
        let ctx = make_ctx(&elicit);
        let result = with_elicitation(&ctx, None, |_r| async {
            Err(McpError::ReasonRequired {
                message: "reason required".into(),
                schema: json!({}),
            })
        })
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn with_elicitation_errors_when_reason_field_missing() {
        let elicit = MockElicit {
            result: ElicitResult::Accept {
                content: json!({"not_reason": "x"}),
            },
        };
        let ctx = make_ctx(&elicit);
        let result = with_elicitation(&ctx, None, |_r| async {
            Err(McpError::ReasonRequired {
                message: "reason required".into(),
                schema: json!({}),
            })
        })
        .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("'reason' field"));
    }

    #[tokio::test]
    async fn with_elicitation_skips_when_reason_provided() {
        let elicit = MockElicit {
            result: ElicitResult::Accept {
                content: json!({"reason": "should not be called"}),
            },
        };
        let ctx = make_ctx(&elicit);
        let result = with_elicitation(&ctx, Some("pre-provided".into()), |r| async move {
            assert_eq!(r.as_deref(), Some("pre-provided"));
            Ok(json!({"direct": true}))
        })
        .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap()["direct"], true);
    }
}
