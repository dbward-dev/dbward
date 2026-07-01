use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use serde::Deserialize;
use serde_json::json;

use dbward_app::error::AppError;
use dbward_app::ports::PreflightJob;
use dbward_app::use_cases::preflight::{ImpactStatus, PreflightExplainRequest, PreflightInput};
use dbward_domain::auth::AuthUser;
use dbward_domain::entities::AuditEvent;
use dbward_domain::services::sql_redactor;
use dbward_domain::values::{DatabaseName, Environment};

use crate::middleware::trusted_proxies::ClientIp;
use crate::preflight_notifier::NotifierGuard;
use crate::routes::map_error;
use crate::state::AppState;

type ApiResult =
    Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)>;

#[derive(Deserialize)]
pub struct PreflightBody {
    pub database: String,
    pub environment: String,
    pub sql: String,
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default = "default_include_explain")]
    pub include_explain: bool,
    #[serde(default = "default_explain_timeout")]
    pub explain_timeout_ms: u64,
}

fn default_include_explain() -> bool {
    true
}
fn default_explain_timeout() -> u64 {
    5000
}

pub async fn create(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    client_ip: Option<Extension<ClientIp>>,
    connect_info: Option<Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    Json(body): Json<PreflightBody>,
) -> ApiResult {
    // TODO(PRE-1): Add per-user rate limiter (30 req/min sliding window).
    // The DB-based concurrent limit (create_with_limit) prevents abuse for now.
    // Full rate limiter deferred to follow-up PR.

    let database = DatabaseName::new(&body.database)
        .map_err(|e| map_error(AppError::Validation(e.to_string())))?;
    let environment = Environment::new(&body.environment)
        .map_err(|e| map_error(AppError::Validation(e.to_string())))?;

    // Clamp timeout to server max
    let explain_timeout_ms = body
        .explain_timeout_ms
        .min(state.preflight_max_explain_timeout_ms);

    let input = PreflightInput {
        database,
        environment,
        sql: body.sql.clone(),
        operation_override: body.operation,
        include_explain: body.include_explain,
        explain_timeout_ms,
    };

    // Execute static analysis (layers 1-4)
    let uc = state.preflight();
    let (mut result, explain_request) = uc.execute(&user, &input).map_err(map_error)?;

    // Layer 5: EXPLAIN via agent (if needed)
    if let Some(explain_req) = explain_request {
        let impact = handle_explain(&state, &explain_req)
            .await
            .map_err(map_error)?;
        result.impact = impact;
    }

    // Audit (best-effort)
    let audit_ctx = super::extract_audit_context(
        client_ip.as_ref().map(|e| &e.0),
        connect_info.as_ref().map(|e| &e.0),
    );
    let fingerprint = sql_redactor::redact_literals(&body.sql);
    let audit_event = build_audit_event(
        &user,
        &body.database,
        &body.environment,
        &result,
        &fingerprint,
        body.include_explain,
        &audit_ctx,
    );
    if let Err(e) = state.audit_logger().record(&audit_event) {
        tracing::warn!("preflight audit write failed: {e}");
    }

    Ok((
        StatusCode::OK,
        Json(serde_json::to_value(&result).unwrap_or(json!({}))),
    ))
}

async fn handle_explain(
    state: &AppState,
    req: &PreflightExplainRequest,
) -> Result<dbward_app::use_cases::preflight::PreflightImpact, AppError> {
    use dbward_app::use_cases::preflight::PreflightImpact;

    let notifier = &state.preflight_notifier;
    let repo = &state.preflight_job_repo;

    // 1. Register waiter BEFORE job becomes visible
    let mut rx = notifier.register(&req.job_id);
    let _guard = NotifierGuard::new(notifier, req.job_id.clone());

    // 2. Create job in DB (atomic concurrent limit check)
    let now = chrono::Utc::now();
    let expires_at = now + chrono::Duration::milliseconds(req.timeout_ms as i64 + 5000);
    let job = PreflightJob {
        id: req.job_id.clone(),
        user_id: req.user_id.clone(),
        database_name: req.database.to_string(),
        environment: req.environment.to_string(),
        sql_text: req.sql.clone(),
        status: "pending".into(),
        claimed_by: None,
        claim_token: None,
        result_json: None,
        error_message: None,
        created_at: now.to_rfc3339(),
        expires_at: expires_at.to_rfc3339(),
        completed_at: None,
    };

    let repo_clone = repo.clone();
    let job_clone = job.clone();
    let max_concurrent = state.preflight_max_concurrent_per_user;
    let create_result = tokio::task::spawn_blocking(move || {
        repo_clone.create_with_limit(&job_clone, max_concurrent)
    })
    .await;

    match create_result {
        Ok(Ok(())) => {}
        Ok(Err(e @ AppError::RateLimited(_))) => {
            return Err(e);
        }
        Ok(Err(_)) | Err(_) => {
            return Ok(PreflightImpact {
                status: ImpactStatus::Error,
                explain_plan: None,
                estimated_rows: None,
                estimated_cost: None,
                index_used: None,
            });
        }
    }

    // 3. Wait for notification OR timeout
    let timeout = Duration::from_millis(req.timeout_ms);
    let _ = tokio::time::timeout(timeout, rx.changed()).await;

    // 4. Always check DB state as fallback (handles lost-wakeup)
    let repo_clone = repo.clone();
    let job_id = req.job_id.clone();
    let job_record = tokio::task::spawn_blocking(move || repo_clone.get(&job_id))
        .await
        .ok()
        .and_then(|r| r.ok())
        .flatten();

    match job_record {
        Some(j) if j.status == "completed" => {
            let plan: Option<serde_json::Value> = j
                .result_json
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok());
            Ok(PreflightImpact {
                status: ImpactStatus::Completed,
                explain_plan: plan,
                estimated_rows: None,
                estimated_cost: None,
                index_used: None,
            })
        }
        Some(j) if j.status == "error" => Ok(PreflightImpact {
            status: ImpactStatus::Error,
            explain_plan: None,
            estimated_rows: None,
            estimated_cost: None,
            index_used: None,
        }),
        _ => {
            // Mark the job as expired so it no longer counts against concurrent limit
            let repo_expire = repo.clone();
            let job_id_expire = req.job_id.clone();
            let _ = tokio::task::spawn_blocking(move || repo_expire.mark_expired_by_id(&job_id_expire)).await;
            Ok(PreflightImpact {
                status: ImpactStatus::Timeout,
                explain_plan: None,
                estimated_rows: None,
                estimated_cost: None,
                index_used: None,
            })
        },
    }
}

fn build_audit_event(
    user: &AuthUser,
    database: &str,
    environment: &str,
    result: &dbward_app::use_cases::preflight::PreflightResult,
    fingerprint: &str,
    include_explain: bool,
    audit_ctx: &dbward_domain::entities::AuditContext,
) -> AuditEvent {
    let blocked_codes: Vec<&str> = result
        .review
        .findings
        .iter()
        .filter(|f| f.action == "block")
        .map(|f| f.code.as_str())
        .collect();

    let mut event = AuditEvent::simple(
        "preflight.attempted",
        "preflight",
        &user.subject_id,
        None,
        chrono::Utc::now(),
        audit_ctx,
    );
    event.database_name = Some(database.to_string());
    event.environment = Some(environment.to_string());
    event.detail_fingerprint = Some(fingerprint.to_string());
    event.metadata_json = json!({
        "status": format!("{:?}", result.status).to_lowercase(),
        "risk_level": format!("{:?}", result.risk).to_lowercase(),
        "impact_status": format!("{:?}", result.impact.status).to_lowercase(),
        "blocked_codes": blocked_codes,
        "include_explain": include_explain,
    })
    .to_string();
    event
}
