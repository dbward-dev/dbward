use axum::{
    extract::{MatchedPath, State},
    middleware::Next,
    response::Response,
};

use crate::state::AppState;

pub async fn metrics_middleware(
    State(state): State<AppState>,
    matched_path: Option<MatchedPath>,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    let method = req.method().to_string();
    let path = matched_path
        .map(|mp| mp.as_str().to_string())
        .unwrap_or_else(|| "<unmatched>".to_string());
    let start = std::time::Instant::now();

    let response = next.run(req).await;

    let status = response.status().as_u16().to_string();
    let duration = start.elapsed().as_secs_f64();

    state
        .metrics
        .http_requests_total
        .inc([&method, &path, &status]);
    state
        .metrics
        .http_request_duration
        .observe([&method, &path], duration);

    response
}
