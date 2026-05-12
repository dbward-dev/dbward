use axum::{
    extract::{Extension, State},
    http::StatusCode,
    response::IntoResponse,
};

use dbward_domain::auth::{AuthUser, Permission};

use crate::state::AppState;

pub async fn metrics(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    state.authorizer.authorize_global(&user, Permission::MetricsView)
        .map_err(|_| (StatusCode::FORBIDDEN, "forbidden".to_string()))?;

    let body = crate::metrics::render(
        &state.metrics,
        state.request_repo.as_ref(),
        state.agent_repo.as_ref(),
    );

    Ok((
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        body,
    ))
}
