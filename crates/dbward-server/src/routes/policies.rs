use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    Json,
};
use dbward_app::use_cases::policy_manage::PolicyManage;
use dbward_domain::auth::{AuthUser, RoleDefinition};
use dbward_domain::policies::{ExecutionPolicy, Workflow};

use crate::state::AppState;

use super::map_error;

fn make_uc(state: &AppState) -> PolicyManage {
    PolicyManage {
        authorizer: state.authorizer.clone(),
        policy_repo: state.policy_repo.clone(),
        license: state.license_checker.clone(),
        audit: state.audit_logger.clone(),
    }
}

pub async fn create_workflow(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Json(body): Json<Workflow>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let uc = make_uc(&state);
    let wf = uc.create_workflow(body, &user).map_err(map_error)?;
    Ok((StatusCode::CREATED, Json(serde_json::json!(wf))))
}

pub async fn list_workflows(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let uc = make_uc(&state);
    let workflows = uc.list_workflows(&user).map_err(map_error)?;
    Ok((StatusCode::OK, Json(serde_json::json!({ "workflows": workflows }))))
}

pub async fn delete_workflow(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let uc = make_uc(&state);
    uc.delete_workflow(&id, &user).map_err(map_error)?;
    Ok((StatusCode::NO_CONTENT, Json(serde_json::json!(null))))
}

pub async fn create_execution_policy(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Json(body): Json<ExecutionPolicy>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let uc = make_uc(&state);
    let ep = uc.create_execution_policy(body, &user).map_err(map_error)?;
    Ok((StatusCode::CREATED, Json(serde_json::json!(ep))))
}

pub async fn list_execution_policies(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let uc = make_uc(&state);
    let policies = uc.list_execution_policies(&user).map_err(map_error)?;
    Ok((StatusCode::OK, Json(serde_json::json!({ "execution_policies": policies }))))
}

pub async fn delete_execution_policy(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let uc = make_uc(&state);
    uc.delete_execution_policy(&id, &user).map_err(map_error)?;
    Ok((StatusCode::NO_CONTENT, Json(serde_json::json!(null))))
}

pub async fn create_role(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Json(body): Json<RoleDefinition>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let uc = make_uc(&state);
    let role = uc.create_role(body, &user).map_err(map_error)?;
    Ok((StatusCode::CREATED, Json(serde_json::json!(role))))
}

pub async fn list_roles(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let uc = make_uc(&state);
    let roles = uc.list_roles(&user).map_err(map_error)?;
    Ok((StatusCode::OK, Json(serde_json::json!({ "roles": roles }))))
}

pub async fn delete_role(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(name): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let uc = make_uc(&state);
    uc.delete_role(&name, &user).map_err(map_error)?;
    Ok((StatusCode::NO_CONTENT, Json(serde_json::json!(null))))
}
