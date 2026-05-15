use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
};
use dbward_app::use_cases::policy_manage::{
    CreateNotificationPolicyInput, CreateResultPolicyInput, CreateWorkflowInput, PolicyManage,
    UpdateNotificationPolicyInput, UpdateResultPolicyInput,
};
use dbward_domain::auth::{AuthUser, RoleDefinition};
use dbward_domain::policies::{DeliveryMode, ExecutionPolicy, WorkflowStep};
use dbward_domain::values::{DatabaseName, Environment, Operation, Selector};

use crate::middleware::trusted_proxies::ClientIp;
use crate::state::AppState;

use super::map_error;

fn make_uc(state: &AppState) -> PolicyManage {
    PolicyManage {
        authorizer: state.authorizer.clone(),
        policy_repo: state.policy_repo.clone(),
        license: state.license_checker.clone(),
        audit: state.audit_logger.clone(),
        clock: state.clock.clone(),
        id_gen: state.id_generator.clone(),
    }
}

#[derive(serde::Deserialize)]
pub(super) struct CreateWorkflowBody {
    #[serde(default = "star")]
    database: String,
    #[serde(default = "star")]
    environment: String,
    #[serde(default)]
    operations: Vec<Operation>,
    #[serde(default)]
    steps: Vec<WorkflowStep>,
    #[serde(default)]
    require_reason: bool,
}
fn star() -> String {
    "*".into()
}

pub async fn create_workflow(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    client_ip: Option<Extension<ClientIp>>,
    connect_info: Option<Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    Json(body): Json<CreateWorkflowBody>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let ctx = super::extract_audit_context(
        client_ip.as_ref().map(|e| &e.0),
        connect_info.as_ref().map(|e| &e.0),
    );
    let database = DatabaseName::new(body.database)
        .map_err(|e| map_error(dbward_app::error::AppError::Validation(e.into())))?;
    let environment = Environment::new(body.environment)
        .map_err(|e| map_error(dbward_app::error::AppError::Validation(e.into())))?;
    let input = CreateWorkflowInput {
        database,
        environment,
        operations: body.operations,
        steps: body.steps,
        require_reason: body.require_reason,
    };
    let uc = make_uc(&state);
    let wf = uc.create_workflow(input, &user, &ctx).map_err(map_error)?;
    Ok((StatusCode::CREATED, Json(serde_json::json!(wf))))
}

pub async fn list_workflows(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let uc = make_uc(&state);
    let workflows = uc.list_workflows(&user).map_err(map_error)?;
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({ "workflows": workflows })),
    ))
}

pub async fn delete_workflow(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    client_ip: Option<Extension<ClientIp>>,
    connect_info: Option<Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let ctx = super::extract_audit_context(
        client_ip.as_ref().map(|e| &e.0),
        connect_info.as_ref().map(|e| &e.0),
    );
    let uc = make_uc(&state);
    uc.delete_workflow(&id, &user, &ctx).map_err(map_error)?;
    Ok((StatusCode::NO_CONTENT, Json(serde_json::json!(null))))
}

pub async fn create_execution_policy(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    client_ip: Option<Extension<ClientIp>>,
    connect_info: Option<Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    Json(body): Json<ExecutionPolicy>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let ctx = super::extract_audit_context(
        client_ip.as_ref().map(|e| &e.0),
        connect_info.as_ref().map(|e| &e.0),
    );
    let uc = make_uc(&state);
    let ep = uc
        .create_execution_policy(body, &user, &ctx)
        .map_err(map_error)?;
    Ok((StatusCode::CREATED, Json(serde_json::json!(ep))))
}

pub async fn list_execution_policies(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let uc = make_uc(&state);
    let policies = uc.list_execution_policies(&user).map_err(map_error)?;
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({ "execution_policies": policies })),
    ))
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
    client_ip: Option<Extension<ClientIp>>,
    connect_info: Option<Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    Json(body): Json<RoleDefinition>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let ctx = super::extract_audit_context(
        client_ip.as_ref().map(|e| &e.0),
        connect_info.as_ref().map(|e| &e.0),
    );
    let uc = make_uc(&state);
    let role = uc.create_role(body, &user, &ctx).map_err(map_error)?;
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

// --- ResultPolicy CRUD ---

pub(super) async fn create_result_policy(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    client_ip: Option<Extension<ClientIp>>,
    connect_info: Option<Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    Json(body): Json<dbward_api_types::policies::CreateResultPolicyRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let ctx = super::extract_audit_context(
        client_ip.as_ref().map(|e| &e.0),
        connect_info.as_ref().map(|e| &e.0),
    );
    let database = DatabaseName::new(&body.database)
        .map_err(|e| map_error(dbward_app::error::AppError::Validation(e.to_string())))?;
    let environment = Environment::new(&body.environment)
        .map_err(|e| map_error(dbward_app::error::AppError::Validation(e.to_string())))?;
    let delivery_mode: DeliveryMode = serde_json::from_value(serde_json::Value::String(
        body.delivery_mode.clone(),
    ))
    .map_err(|_| {
        map_error(dbward_app::error::AppError::Validation(format!(
            "invalid delivery_mode: {}",
            body.delivery_mode
        )))
    })?;
    let access: Vec<Selector> = body
        .access
        .iter()
        .map(|s| {
            Selector::parse(s)
                .map_err(|e| map_error(dbward_app::error::AppError::Validation(e.0.clone())))
        })
        .collect::<Result<_, _>>()?;

    let uc = make_uc(&state);
    let policy = uc
        .create_result_policy(
            CreateResultPolicyInput {
                database,
                environment,
                retention_days: body.retention_days,
                delivery_mode,
                access,
            },
            &user,
            &ctx,
        )
        .map_err(map_error)?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": policy.id,
            "database": policy.database.as_str(),
            "environment": policy.environment.as_str(),
            "retention_days": policy.retention_days,
            "delivery_mode": policy.delivery_mode,
            "access": policy.access.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            "created_at": policy.created_at.map(|d| d.to_rfc3339()),
            "updated_at": policy.updated_at.map(|d| d.to_rfc3339()),
        })),
    ))
}

pub(super) async fn list_result_policies(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let uc = make_uc(&state);
    let policies = uc.list_result_policies(&user).map_err(map_error)?;
    let items: Vec<serde_json::Value> = policies
        .iter()
        .map(|p| {
            serde_json::json!({
                "id": p.id,
                "database": p.database.as_str(),
                "environment": p.environment.as_str(),
                "retention_days": p.retention_days,
                "delivery_mode": p.delivery_mode,
                "access": p.access.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                "created_at": p.created_at.map(|d| d.to_rfc3339()),
                "updated_at": p.updated_at.map(|d| d.to_rfc3339()),
            })
        })
        .collect();
    Ok((StatusCode::OK, Json(serde_json::json!(items))))
}

pub(super) async fn get_result_policy(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let uc = make_uc(&state);
    let policy = uc.get_result_policy(&id, &user).map_err(map_error)?;
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "id": policy.id,
            "database": policy.database.as_str(),
            "environment": policy.environment.as_str(),
            "retention_days": policy.retention_days,
            "delivery_mode": policy.delivery_mode,
            "access": policy.access.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            "created_at": policy.created_at.map(|d| d.to_rfc3339()),
            "updated_at": policy.updated_at.map(|d| d.to_rfc3339()),
        })),
    ))
}

pub(super) async fn update_result_policy(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    client_ip: Option<Extension<ClientIp>>,
    connect_info: Option<Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    Path(id): Path<String>,
    Json(body): Json<dbward_api_types::policies::UpdateResultPolicyRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let ctx = super::extract_audit_context(
        client_ip.as_ref().map(|e| &e.0),
        connect_info.as_ref().map(|e| &e.0),
    );
    let delivery_mode =
        body.delivery_mode
            .map(|s| {
                serde_json::from_value::<DeliveryMode>(serde_json::Value::String(s.clone()))
                    .map_err(|_| {
                        map_error(dbward_app::error::AppError::Validation(format!(
                            "invalid delivery_mode: {s}"
                        )))
                    })
            })
            .transpose()?;
    let access = body
        .access
        .map(|v| {
            v.iter()
                .map(|s| {
                    Selector::parse(s).map_err(|e| {
                        map_error(dbward_app::error::AppError::Validation(e.0.clone()))
                    })
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;

    let uc = make_uc(&state);
    let policy = uc
        .update_result_policy(
            &id,
            UpdateResultPolicyInput {
                retention_days: body.retention_days,
                delivery_mode,
                access,
            },
            &user,
            &ctx,
        )
        .map_err(map_error)?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "id": policy.id,
            "database": policy.database.as_str(),
            "environment": policy.environment.as_str(),
            "retention_days": policy.retention_days,
            "delivery_mode": policy.delivery_mode,
            "access": policy.access.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            "created_at": policy.created_at.map(|d| d.to_rfc3339()),
            "updated_at": policy.updated_at.map(|d| d.to_rfc3339()),
        })),
    ))
}

pub(super) async fn delete_result_policy(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    client_ip: Option<Extension<ClientIp>>,
    connect_info: Option<Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let ctx = super::extract_audit_context(
        client_ip.as_ref().map(|e| &e.0),
        connect_info.as_ref().map(|e| &e.0),
    );
    let uc = make_uc(&state);
    uc.delete_result_policy(&id, &user, &ctx)
        .map_err(map_error)?;
    Ok((StatusCode::NO_CONTENT, Json(serde_json::json!(null))))
}

// --- NotificationPolicy CRUD ---

pub(super) async fn create_notification_policy(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    client_ip: Option<Extension<ClientIp>>,
    connect_info: Option<Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    Json(body): Json<dbward_api_types::policies::CreateNotificationPolicyRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let ctx = super::extract_audit_context(
        client_ip.as_ref().map(|e| &e.0),
        connect_info.as_ref().map(|e| &e.0),
    );
    let database = DatabaseName::new(&body.database)
        .map_err(|e| map_error(dbward_app::error::AppError::Validation(e.to_string())))?;
    let environment = Environment::new(&body.environment)
        .map_err(|e| map_error(dbward_app::error::AppError::Validation(e.to_string())))?;

    let uc = make_uc(&state);
    let policy = uc
        .create_notification_policy(
            CreateNotificationPolicyInput {
                database,
                environment,
                webhooks: body.webhooks,
                events: body.events,
            },
            &user,
            &ctx,
        )
        .map_err(map_error)?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": policy.id,
            "database": policy.database.as_str(),
            "environment": policy.environment.as_str(),
            "webhooks": policy.webhooks,
            "events": policy.events,
        })),
    ))
}

pub(super) async fn list_notification_policies(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let uc = make_uc(&state);
    let policies = uc.list_notification_policies(&user).map_err(map_error)?;
    let items: Vec<serde_json::Value> = policies
        .iter()
        .map(|p| {
            serde_json::json!({
                "id": p.id,
                "database": p.database.as_str(),
                "environment": p.environment.as_str(),
                "webhooks": p.webhooks,
                "events": p.events,
            })
        })
        .collect();
    Ok((StatusCode::OK, Json(serde_json::json!(items))))
}

pub(super) async fn get_notification_policy(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let uc = make_uc(&state);
    let policy = uc.get_notification_policy(&id, &user).map_err(map_error)?;
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "id": policy.id,
            "database": policy.database.as_str(),
            "environment": policy.environment.as_str(),
            "webhooks": policy.webhooks,
            "events": policy.events,
        })),
    ))
}

pub(super) async fn update_notification_policy(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    client_ip: Option<Extension<ClientIp>>,
    connect_info: Option<Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    Path(id): Path<String>,
    Json(body): Json<dbward_api_types::policies::UpdateNotificationPolicyRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let ctx = super::extract_audit_context(
        client_ip.as_ref().map(|e| &e.0),
        connect_info.as_ref().map(|e| &e.0),
    );
    let uc = make_uc(&state);
    let policy = uc
        .update_notification_policy(
            &id,
            UpdateNotificationPolicyInput {
                webhooks: body.webhooks,
                events: body.events,
            },
            &user,
            &ctx,
        )
        .map_err(map_error)?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "id": policy.id,
            "database": policy.database.as_str(),
            "environment": policy.environment.as_str(),
            "webhooks": policy.webhooks,
            "events": policy.events,
        })),
    ))
}

pub(super) async fn delete_notification_policy(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    client_ip: Option<Extension<ClientIp>>,
    connect_info: Option<Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let ctx = super::extract_audit_context(
        client_ip.as_ref().map(|e| &e.0),
        connect_info.as_ref().map(|e| &e.0),
    );
    let uc = make_uc(&state);
    uc.delete_notification_policy(&id, &user, &ctx)
        .map_err(map_error)?;
    Ok((StatusCode::NO_CONTENT, Json(serde_json::json!(null))))
}
