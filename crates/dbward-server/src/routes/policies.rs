use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
};
use dbward_app::use_cases::policy_manage::{
    CreateNotificationPolicyInput, CreateResultPolicyInput, CreateWorkflowInput,
    UpdateNotificationPolicyInput, UpdateResultPolicyInput,
};
use dbward_domain::auth::{AuthUser, RoleDefinition};
use dbward_domain::policies::{DeliveryMode, ExecutionPolicy, WorkflowStep};
use dbward_domain::values::{DatabaseName, Environment, Operation, Selector};

use crate::middleware::trusted_proxies::ClientIp;
use crate::state::AppState;

use super::map_error;

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
    let uc = state.admin().policy_manage();
    let wf = uc.create_workflow(input, &user, &ctx).map_err(map_error)?;
    Ok((StatusCode::CREATED, Json(serde_json::json!(wf))))
}

pub async fn list_workflows(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let uc = state.admin().policy_manage();
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
    let uc = state.admin().policy_manage();
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
    let uc = state.admin().policy_manage();
    let ep = uc
        .create_execution_policy(body, &user, &ctx)
        .map_err(map_error)?;
    Ok((StatusCode::CREATED, Json(serde_json::json!(ep))))
}

pub async fn list_execution_policies(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let uc = state.admin().policy_manage();
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
    let uc = state.admin().policy_manage();
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
    let uc = state.admin().policy_manage();
    let role = uc.create_role(body, &user, &ctx).map_err(map_error)?;
    Ok((StatusCode::CREATED, Json(serde_json::json!(role))))
}

pub async fn list_roles(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let uc = state.admin().policy_manage();
    let roles = uc.list_roles(&user).map_err(map_error)?;
    Ok((StatusCode::OK, Json(serde_json::json!({ "roles": roles }))))
}

pub async fn delete_role(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(name): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let uc = state.admin().policy_manage();
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

    let uc = state.admin().policy_manage();
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
    let uc = state.admin().policy_manage();
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
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({"result_policies": items})),
    ))
}

pub(super) async fn get_result_policy(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let uc = state.admin().policy_manage();
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

    let uc = state.admin().policy_manage();
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
    let uc = state.admin().policy_manage();
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

    let uc = state.admin().policy_manage();
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
    let uc = state.admin().policy_manage();
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
    let uc = state.admin().policy_manage();
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
    let uc = state.admin().policy_manage();
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
    let uc = state.admin().policy_manage();
    uc.delete_notification_policy(&id, &user, &ctx)
        .map_err(map_error)?;
    Ok((StatusCode::NO_CONTENT, Json(serde_json::json!(null))))
}

// ---------------------------------------------------------------------------
// Policy Resolution
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct PolicyResolutionQuery {
    pub database: String,
    pub environment: String,
    pub operation: Option<String>,
}

pub async fn policy_resolution(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    axum::extract::Query(q): axum::extract::Query<PolicyResolutionQuery>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    use dbward_domain::auth::{Permission, ResourceContext};
    use dbward_domain::services::workflow_matcher;
    use serde_json::json;

    let db = DatabaseName::new(&q.database).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e, "code": "validation"})),
        )
    })?;
    let env = Environment::new(&q.environment).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e, "code": "validation"})),
        )
    })?;

    state
        .authorizer
        .authorize_scoped(
            &user,
            Permission::RequestView,
            &db,
            &env,
            &ResourceContext::Global,
        )
        .map_err(|e| {
            (
                StatusCode::FORBIDDEN,
                Json(json!({"error": e.to_string(), "code": "forbidden"})),
            )
        })?;

    let ops: Vec<Operation> = if let Some(ref op_str) = q.operation {
        vec![op_str.parse::<Operation>().map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": e, "code": "validation"})),
            )
        })?]
    } else {
        vec![
            Operation::ExecuteSelect,
            Operation::ExecuteDml,
            Operation::MigrateUp,
            Operation::MigrateDown,
            Operation::MigrateStatus,
        ]
    };

    let registered = state
        .database_registry()
        .exists(&db, &env)
        .map_err(map_error)?;
    if !registered {
        return Ok((
            StatusCode::OK,
            Json(json!({
                "database": q.database,
                "environment": q.environment,
                "registered": false,
                "decision_preview": "deny",
                "reason_code": "db_not_registered"
            })),
        ));
    }

    let auto_entry = workflow_matcher::find_auto_approve(&state.auto_approve_entries, &db, &env);
    let exec_policy = state.policy_evaluator().get_execution_policy(&db, &env);

    let exec_policy_json = {
        let matched_by = format!("({}, {})", exec_policy.database, exec_policy.environment);
        let explicit = !exec_policy.id.is_empty();
        json!({
            "statement_timeout_secs": exec_policy.statement_timeout_secs,
            "migration_statement_timeout_secs": exec_policy.migration_statement_timeout_secs,
            "max_rows": exec_policy.max_rows,
            "matched_by": matched_by,
            "explicit": explicit,
        })
    };

    let auto_approve_json = auto_entry.map(|e| {
        let matched_by = format!("({}, {})", e.database, e.environment);
        let max_risk = e.max_risk_level.map(|l| format!("{l:?}").to_lowercase());
        json!({
            "max_risk": max_risk,
            "allow_read_only": e.allow_read_only,
            "allow_safe_ddl": e.allow_safe_ddl,
            "matched_by": matched_by,
        })
    });

    if q.operation.is_some() {
        let op = ops[0];
        let wf = state
            .policy_evaluator()
            .evaluate_workflow(&db, &env, op)
            .map_err(map_error)?;
        let (decision, reason_code, _) = resolve_single(&wf, op, auto_entry);

        let resp = json!({
            "database": q.database,
            "environment": q.environment,
            "operation": op.as_str(),
            "registered": true,
            "workflow": wf.as_ref().map(build_workflow_json),
            "auto_approve": auto_approve_json,
            "execution_policy": exec_policy_json,
            "decision_preview": decision,
            "reason_code": reason_code,
        });
        return Ok((StatusCode::OK, Json(resp)));
    }

    let mut resolutions = Vec::new();
    for op in &ops {
        let wf = state
            .policy_evaluator()
            .evaluate_workflow(&db, &env, *op)
            .map_err(map_error)?;
        let (decision, reason_code, _) = resolve_single(&wf, *op, auto_entry);
        let wf_id = wf.as_ref().map(|w| w.id.as_str()).unwrap_or("");
        let matched_by = wf
            .as_ref()
            .map(|w| format!("({}, {})", w.database, w.environment))
            .unwrap_or_default();
        resolutions.push(json!({
            "operation": op.as_str(),
            "workflow_id": if wf_id.is_empty() { serde_json::Value::Null } else { json!(wf_id) },
            "matched_by": if matched_by.is_empty() { serde_json::Value::Null } else { json!(matched_by) },
            "decision_preview": decision,
            "reason_code": reason_code,
        }));
    }

    Ok((
        StatusCode::OK,
        Json(json!({
            "database": q.database,
            "environment": q.environment,
            "registered": true,
            "resolutions": resolutions,
        })),
    ))
}

fn resolve_single(
    wf: &Option<dbward_domain::policies::Workflow>,
    op: Operation,
    auto_entry: Option<&dbward_domain::services::workflow_matcher::AutoApproveEntry>,
) -> (&'static str, &'static str, serde_json::Value) {
    use serde_json::json;
    match wf {
        None => ("deny", "no_matching_workflow", json!(null)),
        Some(w) => {
            if w.steps.is_empty() {
                ("auto_approved", "empty_steps", build_workflow_json(w))
            } else if op == Operation::ExecuteSelect
                && auto_entry.is_some_and(|e| e.allow_read_only && e.max_risk_level.is_some())
            {
                (
                    "auto_approved",
                    "read_only_low_risk",
                    build_workflow_json(w),
                )
            } else {
                (
                    "needs_approval",
                    "risk_unknown_until_analyzed",
                    build_workflow_json(w),
                )
            }
        }
    }
}

fn build_workflow_json(wf: &dbward_domain::policies::Workflow) -> serde_json::Value {
    use serde_json::json;
    let steps: Vec<serde_json::Value> = wf
        .steps
        .iter()
        .map(|s| {
            let approvers: Vec<String> =
                s.approvers.iter().map(|a| a.selector.to_string()).collect();
            json!({
                "approvers": approvers,
                "mode": format!("{:?}", s.mode).to_lowercase(),
                "min": s.approvers.first().map(|a| a.min).unwrap_or(1),
            })
        })
        .collect();
    json!({
        "id": wf.id,
        "matched_by": format!("({}, {})", wf.database, wf.environment),
        "steps": steps,
        "require_reason": wf.require_reason,
        "explain": wf.explain,
    })
}
