mod approval;
mod background;
mod reader;
mod writer;

use chrono::{DateTime, Utc};

use dbward_app::error::AppError;
use dbward_domain::entities::{ApprovalAction, Request, RequestStatus};
use dbward_domain::values::{DatabaseName, Environment, Operation};

use crate::sqlite::DbConn;
use crate::sqlite::error::db_err;

pub struct SqliteRequestRepo {
    conn: DbConn,
}

impl SqliteRequestRepo {
    pub fn new(conn: DbConn) -> Self {
        Self { conn }
    }
}

fn build_selectors(user_id: &str, groups: &[String], roles: &[String]) -> Vec<String> {
    let mut selectors = vec![format!("user:{user_id}")];
    for g in groups {
        selectors.push(format!("group:{g}"));
    }
    for r in roles {
        selectors.push(format!("role:{r}"));
    }
    selectors
}

pub(crate) fn database_id(db: &DatabaseName, env: &Environment) -> String {
    format!("{}:{}", db.as_str(), env.as_str())
}

fn populate_pending_approvers(
    conn: &rusqlite::Connection,
    request_id: &str,
    workflow_snapshot_json: &Option<String>,
    step_index: u32,
) -> Result<(), AppError> {
    conn.execute(
        "DELETE FROM request_pending_approvers WHERE request_id = ?1",
        rusqlite::params![request_id],
    )
    .map_err(db_err("request: populate_pending_approvers"))?;
    if let Some(json) = workflow_snapshot_json
        && let Ok(workflow) =
            serde_json::from_str::<dbward_domain::policies::workflow::Workflow>(json)
        && let Some(step) = workflow.steps.get(step_index as usize)
    {
        for approver in &step.approvers {
            let selector = approver.selector.to_string();
            conn.execute(
                "INSERT OR IGNORE INTO request_pending_approvers (request_id, selector, step_index) VALUES (?1, ?2, ?3)",
                rusqlite::params![request_id, selector, step_index],
            )
            .map_err(db_err("request: populate_pending_approvers"))?;
        }
    }
    Ok(())
}

fn parse_database_id(id: &str) -> Result<(DatabaseName, Environment), AppError> {
    let (name, env) = id
        .split_once(':')
        .ok_or_else(|| AppError::Internal(format!("invalid database_id: {id}")))?;
    let db = DatabaseName::new(name)
        .map_err(|e| AppError::Internal(format!("invalid database name: {e}")))?;
    let env = Environment::new(env)
        .map_err(|e| AppError::Internal(format!("invalid environment: {e}")))?;
    Ok((db, env))
}

pub(crate) fn parse_status(s: &str) -> Result<RequestStatus, AppError> {
    match s {
        "pending" => Ok(RequestStatus::Pending),
        "approved" => Ok(RequestStatus::Approved),
        "auto_approved" => Ok(RequestStatus::AutoApproved),
        "break_glass" => Ok(RequestStatus::BreakGlass),
        "dispatched" => Ok(RequestStatus::Dispatched),
        "running" => Ok(RequestStatus::Running),
        "executed" => Ok(RequestStatus::Executed),
        "failed" => Ok(RequestStatus::Failed),
        "rejected" => Ok(RequestStatus::Rejected),
        "cancelled" => Ok(RequestStatus::Cancelled),
        "expired" => Ok(RequestStatus::Expired),
        "execution_lost" => Ok(RequestStatus::ExecutionLost),
        _ => Err(AppError::Internal(format!("unknown status: {s}"))),
    }
}

pub(crate) fn parse_approval_action(s: &str) -> Result<ApprovalAction, AppError> {
    match s {
        "approve" => Ok(ApprovalAction::Approve),
        "reject" => Ok(ApprovalAction::Reject),
        _ => Err(AppError::Internal(format!("unknown approval action: {s}"))),
    }
}

pub(crate) fn approval_action_str(a: &ApprovalAction) -> &'static str {
    match a {
        ApprovalAction::Approve => "approve",
        ApprovalAction::Reject => "reject",
    }
}

pub(crate) fn parse_ts(s: &str) -> Result<DateTime<Utc>, AppError> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| AppError::Internal(format!("invalid timestamp '{s}': {e}")))
}

fn parse_optional_ts(s: Option<String>) -> Result<Option<DateTime<Utc>>, AppError> {
    s.map(|v| parse_ts(&v)).transpose()
}

fn row_to_request(row: &rusqlite::Row<'_>) -> Result<Request, rusqlite::Error> {
    let db_id: String = row.get("database_id")?;
    let (database, environment) = parse_database_id(&db_id).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })?;

    let op_str: String = row.get("operation")?;
    let operation: Operation = op_str.parse().map_err(|e: String| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            Box::new(AppError::Internal(e.to_string())),
        )
    })?;

    let status_str: String = row.get("status")?;
    let status = parse_status(&status_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })?;

    let share_with_json: String = row.get("share_with_json")?;
    let share_with: Vec<String> = serde_json::from_str(&share_with_json).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })?;

    let created_at_str: String = row.get("created_at")?;
    let updated_at_str: String = row.get("updated_at")?;
    let resolved_at_str: Option<String> = row.get("resolved_at")?;
    let expires_at_str: Option<String> = row.get("expires_at")?;

    let created_at = parse_ts(&created_at_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let updated_at = parse_ts(&updated_at_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let resolved_at = parse_optional_ts(resolved_at_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let expires_at = parse_optional_ts(expires_at_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })?;

    Ok(Request {
        id: row.get("id")?,
        requester: row.get("requester")?,
        database,
        environment,
        operation,
        detail: row.get("detail")?,
        status,
        emergency: row.get::<_, i64>("emergency")? != 0,
        reason: row.get("reason")?,
        idempotency_key: row.get("idempotency_key")?,
        metadata_json: row.get("metadata_json")?,
        share_with,
        // SQLite column kept as "no_store" to avoid ALTER TABLE migration risk.
        no_result_store: row.get::<_, i64>("no_store")? != 0,
        workflow_snapshot_json: row.get("workflow_snapshot_json")?,
        decision_trace_json: row.get("decision_trace_json")?,
        execution_plan_json: row.get("execution_plan_json")?,
        cancel_reason: row.get("cancel_reason")?,
        cancelled_by: row.get("cancelled_by")?,
        created_at,
        updated_at,
        resolved_at,
        expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite::open_memory;
    use chrono::Utc;
    use dbward_app::ports::{ApprovalRepo, RequestReader, RequestWriter};
    use dbward_domain::entities::{Approval, ApprovalAction};
    use dbward_domain::values::Operation;

    fn make_request() -> Request {
        Request {
            id: "req-1".to_string(),
            requester: "user-1".to_string(),
            database: DatabaseName::new("app").unwrap(),
            environment: Environment::new("production").unwrap(),
            operation: Operation::ExecuteDml,
            detail: "UPDATE users SET active = true".to_string(),
            status: RequestStatus::Pending,
            emergency: false,
            reason: Some("deploy fix".to_string()),
            idempotency_key: Some("idem-1".to_string()),
            metadata_json: "{}".to_string(),
            share_with: vec!["user-2".to_string()],
            no_result_store: false,
            workflow_snapshot_json: None,
            decision_trace_json: None,
            execution_plan_json: None,
            cancel_reason: None,
            cancelled_by: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            resolved_at: None,
            expires_at: None,
        }
    }

    fn setup() -> SqliteRequestRepo {
        let conn = open_memory().unwrap();
        {
            let c = conn.lock();
            c.execute(
                "INSERT INTO databases (id, name, environment, created_at) VALUES ('app:production', 'app', 'production', '2024-01-01T00:00:00Z')",
                [],
            ).unwrap();
        }
        SqliteRequestRepo::new(conn)
    }

    #[test]
    fn insert_and_get() {
        let repo = setup();
        let req = make_request();
        repo.insert(&req).unwrap();

        let fetched = repo.get("req-1").unwrap().unwrap();
        assert_eq!(fetched.id, "req-1");
        assert_eq!(fetched.database.as_str(), "app");
        assert_eq!(fetched.environment.as_str(), "production");
        assert_eq!(fetched.operation, Operation::ExecuteDml);
        assert_eq!(fetched.share_with, vec!["user-2"]);
    }

    #[test]
    fn find_by_idempotency_key() {
        let repo = setup();
        let req = make_request();
        repo.insert(&req).unwrap();

        let found = repo.find_by_idempotency_key("idem-1").unwrap().unwrap();
        assert_eq!(found.id, "req-1");
        assert!(
            repo.find_by_idempotency_key("nonexistent")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn approvals() {
        let repo = setup();
        repo.insert(&make_request()).unwrap();

        let approval = Approval {
            id: "apr-1".to_string(),
            request_id: "req-1".to_string(),
            action: ApprovalAction::Approve,
            actor_id: "admin-1".to_string(),
            matched_selector: "role:admin".to_string(),
            step_index: 0,
            comment: Some("lgtm".to_string()),
            created_at: Utc::now(),
        };
        repo.insert_approval(&approval).unwrap();

        let approvals = repo.get_approvals("req-1").unwrap();
        assert_eq!(approvals.len(), 1);
        assert_eq!(approvals[0].actor_id, "admin-1");
    }

    #[test]
    fn mark_approved_and_dispatched() {
        let repo = setup();
        repo.insert(&make_request()).unwrap();

        let now = Utc::now();
        assert!(repo.mark_approved("req-1", now).unwrap());
        assert!(!repo.mark_approved("req-1", now).unwrap());

        assert!(repo.mark_dispatched("req-1", now).unwrap());
        assert!(repo.mark_running("req-1", now).unwrap());
        assert!(repo.mark_executed("req-1", now).unwrap());
    }

    #[test]
    fn mark_cancelled() {
        let repo = setup();
        repo.insert(&make_request()).unwrap();

        let now = Utc::now();
        assert!(
            repo.mark_cancelled("req-1", "admin", Some("oops"), now)
                .unwrap()
        );

        let req = repo.get("req-1").unwrap().unwrap();
        assert_eq!(req.status, RequestStatus::Cancelled);
        assert_eq!(req.cancelled_by.as_deref(), Some("admin"));
        assert_eq!(req.cancel_reason.as_deref(), Some("oops"));
    }

    #[test]
    fn cancel_all_for_user() {
        let repo = setup();
        let mut req = make_request();
        repo.insert(&req).unwrap();

        req.id = "req-2".to_string();
        req.idempotency_key = Some("idem-2".to_string());
        repo.insert(&req).unwrap();

        let count = repo
            .cancel_all_for_user(
                "user-1",
                "admin",
                "test",
                Utc::now(),
                &dbward_domain::entities::AuditContext::System,
            )
            .unwrap();
        assert_eq!(count.len(), 2);
    }

    #[test]
    fn list_filters_by_status() {
        let repo = setup();
        let mut req = make_request();
        req.id = "req-pending".into();
        req.status = RequestStatus::Pending;
        req.idempotency_key = Some("idem-1".into());
        repo.insert(&req).unwrap();

        let mut req2 = make_request();
        req2.id = "req-dispatched".into();
        req2.status = RequestStatus::Dispatched;
        req2.idempotency_key = Some("idem-2".into());
        repo.insert(&req2).unwrap();

        let (all, _) = repo.list(10, 0, None, None).unwrap();
        assert_eq!(all.len(), 2);

        let (pending, _) = repo.list(10, 0, Some("pending"), None).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, "req-pending");

        let (dispatched, _) = repo.list(10, 0, Some("dispatched"), None).unwrap();
        assert_eq!(dispatched.len(), 1);
        assert_eq!(dispatched[0].id, "req-dispatched");
    }
}
