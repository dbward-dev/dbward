mod common;
use common::*;

use chrono::Utc;
use dbward_app::ports::*;
use dbward_domain::entities::*;
use dbward_domain::values::*;
use dbward_infra::sqlite::*;

#[test]
fn list_stale_config_ids_excludes_non_config_users() {
    let conn = setup();
    let user_repo = SqliteUserRepo::new(conn.clone());
    let now = Utc::now();

    let config_user = User {
        id: "config-alice".into(),
        display_name: None,
        email: None,
        groups: vec![],
        roles: vec![],
        status: UserStatus::Active,
        last_seen_at: None,
        created_at: now,
        updated_at: now,
    };
    let token_user = User {
        id: "token-bob".into(),
        display_name: None,
        email: None,
        groups: vec![],
        roles: vec![],
        status: UserStatus::Active,
        last_seen_at: None,
        created_at: now,
        updated_at: now,
    };

    user_repo.upsert(&config_user).unwrap();
    user_repo.set_source("config-alice", "config").unwrap();
    user_repo.upsert(&token_user).unwrap();

    // Only config-managed users appear as stale
    let stale = user_repo.list_stale_config_ids(&[]).unwrap();
    assert_eq!(stale, vec!["config-alice".to_string()]);

    // If active set includes config-alice, stale is empty
    let stale = user_repo
        .list_stale_config_ids(&["config-alice".into()])
        .unwrap();
    assert!(stale.is_empty());
}

#[test]
fn cancel_all_for_user_raw_inserts_audit_events() {
    let conn = setup();
    let request_repo = SqliteRequestRepo::new(conn.clone());
    let now = Utc::now();

    register_db(&conn);
    let req = Request {
        id: "req-1".into(),
        requester: "alice".into(),
        database: DatabaseName::new("app").unwrap(),
        environment: Environment::new("production").unwrap(),
        operation: Operation::ExecuteSelect,
        detail: "SELECT 1".into(),
        status: RequestStatus::Pending,
        emergency: false,
        reason: None,
        idempotency_key: None,
        metadata_json: "{}".into(),
        share_with: vec![],
        no_store: false,
        workflow_snapshot_json: None,
        decision_trace_json: None,
        execution_plan_json: None,
        cancel_reason: None,
        cancelled_by: None,
        created_at: now,
        updated_at: now,
        resolved_at: None,
        expires_at: None,
    };
    request_repo.insert(&req).unwrap();

    let cancelled = request_repo
        .cancel_all_for_user_raw("alice", "system", "user suspended via config", now)
        .unwrap();
    assert_eq!(cancelled, vec!["req-1".to_string()]);

    // Verify request is cancelled
    let conn_guard = conn.lock();
    let status: String = conn_guard
        .query_row("SELECT status FROM requests WHERE id = 'req-1'", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(status, "cancelled");

    // Verify audit event with actor_type=System
    let (actor_type, actor_id): (String, String) = conn_guard
        .query_row(
            "SELECT actor_type, actor_id FROM audit_events WHERE event_type = 'request_cancelled' AND resource_id = 'req-1'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(actor_type, "system");
    assert_eq!(actor_id, "system");
}
