mod common;
use common::*;

use chrono::Utc;
use dbward_app::ports::*;
use dbward_domain::auth::*;
use dbward_domain::entities::*;
use dbward_domain::values::*;
use dbward_infra::auth::{ConfigRoleResolver, RbacAuthorizer};
use dbward_infra::sqlite::*;
use std::collections::HashMap;

#[test]
fn rbac_with_config_role_resolver() {
    let defs = vec![
        RoleDefinition {
            name: "admin".into(),
            permissions: vec![Permission::All],
            databases: vec![DatabaseName::new("*").unwrap()],
            environments: vec![Environment::new("*").unwrap()],
        },
        RoleDefinition {
            name: "developer".into(),
            permissions: vec![Permission::RequestExecute, Permission::RequestView],
            databases: vec![DatabaseName::new("app").unwrap()],
            environments: vec![Environment::new("development").unwrap()],
        },
    ];
    let role_bindings = HashMap::from([("engineering".to_string(), vec!["developer".to_string()])]);
    let user_bindings = HashMap::from([("alice".to_string(), vec!["admin".to_string()])]);
    let resolver = ConfigRoleResolver::new(defs, role_bindings, user_bindings, None);

    // Alice is admin via user binding
    let alice_roles = resolver.resolve("alice", SubjectType::User, &[]).unwrap();
    let alice = AuthUser {
        subject_id: "alice".into(),
        subject_type: SubjectType::User,
        roles: alice_roles,
        groups: vec![],
        token_id: None,
    };
    let db = DatabaseName::new("app").unwrap();
    let env = Environment::new("production").unwrap();
    assert!(
        RbacAuthorizer
            .authorize_scoped(
                &alice,
                Permission::RequestExecute,
                &db,
                &env,
                &ResourceContext::Global
            )
            .is_ok()
    );

    // Bob is developer via group binding — scoped to app:development only
    let bob_roles = resolver
        .resolve("bob", SubjectType::User, &["engineering".into()])
        .unwrap();
    let bob = AuthUser {
        subject_id: "bob".into(),
        subject_type: SubjectType::User,
        roles: bob_roles,
        groups: vec!["engineering".into()],
        token_id: None,
    };
    let dev = Environment::new("development").unwrap();
    assert!(
        RbacAuthorizer
            .authorize_scoped(
                &bob,
                Permission::RequestExecute,
                &db,
                &dev,
                &ResourceContext::Global
            )
            .is_ok()
    );
    // Bob denied on production
    assert!(
        RbacAuthorizer
            .authorize_scoped(
                &bob,
                Permission::RequestExecute,
                &db,
                &env,
                &ResourceContext::Global
            )
            .is_err()
    );
}

#[test]
fn webhook_crud_lifecycle() {
    let conn = setup();
    let repo = SqliteWebhookRepo::new(conn);

    let wh = Webhook {
        id: "wh-1".into(),
        url: "https://example.com/hook".into(),
        events: vec!["request.approved".into()],
        format: WebhookFormat::Slack,
        secret: Some("s3cr3t".into()),
        status: WebhookStatus::Active,
        created_at: None,
        updated_at: None,
    };
    repo.create(&wh).unwrap();

    let fetched = repo.get("wh-1").unwrap().unwrap();
    assert_eq!(fetched.url, "https://example.com/hook");
    assert_eq!(fetched.format, WebhookFormat::Slack);

    // Update
    let mut updated = fetched;
    updated.url = "https://example.com/v2".into();
    updated.status = WebhookStatus::Inactive;
    repo.update(&updated).unwrap();

    let fetched2 = repo.get("wh-1").unwrap().unwrap();
    assert_eq!(fetched2.url, "https://example.com/v2");
    assert_eq!(fetched2.status, WebhookStatus::Inactive);

    // Delete
    repo.delete("wh-1").unwrap();
    assert!(repo.get("wh-1").unwrap().is_none());
}

#[test]
fn user_suspend_and_request_cancel() {
    let conn = setup();
    register_db(&conn);

    let user_repo = SqliteUserRepo::new(conn.clone());
    let request_repo = SqliteRequestRepo::new(conn.clone());

    // Create user
    let user = User {
        id: "alice".into(),
        display_name: Some("Alice".into()),
        email: Some("alice@example.com".into()),
        groups: vec!["engineering".into()],
        roles: vec![],
        status: UserStatus::Active,
        last_seen_at: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    user_repo.upsert(&user).unwrap();

    // Create pending request
    let req = Request {
        id: "req-suspend".into(),
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
        created_at: Utc::now(),
        updated_at: Utc::now(),
        resolved_at: None,
        expires_at: None,
    };
    request_repo.insert(&req).unwrap();

    // Suspend user + cancel their requests (simulating use case)
    let now = Utc::now();
    assert!(user_repo.suspend("alice", now).unwrap());
    assert!(user_repo.is_suspended("alice").unwrap());
    let cancelled = request_repo
        .cancel_all_for_user(
            "alice",
            "admin",
            "user suspended",
            now,
            &dbward_domain::entities::AuditContext::System,
        )
        .unwrap();
    assert_eq!(cancelled.len(), 1);

    let fetched = request_repo.get("req-suspend").unwrap().unwrap();
    assert_eq!(fetched.status, RequestStatus::Cancelled);
}

#[test]
fn token_create_verify_revoke() {
    let conn = setup();
    let repo = SqliteTokenRepo::new(conn);

    let token = Token {
        id: "tok-1".into(),
        subject_type: SubjectType::User,
        subject_id: "alice".into(),
        token_hash: "abc123hash".into(),
        token_prefix: "dbw_".into(),
        roles: vec!["admin".into()],
        groups: vec![],
        name: Some("my-token".into()),
        status: TokenStatus::Active,
        expires_at: None,
        created_at: Utc::now(),
        revoked_at: None,
    };
    repo.create(&token).unwrap();

    // Verify
    let found = repo.verify("dbw_", "abc123hash").unwrap().unwrap();
    assert_eq!(found.subject_id, "alice");

    // Revoke
    assert!(repo.revoke("tok-1", Utc::now()).unwrap());

    // Verify fails after revoke
    assert!(repo.verify("dbw_", "abc123hash").unwrap().is_none());
}

#[test]
fn database_registry_exists_and_list() {
    let conn = setup();
    register_db(&conn);

    let registry = SqliteDatabaseRegistry::new(conn);
    let db = DatabaseName::new("app").unwrap();
    let env = Environment::new("production").unwrap();

    assert!(registry.exists_active(&db, &env).unwrap());
    assert!(
        !registry
            .exists_active(&DatabaseName::new("other").unwrap(), &env)
            .unwrap()
    );

    let list = registry.list_active().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].0.as_str(), "app");
    assert_eq!(list[0].1.as_str(), "production");
}

#[test]
fn user_get_list_activate() {
    let conn = setup();
    let repo = SqliteUserRepo::new(conn.clone());

    let user = User {
        id: "alice".into(),
        display_name: Some("Alice".into()),
        email: Some("alice@example.com".into()),
        groups: vec!["backend".into()],
        roles: vec!["developer".into()],
        status: UserStatus::Active,
        last_seen_at: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    repo.upsert(&user).unwrap();
    assert_eq!(
        repo.get("alice").unwrap().unwrap().display_name,
        Some("Alice".into())
    );
    assert_eq!(repo.list().unwrap().len(), 1);
    repo.suspend("alice", Utc::now()).unwrap();
    assert!(repo.is_suspended("alice").unwrap());
    repo.activate("alice", Utc::now()).unwrap();
    assert!(!repo.is_suspended("alice").unwrap());
}

#[test]
fn user_ensure_exists() {
    let conn = setup();
    let repo = SqliteUserRepo::new(conn.clone());
    repo.ensure_exists("bob").unwrap();
    assert!(repo.get("bob").unwrap().is_some());
}

#[test]
fn token_list_revoke_all_purge() {
    let conn = setup();
    let repo = SqliteTokenRepo::new(conn);

    let t1 = Token {
        id: "tok-a".into(),
        subject_type: SubjectType::User,
        subject_id: "alice".into(),
        token_hash: "h1".into(),
        token_prefix: "dbw_a".into(),
        roles: vec!["dev".into()],
        groups: vec![],
        name: None,
        status: TokenStatus::Active,
        expires_at: None,
        created_at: Utc::now(),
        revoked_at: None,
    };
    let t2 = Token {
        id: "tok-b".into(),
        token_hash: "h2".into(),
        token_prefix: "dbw_b".into(),
        ..t1.clone()
    };
    repo.create(&t1).unwrap();
    repo.create(&t2).unwrap();

    assert_eq!(repo.count_active().unwrap(), 2);
    assert_eq!(repo.list().unwrap().len(), 2);
    assert_eq!(repo.get("tok-a").unwrap().unwrap().subject_id, "alice");

    let revoked = repo.revoke_all_for_user("alice", Utc::now()).unwrap();
    assert_eq!(revoked, 2);
    assert_eq!(repo.count_active().unwrap(), 0);

    let purged = repo.purge_revoked("2099-01-01T00:00:00Z").unwrap();
    assert_eq!(purged, 2);
}

#[test]
fn unknown_user_status_is_treated_as_suspended() {
    let conn = setup();
    let repo = SqliteUserRepo::new(conn.clone());

    // Insert user with unknown status via raw SQL
    conn.lock().execute(
        "INSERT INTO users (id, groups_json, status, created_at, updated_at) VALUES ('corrupted', '[]', 'garbage', '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z')",
        [],
    ).unwrap();

    // is_suspended must return true for unknown status (fail-closed)
    assert!(repo.is_suspended("corrupted").unwrap());

    // get() must return Suspended for unknown status
    let user = repo.get("corrupted").unwrap().unwrap();
    assert_eq!(user.status, UserStatus::Suspended);
}

#[test]
fn user_status_is_case_sensitive() {
    let conn = setup();
    let repo = SqliteUserRepo::new(conn.clone());

    // "ACTIVE" (uppercase) is NOT "active" — should be treated as suspended
    conn.lock().execute(
        "INSERT INTO users (id, groups_json, status, created_at, updated_at) VALUES ('upper', '[]', 'ACTIVE', '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z')",
        [],
    ).unwrap();

    assert!(repo.is_suspended("upper").unwrap());
    let user = repo.get("upper").unwrap().unwrap();
    assert_eq!(user.status, UserStatus::Suspended);
}

#[test]
fn activate_from_unknown_status() {
    let conn = setup();
    let repo = SqliteUserRepo::new(conn.clone());

    // Insert user with corrupted status
    conn.lock().execute(
        "INSERT INTO users (id, groups_json, status, created_at, updated_at) VALUES ('broken', '[]', 'garbage', '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z')",
        [],
    ).unwrap();

    // activate() should succeed from unknown status
    assert!(repo.activate("broken", Utc::now()).unwrap());
    assert!(!repo.is_suspended("broken").unwrap());
}

#[test]
fn suspend_from_unknown_status() {
    let conn = setup();
    let repo = SqliteUserRepo::new(conn.clone());

    // Insert user with corrupted status
    conn.lock().execute(
        "INSERT INTO users (id, groups_json, status, created_at, updated_at) VALUES ('broken2', '[]', 'garbage', '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z')",
        [],
    ).unwrap();

    // suspend() should succeed from unknown status
    assert!(repo.suspend("broken2", Utc::now()).unwrap());
    // After explicit suspend, status is now "suspended"
    let user = repo.get("broken2").unwrap().unwrap();
    assert_eq!(user.status, UserStatus::Suspended);
}
