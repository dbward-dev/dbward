use chrono::Utc;
use dbward_app::ports::*;
use dbward_domain::auth::*;
use dbward_domain::entities::*;
use dbward_domain::policies::*;
use dbward_domain::values::*;
use dbward_infra::auth::{ConfigRoleResolver, RbacAuthorizer};
use dbward_infra::sqlite::{self, *};
use std::collections::HashMap;

fn setup() -> DbConn {
    sqlite::open_memory().unwrap()
}

fn register_db(conn: &DbConn) {
    conn.lock()
        .unwrap()
        .execute(
            "INSERT INTO databases (id, name, environment, created_at) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                "app:production",
                "app",
                "production",
                Utc::now().to_rfc3339()
            ],
        )
        .unwrap();
}

// --- 1. Request lifecycle requires registered database (cross-repo) ---

#[test]
fn request_lifecycle_with_registered_database() {
    let conn = setup();
    register_db(&conn);

    let repo = SqliteRequestRepo::new(conn.clone());
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
        cancel_reason: None,
        cancelled_by: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        resolved_at: None,
        expires_at: None,
    };

    repo.insert(&req).unwrap();
    let now = Utc::now();
    assert!(repo.mark_approved("req-1", now).unwrap());
    assert!(repo.mark_dispatched("req-1", now).unwrap());
    assert!(repo.mark_running("req-1", now).unwrap());
    assert!(repo.mark_executed("req-1", now).unwrap());

    let final_req = repo.get("req-1").unwrap().unwrap();
    assert_eq!(final_req.status, RequestStatus::Executed);
    assert!(final_req.resolved_at.is_some());
}

// --- 2. Request insert fails without registered database (FK constraint) ---

#[test]
fn request_insert_fails_without_database() {
    let conn = setup();
    let repo = SqliteRequestRepo::new(conn);
    let req = Request {
        id: "req-bad".into(),
        requester: "alice".into(),
        database: DatabaseName::new("unknown").unwrap(),
        environment: Environment::new("production").unwrap(),
        operation: Operation::ExecuteDml,
        detail: "DELETE FROM x".into(),
        status: RequestStatus::Pending,
        emergency: false,
        reason: None,
        idempotency_key: None,
        metadata_json: "{}".into(),
        share_with: vec![],
        no_store: false,
        workflow_snapshot_json: None,
        cancel_reason: None,
        cancelled_by: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        resolved_at: None,
        expires_at: None,
    };
    assert!(repo.insert(&req).is_err());
}

// --- 3. Audit hash chain integrity across multiple records ---

#[test]
fn audit_hash_chain_integrity() {
    let conn = setup();
    let logger = SqliteAuditLogger::new(conn.clone());
    let audit_repo = SqliteAuditRepo::new(conn.clone());

    // Insert 3 chained events
    let mut prev_hash: Option<String> = None;
    for i in 0..3 {
        let hash = format!("hash-{i}");
        let event = AuditEvent {
            id: format!("evt-{i}"),
            event_type: "request.created".into(),
            event_category: EventCategory::Execution,
            event_version: 1,
            outcome: EventOutcome::Success,
            actor_id: "alice".into(),
            actor_type: ActorType::User,
            resource_type: None,
            resource_id: None,
            peer_ip: None,
            client_ip: None,
            client_ip_source: None,
            request_id: None,
            operation: None,
            database_name: None,
            environment: None,
            detail_fingerprint: None,
            detail_raw: None,
            reason: None,
            metadata_json: "{}".into(),
            prev_hash: prev_hash.clone(),
            event_hash: hash.clone(),
            created_at: Utc::now(),
        };
        logger.record(&event).unwrap();
        prev_hash = Some(hash);
    }

    let result = audit_repo.verify_chain().unwrap();
    assert_eq!(result.total_events, 3);
    assert!(result.first_broken_id.is_none());
}

// --- 4. Audit chain detects tampering ---

#[test]
fn audit_chain_detects_broken_link() {
    let conn = setup();
    let logger = SqliteAuditLogger::new(conn.clone());
    let repo = SqliteAuditRepo::new(conn.clone());

    // Insert two valid events (infra computes hashes)
    let e1 = AuditEvent {
        id: String::new(),
        event_type: "test".into(),
        event_category: EventCategory::Auth,
        event_version: 1,
        outcome: EventOutcome::Success,
        actor_id: "sys".into(),
        actor_type: ActorType::System,
        resource_type: None,
        resource_id: None,
        peer_ip: None,
        client_ip: None,
        client_ip_source: None,
        request_id: None,
        operation: None,
        database_name: None,
        environment: None,
        detail_fingerprint: None,
        detail_raw: None,
        reason: None,
        metadata_json: "{}".into(),
        prev_hash: None,
        event_hash: String::new(),
        created_at: Utc::now(),
    };
    logger.record(&e1).unwrap();
    logger.record(&e1).unwrap();

    // Chain should be valid
    let result = repo.verify_chain().unwrap();
    assert!(result.first_broken_id.is_none());

    // Tamper with the DB directly (simulate attacker modifying actor_id)
    {
        let c = conn.lock().unwrap();
        c.execute(
            "UPDATE audit_events SET actor_id = 'hacked' WHERE rowid = 1",
            [],
        )
        .unwrap();
    }

    // verify_chain should now detect the tampering
    let result = repo.verify_chain().unwrap();
    assert!(result.first_broken_id.is_some());
}

// --- 5. PolicyEvaluator 4-level workflow lookup ---

#[test]
fn policy_evaluator_4_level_workflow_priority() {
    let conn = setup();
    let policy_repo = SqlitePolicyRepo::new(conn.clone());
    let evaluator = SqlitePolicyEvaluator::new(conn.clone());

    let step = WorkflowStep {
        approvers: vec![ApproverGroup {
            selector: Selector::Role("admin".into()),
            min: 1,
        }],
        mode: WorkflowStepMode::Any,
    };

    // Level 4 (lowest): (*, *)
    policy_repo
        .create_workflow(&Workflow {
            id: "w-global".into(),
            database: DatabaseName::new("*").unwrap(),
            environment: Environment::new("*").unwrap(),
            operations: vec![],
            steps: vec![],
            skip_approval_for: vec![],
            require_reason: false,
            allow_self_approve: false,
            allow_same_approver_across_steps: false,
            pending_ttl_secs: None,
            statement_timeout_secs: None,
            approval_ttl_secs: None,
            created_at: None,
            updated_at: None,
        })
        .unwrap();

    // Level 3: (app, *)
    policy_repo
        .create_workflow(&Workflow {
            id: "w-db".into(),
            database: DatabaseName::new("app").unwrap(),
            environment: Environment::new("*").unwrap(),
            operations: vec![],
            steps: vec![step.clone()],
            skip_approval_for: vec![],
            require_reason: false,
            allow_self_approve: false,
            allow_same_approver_across_steps: false,
            pending_ttl_secs: None,
            statement_timeout_secs: None,
            approval_ttl_secs: None,
            created_at: None,
            updated_at: None,
        })
        .unwrap();

    // Level 2: (*, production)
    policy_repo
        .create_workflow(&Workflow {
            id: "w-env".into(),
            database: DatabaseName::new("*").unwrap(),
            environment: Environment::new("production").unwrap(),
            operations: vec![],
            steps: vec![step.clone(), step.clone()],
            skip_approval_for: vec![],
            require_reason: true,
            allow_self_approve: false,
            allow_same_approver_across_steps: false,
            pending_ttl_secs: None,
            statement_timeout_secs: None,
            approval_ttl_secs: None,
            created_at: None,
            updated_at: None,
        })
        .unwrap();

    // Level 1 (highest): (app, production)
    policy_repo
        .create_workflow(&Workflow {
            id: "w-exact".into(),
            database: DatabaseName::new("app").unwrap(),
            environment: Environment::new("production").unwrap(),
            operations: vec![Operation::ExecuteDml],
            steps: vec![step.clone(), step.clone(), step.clone()],
            skip_approval_for: vec![],
            require_reason: true,
            allow_self_approve: false,
            allow_same_approver_across_steps: false,
            pending_ttl_secs: None,
            statement_timeout_secs: None,
            approval_ttl_secs: None,
            created_at: None,
            updated_at: None,
        })
        .unwrap();

    let db = DatabaseName::new("app").unwrap();
    let env = Environment::new("production").unwrap();

    // DML on app:production → exact match (w-exact, 3 steps)
    let matched = evaluator
        .evaluate_workflow(&db, &env, Operation::ExecuteDml)
        .unwrap()
        .unwrap();
    assert_eq!(matched.id, "w-exact");

    // SELECT on app:production → (*, production) wins over (app, *) per env > db priority
    let matched = evaluator
        .evaluate_workflow(&db, &env, Operation::ExecuteSelect)
        .unwrap()
        .unwrap();
    assert_eq!(matched.id, "w-env");

    // DML on app:staging → (app, *) matches
    let staging = Environment::new("staging").unwrap();
    let matched = evaluator
        .evaluate_workflow(&db, &staging, Operation::ExecuteDml)
        .unwrap()
        .unwrap();
    assert_eq!(matched.id, "w-db");

    // SELECT on other:staging → (*, *) matches
    let other = DatabaseName::new("other").unwrap();
    let matched = evaluator
        .evaluate_workflow(&other, &staging, Operation::ExecuteSelect)
        .unwrap()
        .unwrap();
    assert_eq!(matched.id, "w-global");
}

// --- 6. PolicyEvaluator execution policy 4-level lookup ---

#[test]
fn execution_policy_specificity() {
    let conn = setup();
    let policy_repo = SqlitePolicyRepo::new(conn.clone());
    let evaluator = SqlitePolicyEvaluator::new(conn.clone());

    // Global default
    policy_repo
        .create_execution_policy(&ExecutionPolicy {
            id: "ep-global".into(),
            database: DatabaseName::new("*").unwrap(),
            environment: Environment::new("*").unwrap(),
            statement_timeout_secs: 10,
            ..ExecutionPolicy::default()
        })
        .unwrap();

    // Exact match
    policy_repo
        .create_execution_policy(&ExecutionPolicy {
            id: "ep-exact".into(),
            database: DatabaseName::new("app").unwrap(),
            environment: Environment::new("production").unwrap(),
            statement_timeout_secs: 60,
            ..ExecutionPolicy::default()
        })
        .unwrap();

    let db = DatabaseName::new("app").unwrap();
    let prod = Environment::new("production").unwrap();
    let staging = Environment::new("staging").unwrap();

    let ep = evaluator.get_execution_policy(&db, &prod);
    assert_eq!(ep.statement_timeout_secs, 60);

    let ep = evaluator.get_execution_policy(&db, &staging);
    assert_eq!(ep.statement_timeout_secs, 10);
}

// --- 7. RbacAuthorizer with real ResolvedRoles from ConfigRoleResolver ---

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
            permissions: vec![Permission::RequestCreate, Permission::RequestView],
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
                Permission::RequestCreate,
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
                Permission::RequestCreate,
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
                Permission::RequestCreate,
                &db,
                &env,
                &ResourceContext::Global
            )
            .is_err()
    );
}

// --- 8. Execution tracking with agent repo ---

#[test]
fn execution_tracking_cross_repo() {
    let conn = setup();
    register_db(&conn);

    let agent_repo = SqliteAgentRepo::new(conn.clone());
    let request_repo = SqliteRequestRepo::new(conn.clone());

    // Insert request first
    let req = Request {
        id: "req-exec".into(),
        requester: "alice".into(),
        database: DatabaseName::new("app").unwrap(),
        environment: Environment::new("production").unwrap(),
        operation: Operation::ExecuteDml,
        detail: "UPDATE t SET x=1".into(),
        status: RequestStatus::Dispatched,
        emergency: false,
        reason: None,
        idempotency_key: None,
        metadata_json: "{}".into(),
        share_with: vec![],
        no_store: false,
        workflow_snapshot_json: None,
        cancel_reason: None,
        cancelled_by: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        resolved_at: None,
        expires_at: None,
    };
    request_repo.insert(&req).unwrap();

    // Register agent
    let agent = Agent {
        lease_duration_secs: None,
        id: "agent-1".into(),
        token_id: "tok-1".into(),
        databases: vec![DatabaseCapability {
            database: DatabaseName::new("app").unwrap(),
            environment: Environment::new("production").unwrap(),
        }],
        status: AgentStatus::Active,
        max_concurrent: 2,
        in_flight: 0,
        last_seen: Some(Utc::now()),
        created_at: Utc::now(),
    };
    agent_repo.upsert(&agent).unwrap();

    // Create execution (FK to requests)
    let execution = Execution {
        id: "exec-1".into(),
        request_id: "req-exec".into(),
        agent_id: "agent-1".into(),
        status: ExecutionStatus::Claimed,
        token: "signed-token".into(),
        lease_expires_at: Utc::now() + chrono::Duration::minutes(5),
        started_at: None,
        finished_at: None,
        error_message: None,
        created_at: Utc::now(),
    };
    agent_repo.create_execution(&execution).unwrap();

    // Verify execution count from request repo
    assert_eq!(request_repo.count_executions("req-exec").unwrap(), 1);

    // Update execution status
    agent_repo
        .update_execution_status("exec-1", ExecutionStatus::Running)
        .unwrap();
    let fetched = agent_repo.get_execution("exec-1").unwrap().unwrap();
    assert_eq!(fetched.status, ExecutionStatus::Running);
}

// --- 9. Webhook CRUD lifecycle ---

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

// --- 10. User suspend cancels pending requests (cross-repo) ---

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
    let cancelled = request_repo.cancel_all_for_user("alice", now).unwrap();
    assert_eq!(cancelled, 1);

    let fetched = request_repo.get("req-suspend").unwrap().unwrap();
    assert_eq!(fetched.status, RequestStatus::Cancelled);
}

// --- 11. Token create and verify ---

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

// --- 12. Database registry list ---

#[test]
fn database_registry_exists_and_list() {
    let conn = setup();
    register_db(&conn);

    let registry = SqliteDatabaseRegistry::new(conn);
    let db = DatabaseName::new("app").unwrap();
    let env = Environment::new("production").unwrap();

    assert!(registry.exists(&db, &env).unwrap());
    assert!(
        !registry
            .exists(&DatabaseName::new("other").unwrap(), &env)
            .unwrap()
    );

    let list = registry.list().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].0.as_str(), "app");
    assert_eq!(list[0].1.as_str(), "production");
}

// --- 13. complete_execution: success case ---

#[test]
fn complete_execution_success() {
    let conn = setup();
    register_db(&conn);

    let agent_repo = SqliteAgentRepo::new(conn.clone());
    let request_repo = SqliteRequestRepo::new(conn.clone());

    let req = Request {
        id: "req-ce-ok".into(),
        requester: "alice".into(),
        database: DatabaseName::new("app").unwrap(),
        environment: Environment::new("production").unwrap(),
        operation: Operation::ExecuteDml,
        detail: "UPDATE t SET x=1".into(),
        status: RequestStatus::Running,
        emergency: false,
        reason: None,
        idempotency_key: None,
        metadata_json: "{}".into(),
        share_with: vec![],
        no_store: false,
        workflow_snapshot_json: None,
        cancel_reason: None,
        cancelled_by: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        resolved_at: None,
        expires_at: None,
    };
    request_repo.insert(&req).unwrap();

    let execution = Execution {
        id: "exec-ce-ok".into(),
        request_id: "req-ce-ok".into(),
        agent_id: "agent-1".into(),
        status: ExecutionStatus::Running,
        token: "tok".into(),
        lease_expires_at: Utc::now() + chrono::Duration::minutes(5),
        started_at: Some(Utc::now()),
        finished_at: None,
        error_message: None,
        created_at: Utc::now(),
    };
    agent_repo.create_execution(&execution).unwrap();

    let now = Utc::now();
    let result = agent_repo
        .complete_execution(
            "exec-ce-ok",
            "req-ce-ok",
            true,
            now,
            &AuditEvent::simple(
                "execution.completed",
                "execution",
                "agent-1",
                Some("exec-ce-ok"),
                now,
                &AuditContext::System,
            ),
            None,
            &[],
        )
        .unwrap();
    assert!(result);

    let fetched_exec = agent_repo.get_execution("exec-ce-ok").unwrap().unwrap();
    assert_eq!(fetched_exec.status, ExecutionStatus::Completed);
    assert!(fetched_exec.finished_at.is_some());

    let fetched_req = request_repo.get("req-ce-ok").unwrap().unwrap();
    assert_eq!(fetched_req.status, RequestStatus::Executed);
}

// --- 14. complete_execution: failure case ---

#[test]
fn complete_execution_failure() {
    let conn = setup();
    register_db(&conn);

    let agent_repo = SqliteAgentRepo::new(conn.clone());
    let request_repo = SqliteRequestRepo::new(conn.clone());

    let req = Request {
        id: "req-ce-fail".into(),
        requester: "alice".into(),
        database: DatabaseName::new("app").unwrap(),
        environment: Environment::new("production").unwrap(),
        operation: Operation::ExecuteDml,
        detail: "UPDATE t SET x=1".into(),
        status: RequestStatus::Running,
        emergency: false,
        reason: None,
        idempotency_key: None,
        metadata_json: "{}".into(),
        share_with: vec![],
        no_store: false,
        workflow_snapshot_json: None,
        cancel_reason: None,
        cancelled_by: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        resolved_at: None,
        expires_at: None,
    };
    request_repo.insert(&req).unwrap();

    let execution = Execution {
        id: "exec-ce-fail".into(),
        request_id: "req-ce-fail".into(),
        agent_id: "agent-1".into(),
        status: ExecutionStatus::Running,
        token: "tok".into(),
        lease_expires_at: Utc::now() + chrono::Duration::minutes(5),
        started_at: Some(Utc::now()),
        finished_at: None,
        error_message: None,
        created_at: Utc::now(),
    };
    agent_repo.create_execution(&execution).unwrap();

    let now = Utc::now();
    let result = agent_repo
        .complete_execution(
            "exec-ce-fail",
            "req-ce-fail",
            false,
            now,
            &AuditEvent::simple(
                "execution.failed",
                "execution",
                "agent-1",
                Some("exec-ce-fail"),
                now,
                &AuditContext::System,
            ),
            None,
            &[],
        )
        .unwrap();
    assert!(result);

    let fetched_exec = agent_repo.get_execution("exec-ce-fail").unwrap().unwrap();
    assert_eq!(fetched_exec.status, ExecutionStatus::Failed);

    let fetched_req = request_repo.get("req-ce-fail").unwrap().unwrap();
    assert_eq!(fetched_req.status, RequestStatus::Failed);
}

// --- 15. complete_execution: cancelled request stays cancelled ---

#[test]
fn complete_execution_cancelled_request() {
    let conn = setup();
    register_db(&conn);

    let agent_repo = SqliteAgentRepo::new(conn.clone());
    let request_repo = SqliteRequestRepo::new(conn.clone());

    let req = Request {
        id: "req-ce-cancel".into(),
        requester: "alice".into(),
        database: DatabaseName::new("app").unwrap(),
        environment: Environment::new("production").unwrap(),
        operation: Operation::ExecuteDml,
        detail: "UPDATE t SET x=1".into(),
        status: RequestStatus::Cancelled,
        emergency: false,
        reason: None,
        idempotency_key: None,
        metadata_json: "{}".into(),
        share_with: vec![],
        no_store: false,
        workflow_snapshot_json: None,
        cancel_reason: Some("user cancelled".into()),
        cancelled_by: Some("alice".into()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        resolved_at: Some(Utc::now()),
        expires_at: None,
    };
    request_repo.insert(&req).unwrap();

    let execution = Execution {
        id: "exec-ce-cancel".into(),
        request_id: "req-ce-cancel".into(),
        agent_id: "agent-1".into(),
        status: ExecutionStatus::Running,
        token: "tok".into(),
        lease_expires_at: Utc::now() + chrono::Duration::minutes(5),
        started_at: Some(Utc::now()),
        finished_at: None,
        error_message: None,
        created_at: Utc::now(),
    };
    agent_repo.create_execution(&execution).unwrap();

    let now = Utc::now();
    let result = agent_repo
        .complete_execution(
            "exec-ce-cancel",
            "req-ce-cancel",
            true,
            now,
            &AuditEvent::simple(
                "execution.completed",
                "execution",
                "agent-1",
                Some("exec-ce-cancel"),
                now,
                &AuditContext::System,
            ),
            None,
            &[],
        )
        .unwrap();
    assert!(!result);

    // Execution is still updated
    let fetched_exec = agent_repo.get_execution("exec-ce-cancel").unwrap().unwrap();
    assert_eq!(fetched_exec.status, ExecutionStatus::Completed);

    // Request stays cancelled
    let fetched_req = request_repo.get("req-ce-cancel").unwrap().unwrap();
    assert_eq!(fetched_req.status, RequestStatus::Cancelled);
}

// --- 16. complete_execution: already completed (not running) ---

#[test]
fn complete_execution_already_completed() {
    let conn = setup();
    register_db(&conn);

    let agent_repo = SqliteAgentRepo::new(conn.clone());
    let request_repo = SqliteRequestRepo::new(conn.clone());

    let req = Request {
        id: "req-ce-done".into(),
        requester: "alice".into(),
        database: DatabaseName::new("app").unwrap(),
        environment: Environment::new("production").unwrap(),
        operation: Operation::ExecuteDml,
        detail: "UPDATE t SET x=1".into(),
        status: RequestStatus::Executed,
        emergency: false,
        reason: None,
        idempotency_key: None,
        metadata_json: "{}".into(),
        share_with: vec![],
        no_store: false,
        workflow_snapshot_json: None,
        cancel_reason: None,
        cancelled_by: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        resolved_at: Some(Utc::now()),
        expires_at: None,
    };
    request_repo.insert(&req).unwrap();

    let execution = Execution {
        id: "exec-ce-done".into(),
        request_id: "req-ce-done".into(),
        agent_id: "agent-1".into(),
        status: ExecutionStatus::Running,
        token: "tok".into(),
        lease_expires_at: Utc::now() + chrono::Duration::minutes(5),
        started_at: Some(Utc::now()),
        finished_at: None,
        error_message: None,
        created_at: Utc::now(),
    };
    agent_repo.create_execution(&execution).unwrap();

    let now = Utc::now();
    let result = agent_repo
        .complete_execution(
            "exec-ce-done",
            "req-ce-done",
            true,
            now,
            &AuditEvent::simple(
                "execution.completed",
                "execution",
                "agent-1",
                Some("exec-ce-done"),
                now,
                &AuditContext::System,
            ),
            None,
            &[],
        )
        .unwrap();
    assert!(!result);

    // Execution still updated
    let fetched_exec = agent_repo.get_execution("exec-ce-done").unwrap().unwrap();
    assert_eq!(fetched_exec.status, ExecutionStatus::Completed);
}

// --- 17. create_and_dispatch: success ---

#[test]
fn create_and_dispatch_success() {
    let conn = setup();
    register_db(&conn);

    let request_repo = SqliteRequestRepo::new(conn.clone());

    let req = Request {
        id: "req-cad".into(),
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
        cancel_reason: None,
        cancelled_by: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        resolved_at: None,
        expires_at: None,
    };
    request_repo.create_and_dispatch(&req).unwrap();

    let fetched = request_repo.get("req-cad").unwrap().unwrap();
    assert_eq!(fetched.status, RequestStatus::Dispatched);
    assert_eq!(fetched.requester, "alice");
    assert_eq!(fetched.detail, "SELECT 1");
}

// --- 18. reject_and_record: success ---

#[test]
fn reject_and_record_success() {
    let conn = setup();
    register_db(&conn);

    let request_repo = SqliteRequestRepo::new(conn.clone());

    let req = Request {
        id: "req-rej".into(),
        requester: "alice".into(),
        database: DatabaseName::new("app").unwrap(),
        environment: Environment::new("production").unwrap(),
        operation: Operation::ExecuteDml,
        detail: "DELETE FROM t".into(),
        status: RequestStatus::Pending,
        emergency: false,
        reason: None,
        idempotency_key: None,
        metadata_json: "{}".into(),
        share_with: vec![],
        no_store: false,
        workflow_snapshot_json: None,
        cancel_reason: None,
        cancelled_by: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        resolved_at: None,
        expires_at: None,
    };
    request_repo.insert(&req).unwrap();

    let approval = Approval {
        id: "apr-rej".into(),
        request_id: "req-rej".into(),
        action: ApprovalAction::Reject,
        actor_id: "admin-1".into(),
        matched_selector: "role:admin".into(),
        step_index: 0,
        comment: Some("too dangerous".into()),
        created_at: Utc::now(),
    };

    let now = Utc::now();
    let result = request_repo
        .reject_and_record("req-rej", &approval, now)
        .unwrap();
    assert!(result);

    let fetched = request_repo.get("req-rej").unwrap().unwrap();
    assert_eq!(fetched.status, RequestStatus::Rejected);

    let approvals = request_repo.get_approvals("req-rej").unwrap();
    assert_eq!(approvals.len(), 1);
    assert_eq!(approvals[0].actor_id, "admin-1");
    assert_eq!(approvals[0].comment.as_deref(), Some("too dangerous"));
}

// --- 19. reject_and_record: already rejected (optimistic lock) ---

#[test]
fn reject_and_record_already_rejected() {
    let conn = setup();
    register_db(&conn);

    let request_repo = SqliteRequestRepo::new(conn.clone());

    let req = Request {
        id: "req-rej2".into(),
        requester: "alice".into(),
        database: DatabaseName::new("app").unwrap(),
        environment: Environment::new("production").unwrap(),
        operation: Operation::ExecuteDml,
        detail: "DELETE FROM t".into(),
        status: RequestStatus::Rejected,
        emergency: false,
        reason: None,
        idempotency_key: None,
        metadata_json: "{}".into(),
        share_with: vec![],
        no_store: false,
        workflow_snapshot_json: None,
        cancel_reason: None,
        cancelled_by: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        resolved_at: Some(Utc::now()),
        expires_at: None,
    };
    request_repo.insert(&req).unwrap();

    let approval = Approval {
        id: "apr-rej2".into(),
        request_id: "req-rej2".into(),
        action: ApprovalAction::Reject,
        actor_id: "admin-2".into(),
        matched_selector: "role:admin".into(),
        step_index: 0,
        comment: None,
        created_at: Utc::now(),
    };

    let result = request_repo
        .reject_and_record("req-rej2", &approval, Utc::now())
        .unwrap();
    assert!(!result);

    // No approval record inserted on failure
    let approvals = request_repo.get_approvals("req-rej2").unwrap();
    assert_eq!(approvals.len(), 0);
}

// --- 20. claim_and_mark_running: success ---

#[test]
fn claim_and_mark_running_success() {
    let conn = setup();
    register_db(&conn);

    let agent_repo = SqliteAgentRepo::new(conn.clone());
    let request_repo = SqliteRequestRepo::new(conn.clone());

    let req = Request {
        id: "req-claim".into(),
        requester: "alice".into(),
        database: DatabaseName::new("app").unwrap(),
        environment: Environment::new("production").unwrap(),
        operation: Operation::ExecuteDml,
        detail: "UPDATE t SET x=1".into(),
        status: RequestStatus::Dispatched,
        emergency: false,
        reason: None,
        idempotency_key: None,
        metadata_json: "{}".into(),
        share_with: vec![],
        no_store: false,
        workflow_snapshot_json: None,
        cancel_reason: None,
        cancelled_by: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        resolved_at: None,
        expires_at: None,
    };
    request_repo.insert(&req).unwrap();

    let execution = Execution {
        id: "exec-claim".into(),
        request_id: "req-claim".into(),
        agent_id: "agent-1".into(),
        status: ExecutionStatus::Claimed,
        token: "signed-tok".into(),
        lease_expires_at: Utc::now() + chrono::Duration::minutes(5),
        started_at: None,
        finished_at: None,
        error_message: None,
        created_at: Utc::now(),
    };

    let now = Utc::now();
    let result = agent_repo
        .claim_and_mark_running(&execution, "req-claim", now)
        .unwrap();
    assert!(result);

    let fetched_exec = agent_repo.get_execution("exec-claim").unwrap().unwrap();
    assert_eq!(fetched_exec.status, ExecutionStatus::Claimed);
    assert_eq!(fetched_exec.agent_id, "agent-1");

    let fetched_req = request_repo.get("req-claim").unwrap().unwrap();
    assert_eq!(fetched_req.status, RequestStatus::Running);
}

// --- 21. claim_and_mark_running: request not dispatched → rollback ---

#[test]
fn claim_and_mark_running_not_dispatched_rollback() {
    let conn = setup();
    register_db(&conn);

    let agent_repo = SqliteAgentRepo::new(conn.clone());
    let request_repo = SqliteRequestRepo::new(conn.clone());

    // Request is 'running', not 'dispatched'
    let req = Request {
        id: "req-claim-fail".into(),
        requester: "alice".into(),
        database: DatabaseName::new("app").unwrap(),
        environment: Environment::new("production").unwrap(),
        operation: Operation::ExecuteDml,
        detail: "UPDATE t SET x=1".into(),
        status: RequestStatus::Running,
        emergency: false,
        reason: None,
        idempotency_key: None,
        metadata_json: "{}".into(),
        share_with: vec![],
        no_store: false,
        workflow_snapshot_json: None,
        cancel_reason: None,
        cancelled_by: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        resolved_at: None,
        expires_at: None,
    };
    request_repo.insert(&req).unwrap();

    let execution = Execution {
        id: "exec-claim-fail".into(),
        request_id: "req-claim-fail".into(),
        agent_id: "agent-1".into(),
        status: ExecutionStatus::Claimed,
        token: "signed-tok".into(),
        lease_expires_at: Utc::now() + chrono::Duration::minutes(5),
        started_at: None,
        finished_at: None,
        error_message: None,
        created_at: Utc::now(),
    };

    let now = Utc::now();
    let result = agent_repo
        .claim_and_mark_running(&execution, "req-claim-fail", now)
        .unwrap();
    assert!(!result);

    // Verify NO orphan execution was created (rollback worked)
    let fetched_exec = agent_repo.get_execution("exec-claim-fail").unwrap();
    assert!(fetched_exec.is_none());

    // Request status unchanged
    let fetched_req = request_repo.get("req-claim-fail").unwrap().unwrap();
    assert_eq!(fetched_req.status, RequestStatus::Running);
}

// --- 22. find_expired_approved: workflow-specific approval_ttl_secs ---

#[test]
fn find_expired_approved_with_workflow_ttl() {
    let conn = setup();
    register_db(&conn);

    let repo = SqliteRequestRepo::new(conn.clone());
    let two_min_ago = Utc::now() - chrono::Duration::seconds(120);
    let req = Request {
        id: "req-exp-appr".into(),
        requester: "alice".into(),
        database: DatabaseName::new("app").unwrap(),
        environment: Environment::new("production").unwrap(),
        operation: Operation::ExecuteSelect,
        detail: "SELECT 1".into(),
        status: RequestStatus::Approved,
        emergency: false,
        reason: None,
        idempotency_key: None,
        metadata_json: "{}".into(),
        share_with: vec![],
        no_store: false,
        workflow_snapshot_json: Some(r#"{"approval_ttl_secs":60}"#.into()),
        cancel_reason: None,
        cancelled_by: None,
        created_at: two_min_ago,
        updated_at: two_min_ago,
        resolved_at: None,
        expires_at: None,
    };
    repo.insert(&req).unwrap();

    let now = Utc::now().to_rfc3339();
    let expired = repo.find_expired_approved(&now).unwrap();
    assert!(expired.contains(&"req-exp-appr".to_string()));
}

// --- 23. find_expired_pending: workflow-specific pending_ttl_secs ---

#[test]
fn find_expired_pending_with_workflow_ttl() {
    let conn = setup();
    register_db(&conn);

    let repo = SqliteRequestRepo::new(conn.clone());
    let two_min_ago = Utc::now() - chrono::Duration::seconds(120);
    let req = Request {
        id: "req-exp-pend".into(),
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
        workflow_snapshot_json: Some(r#"{"pending_ttl_secs":60}"#.into()),
        cancel_reason: None,
        cancelled_by: None,
        created_at: two_min_ago,
        updated_at: two_min_ago,
        resolved_at: None,
        expires_at: None,
    };
    repo.insert(&req).unwrap();

    let now = Utc::now().to_rfc3339();
    let expired = repo.find_expired_pending(&now).unwrap();
    assert!(expired.contains(&"req-exp-pend".to_string()));
}

// --- 24. find_expired_pending: no pending_ttl → infinite (not expired) ---

#[test]
fn find_expired_pending_no_ttl_means_infinite() {
    let conn = setup();
    register_db(&conn);

    let repo = SqliteRequestRepo::new(conn.clone());
    let old = Utc::now() - chrono::Duration::days(30);
    let req = Request {
        id: "req-no-ttl".into(),
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
        workflow_snapshot_json: Some(r#"{"require_reason":true}"#.into()),
        cancel_reason: None,
        cancelled_by: None,
        created_at: old,
        updated_at: old,
        resolved_at: None,
        expires_at: None,
    };
    repo.insert(&req).unwrap();

    let now = Utc::now().to_rfc3339();
    let expired = repo.find_expired_pending(&now).unwrap();
    assert!(!expired.contains(&"req-no-ttl".to_string()));
}

// --- 25. find_dispatched_older_than: dispatched > 300s ago ---

#[test]
fn find_dispatched_older_than_timeout() {
    let conn = setup();
    register_db(&conn);

    let repo = SqliteRequestRepo::new(conn.clone());
    let six_min_ago = Utc::now() - chrono::Duration::seconds(360);
    let req = Request {
        id: "req-stale-disp".into(),
        requester: "alice".into(),
        database: DatabaseName::new("app").unwrap(),
        environment: Environment::new("production").unwrap(),
        operation: Operation::ExecuteSelect,
        detail: "SELECT 1".into(),
        status: RequestStatus::Dispatched,
        emergency: false,
        reason: None,
        idempotency_key: None,
        metadata_json: "{}".into(),
        share_with: vec![],
        no_store: false,
        workflow_snapshot_json: None,
        cancel_reason: None,
        cancelled_by: None,
        created_at: six_min_ago,
        updated_at: six_min_ago,
        resolved_at: None,
        expires_at: None,
    };
    repo.insert(&req).unwrap();

    let now = Utc::now().to_rfc3339();
    let stale = repo.find_dispatched_older_than(&now).unwrap();
    assert!(stale.contains(&"req-stale-disp".to_string()));
}

// --- 26. find_expired_leases: lease_expires_at in the past ---

#[test]
fn find_expired_leases_past() {
    let conn = setup();
    register_db(&conn);

    let agent_repo = SqliteAgentRepo::new(conn.clone());
    let request_repo = SqliteRequestRepo::new(conn.clone());

    let req = Request {
        id: "req-lease-exp".into(),
        requester: "alice".into(),
        database: DatabaseName::new("app").unwrap(),
        environment: Environment::new("production").unwrap(),
        operation: Operation::ExecuteDml,
        detail: "UPDATE t SET x=1".into(),
        status: RequestStatus::Running,
        emergency: false,
        reason: None,
        idempotency_key: None,
        metadata_json: "{}".into(),
        share_with: vec![],
        no_store: false,
        workflow_snapshot_json: None,
        cancel_reason: None,
        cancelled_by: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        resolved_at: None,
        expires_at: None,
    };
    request_repo.insert(&req).unwrap();

    let expired_lease = Utc::now() - chrono::Duration::seconds(60);
    let execution = Execution {
        id: "exec-lease-exp".into(),
        request_id: "req-lease-exp".into(),
        agent_id: "agent-1".into(),
        status: ExecutionStatus::Running,
        token: "tok".into(),
        lease_expires_at: expired_lease,
        started_at: Some(Utc::now() - chrono::Duration::seconds(120)),
        finished_at: None,
        error_message: None,
        created_at: Utc::now() - chrono::Duration::seconds(120),
    };
    agent_repo.create_execution(&execution).unwrap();

    let now = Utc::now().to_rfc3339();
    let expired = agent_repo.find_expired_leases(&now).unwrap();
    assert!(expired.iter().any(|(eid, _)| eid == "exec-lease-exp"));
}

// --- 27. SEC-4: Duplicate approval prevention (UNIQUE index) ---

#[test]
fn duplicate_approve_same_actor_step_rejected() {
    let conn = setup();
    register_db(&conn);

    let request_repo = SqliteRequestRepo::new(conn.clone());

    // Insert a pending request
    let req = Request {
        id: "req-dup-appr".into(),
        requester: "alice".into(),
        database: DatabaseName::new("app").unwrap(),
        environment: Environment::new("production").unwrap(),
        operation: Operation::ExecuteDml,
        detail: "UPDATE t SET x=1".into(),
        status: RequestStatus::Pending,
        emergency: false,
        reason: None,
        idempotency_key: None,
        metadata_json: "{}".into(),
        share_with: vec![],
        no_store: false,
        workflow_snapshot_json: None,
        cancel_reason: None,
        cancelled_by: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        resolved_at: None,
        expires_at: None,
    };
    request_repo.insert(&req).unwrap();

    // First approval succeeds
    let a1 = Approval {
        id: "apr-dup-1".into(),
        request_id: "req-dup-appr".into(),
        action: ApprovalAction::Approve,
        actor_id: "bob".into(),
        matched_selector: "role:dba".into(),
        step_index: 0,
        comment: None,
        created_at: Utc::now(),
    };
    request_repo.insert_approval(&a1).unwrap();

    // Second approval with same (request_id, actor_id, step_index, action=approve) → UNIQUE violation
    let a2 = Approval {
        id: "apr-dup-2".into(),
        request_id: "req-dup-appr".into(),
        action: ApprovalAction::Approve,
        actor_id: "bob".into(),
        matched_selector: "role:dba".into(),
        step_index: 0,
        comment: Some("second attempt".into()),
        created_at: Utc::now(),
    };
    let result = request_repo.insert_approval(&a2);
    assert!(
        result.is_err(),
        "duplicate approve should be rejected by UNIQUE index"
    );

    // Reject with same (request_id, actor_id, step_index) still works (index is WHERE action='approve')
    let a3 = Approval {
        id: "apr-dup-3".into(),
        request_id: "req-dup-appr".into(),
        action: ApprovalAction::Reject,
        actor_id: "bob".into(),
        matched_selector: "role:dba".into(),
        step_index: 0,
        comment: None,
        created_at: Utc::now(),
    };
    request_repo.insert_approval(&a3).unwrap();
}

// === Policy CRUD ===

#[test]
fn workflow_crud_lifecycle() {
    let conn = setup();
    let repo = SqlitePolicyRepo::new(conn.clone());

    let wf = Workflow {
        id: "wf-1".into(),
        database: DatabaseName::new("app").unwrap(),
        environment: Environment::new("production").unwrap(),
        operations: vec![],
        steps: vec![],
        skip_approval_for: vec![],
        require_reason: true,
        allow_self_approve: false,
        allow_same_approver_across_steps: false,
        pending_ttl_secs: None,
        approval_ttl_secs: Some(3600),
        statement_timeout_secs: None,
        created_at: None,
        updated_at: None,
    };
    repo.create_workflow(&wf).unwrap();
    assert_eq!(repo.get_workflow("wf-1").unwrap().unwrap().id, "wf-1");
    assert_eq!(repo.list_workflows().unwrap().len(), 1);
    assert_eq!(repo.count_workflows().unwrap(), 1);
    assert!(repo.delete_workflow("wf-1").unwrap());
    assert!(!repo.delete_workflow("wf-1").unwrap());
    assert_eq!(repo.count_workflows().unwrap(), 0);
}

#[test]
fn execution_policy_crud() {
    let conn = setup();
    let repo = SqlitePolicyRepo::new(conn.clone());

    let ep = ExecutionPolicy {
        id: "ep-1".into(),
        database: DatabaseName::new("app").unwrap(),
        environment: Environment::new("production").unwrap(),
        max_executions: 3,
        execution_window_secs: 3600,
        retry_on_failure: false,
        statement_timeout_secs: 30,
        max_statement_timeout_secs: 300,
        created_at: None,
        updated_at: None,
    };
    repo.create_execution_policy(&ep).unwrap();
    assert_eq!(
        repo.get_execution_policy("ep-1")
            .unwrap()
            .unwrap()
            .statement_timeout_secs,
        30
    );
    assert_eq!(repo.list_execution_policies().unwrap().len(), 1);
    assert!(repo.delete_execution_policy("ep-1").unwrap());
    assert!(repo.list_execution_policies().unwrap().is_empty());
}

#[test]
fn role_crud() {
    let conn = setup();
    let repo = SqlitePolicyRepo::new(conn.clone());
    let initial_count = repo.count_roles().unwrap();

    let role = RoleDefinition {
        name: "dba".into(),
        permissions: vec![Permission::RequestCreate, Permission::RequestApprove],
        databases: vec![DatabaseName::new("app").unwrap()],
        environments: vec![Environment::new("production").unwrap()],
    };
    repo.create_role(&role).unwrap();
    assert_eq!(repo.get_roles_by_names(&["dba".into()]).unwrap().len(), 1);
    assert_eq!(repo.count_roles().unwrap(), initial_count + 1);
    assert!(repo.delete_role("dba").unwrap());
    assert_eq!(repo.count_roles().unwrap(), initial_count);
}

#[test]
fn result_policy_lookup_returns_none() {
    let conn = setup();
    register_db(&conn);
    let repo = SqlitePolicyRepo::new(conn.clone());
    let db = DatabaseName::new("app").unwrap();
    let env = Environment::new("production").unwrap();
    assert!(repo.find_result_policy(&db, &env).unwrap().is_none());
}

#[test]
fn result_policy_crud_roundtrip() {
    let conn = setup();
    let repo = SqlitePolicyRepo::new(conn.clone());

    let policy = ResultPolicy {
        id: "rp-1".into(),
        database: DatabaseName::new("app").unwrap(),
        environment: Environment::new("production").unwrap(),
        retention_days: 30,
        delivery_mode: DeliveryMode::Both,
        access: vec![Selector::parse("role:admin").unwrap()],
        created_at: None,
        updated_at: None,
    };
    repo.create_result_policy(&policy).unwrap();

    let got = repo.get_result_policy("rp-1").unwrap().unwrap();
    assert_eq!(got.retention_days, 30);
    assert_eq!(got.access.len(), 1);

    assert_eq!(repo.list_result_policies().unwrap().len(), 1);

    let mut updated = got;
    updated.retention_days = 90;
    assert!(repo.update_result_policy(&updated).unwrap());

    let got2 = repo.get_result_policy("rp-1").unwrap().unwrap();
    assert_eq!(got2.retention_days, 90);

    assert!(repo.delete_result_policy("rp-1").unwrap());
    assert!(repo.get_result_policy("rp-1").unwrap().is_none());
    assert!(!repo.delete_result_policy("rp-1").unwrap());
}

#[test]
fn result_policy_conflict_on_duplicate() {
    let conn = setup();
    let repo = SqlitePolicyRepo::new(conn.clone());

    let policy = ResultPolicy {
        id: "rp-1".into(),
        database: DatabaseName::new("app").unwrap(),
        environment: Environment::new("production").unwrap(),
        retention_days: 30,
        delivery_mode: DeliveryMode::Both,
        access: vec![],
        created_at: None,
        updated_at: None,
    };
    repo.create_result_policy(&policy).unwrap();

    let dup = ResultPolicy {
        id: "rp-2".into(),
        ..policy
    };
    let err = repo.create_result_policy(&dup).unwrap_err();
    assert!(matches!(err, dbward_app::error::AppError::Conflict(_)));
}

#[test]
fn notification_policy_crud_roundtrip() {
    let conn = setup();
    let repo = SqlitePolicyRepo::new(conn.clone());

    let policy = dbward_domain::policies::NotificationPolicy {
        id: "np-1".into(),
        database: DatabaseName::new("app").unwrap(),
        environment: Environment::new("production").unwrap(),
        webhooks: vec!["https://example.com/hook".into()],
        events: vec!["request.created".into()],
    };
    repo.create_notification_policy(&policy).unwrap();

    let got = repo.get_notification_policy("np-1").unwrap().unwrap();
    assert_eq!(got.webhooks.len(), 1);
    assert_eq!(got.events, vec!["request.created"]);

    assert_eq!(repo.list_notification_policies().unwrap().len(), 1);

    let mut updated = got;
    updated.webhooks = vec!["https://new.example.com/hook".into()];
    assert!(repo.update_notification_policy(&updated).unwrap());

    let got2 = repo.get_notification_policy("np-1").unwrap().unwrap();
    assert_eq!(got2.webhooks[0], "https://new.example.com/hook");

    assert!(repo.delete_notification_policy("np-1").unwrap());
    assert!(repo.get_notification_policy("np-1").unwrap().is_none());
}

// === User CRUD ===

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

// === Token extended ===

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

// === Audit extended ===

#[test]
fn audit_list_with_filter() {
    let conn = setup();
    let logger = SqliteAuditLogger::new(conn.clone());
    let repo = SqliteAuditRepo::new(conn.clone());

    logger
        .record(&AuditEvent::simple(
            "query_executed",
            "query",
            "alice",
            Some("req-1"),
            Utc::now(),
            &AuditContext::System,
        ))
        .unwrap();
    logger
        .record(&AuditEvent::simple(
            "request_created",
            "request",
            "bob",
            Some("req-2"),
            Utc::now(),
            &AuditContext::System,
        ))
        .unwrap();

    let filter = AuditFilter {
        actor_id: Some("alice".into()),
        event_type: None,
        event_category: None,
        outcome: None,
        environment: None,
        database: None,
        since: None,
        until: None,
        limit: 100,
        offset: 0,
    };
    let events = repo.list(&filter).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].actor_id, "alice");
}

#[test]
fn audit_purge_old() {
    let conn = setup();
    let logger = SqliteAuditLogger::new(conn.clone());
    let repo = SqliteAuditRepo::new(conn.clone());

    logger
        .record(&AuditEvent::simple(
            "test",
            "test",
            "x",
            None,
            Utc::now(),
            &AuditContext::System,
        ))
        .unwrap();
    // Nothing old enough to purge
    assert_eq!(repo.purge_old("2000-01-01T00:00:00Z").unwrap(), 0);
    // Purge everything
    assert_eq!(repo.purge_old("2099-01-01T00:00:00Z").unwrap(), 1);
}

// === Agent extended ===

#[test]
fn agent_get_and_list() {
    let conn = setup();
    register_db(&conn);
    let repo = SqliteAgentRepo::new(conn.clone());

    let agent = Agent {
        lease_duration_secs: None,
        id: "agent-1".into(),
        token_id: "tok-1".into(),
        databases: vec![DatabaseCapability {
            database: DatabaseName::new("app").unwrap(),
            environment: Environment::new("production").unwrap(),
        }],
        status: AgentStatus::Active,
        max_concurrent: 2,
        in_flight: 0,
        last_seen: Some(Utc::now()),
        created_at: Utc::now(),
    };
    repo.upsert(&agent).unwrap();
    assert_eq!(repo.get("agent-1").unwrap().unwrap().id, "agent-1");
    assert_eq!(repo.list().unwrap().len(), 1);
}

#[test]
fn agent_find_dispatched_jobs() {
    let conn = setup();
    register_db(&conn);
    let repo = SqliteAgentRepo::new(conn.clone());
    let request_repo = SqliteRequestRepo::new(conn.clone());

    let req = Request {
        id: "req-d1".into(),
        requester: "alice".into(),
        database: DatabaseName::new("app").unwrap(),
        environment: Environment::new("production").unwrap(),
        operation: Operation::ExecuteDml,
        detail: "UPDATE t SET x=1".into(),
        status: RequestStatus::Dispatched,
        emergency: false,
        reason: None,
        idempotency_key: None,
        metadata_json: "{}".into(),
        share_with: vec![],
        no_store: false,
        workflow_snapshot_json: None,
        cancel_reason: None,
        cancelled_by: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        resolved_at: None,
        expires_at: None,
    };
    request_repo.insert(&req).unwrap();

    let caps = vec![(
        DatabaseName::new("app").unwrap(),
        Environment::new("production").unwrap(),
    )];
    let jobs = repo.find_dispatched_jobs(&caps).unwrap();
    assert_eq!(jobs.len(), 1);
}

#[test]
fn agent_extend_lease_and_find_executions() {
    let conn = setup();
    register_db(&conn);
    let repo = SqliteAgentRepo::new(conn.clone());
    let request_repo = SqliteRequestRepo::new(conn.clone());

    let req = Request {
        id: "req-el".into(),
        requester: "alice".into(),
        database: DatabaseName::new("app").unwrap(),
        environment: Environment::new("production").unwrap(),
        operation: Operation::ExecuteDml,
        detail: "X".into(),
        status: RequestStatus::Running,
        emergency: false,
        reason: None,
        idempotency_key: None,
        metadata_json: "{}".into(),
        share_with: vec![],
        no_store: false,
        workflow_snapshot_json: None,
        cancel_reason: None,
        cancelled_by: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        resolved_at: None,
        expires_at: None,
    };
    request_repo.insert(&req).unwrap();

    let exec = Execution {
        id: "exec-el".into(),
        request_id: "req-el".into(),
        agent_id: "agent-1".into(),
        status: ExecutionStatus::Claimed,
        token: "tok".into(),
        lease_expires_at: Utc::now(),
        started_at: Some(Utc::now()),
        finished_at: None,
        error_message: None,
        created_at: Utc::now(),
    };
    repo.create_execution(&exec).unwrap();

    let new_expiry = Utc::now() + chrono::Duration::minutes(10);
    repo.extend_lease("exec-el", new_expiry).unwrap();

    let got = repo.get_execution("exec-el").unwrap().unwrap();
    assert!(got.lease_expires_at > Utc::now());

    let execs = repo.find_executions_for_request("req-el").unwrap();
    assert_eq!(execs.len(), 1);
}
