mod common;
use common::*;

use chrono::Utc;
use dbward_app::ports::*;
use dbward_domain::entities::*;
use dbward_domain::values::*;
use dbward_infra::sqlite::*;

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
        decision_trace_json: None,
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
        uptime_secs: 0,
        active_jobs: vec![],
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
        uptime_secs: 0,
        active_jobs: vec![],
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
        decision_trace_json: None,
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
        decision_trace_json: None,
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

#[test]
fn concurrent_claim_only_one_succeeds() {
    use std::sync::Arc;
    use std::thread;

    // Tests CAS logic: only the first claim transitions dispatched→running.
    // Both threads share the same DbConn (serialized by Mutex), so this verifies
    // the SQL-level CAS (WHERE status='dispatched') correctly prevents double-claim.
    // Note: true multi-connection concurrency (separate processes) is tested via E2E.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.db");
    let conn = dbward_infra::sqlite::open(path.to_str().unwrap()).unwrap();
    register_db(&conn);

    let request_repo = SqliteRequestRepo::new(conn.clone());
    let req = Request {
        id: "req-concurrent".into(),
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
        decision_trace_json: None,
        cancel_reason: None,
        cancelled_by: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        resolved_at: None,
        expires_at: None,
    };
    request_repo.insert(&req).unwrap();

    let conn1 = conn.clone();
    let conn2 = conn.clone();

    let barrier = Arc::new(std::sync::Barrier::new(2));
    let b1 = barrier.clone();
    let b2 = barrier.clone();

    let t1 = thread::spawn(move || {
        let repo = SqliteAgentRepo::new(conn1);
        let exec = Execution {
            id: "exec-1".into(),
            request_id: "req-concurrent".into(),
            agent_id: "agent-A".into(),
            status: ExecutionStatus::Running,
            token: "tok-1".into(),
            lease_expires_at: Utc::now() + chrono::Duration::seconds(60),
            started_at: Some(Utc::now()),
            finished_at: None,
            error_message: None,
            created_at: Utc::now(),
        };
        b1.wait(); // synchronize start
        repo.claim_and_mark_running(&exec, "req-concurrent", Utc::now())
    });

    let t2 = thread::spawn(move || {
        let repo = SqliteAgentRepo::new(conn2);
        let exec = Execution {
            id: "exec-2".into(),
            request_id: "req-concurrent".into(),
            agent_id: "agent-B".into(),
            status: ExecutionStatus::Running,
            token: "tok-2".into(),
            lease_expires_at: Utc::now() + chrono::Duration::seconds(60),
            started_at: Some(Utc::now()),
            finished_at: None,
            error_message: None,
            created_at: Utc::now(),
        };
        b2.wait(); // synchronize start
        repo.claim_and_mark_running(&exec, "req-concurrent", Utc::now())
    });

    let r1 = t1.join().unwrap();
    let r2 = t2.join().unwrap();

    // Exactly one should succeed (Ok(true)), the other should get Ok(false) or error
    let successes = [&r1, &r2].iter().filter(|r| matches!(r, Ok(true))).count();
    assert_eq!(
        successes, 1,
        "Exactly one agent should claim: r1={r1:?}, r2={r2:?}"
    );
}
