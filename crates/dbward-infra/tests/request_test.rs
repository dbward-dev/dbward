mod common;
use common::*;

use chrono::Utc;
use dbward_app::ports::*;
use dbward_domain::entities::*;
use dbward_domain::values::*;
use dbward_infra::sqlite::*;

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
    };
    assert!(repo.insert(&req).is_err());
}

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
    assert_eq!(result, dbward_app::ports::CompletionOutcome::Normal);

    let fetched_exec = agent_repo.get_execution("exec-ce-ok").unwrap().unwrap();
    assert_eq!(fetched_exec.status, ExecutionStatus::Completed);
    assert!(fetched_exec.finished_at.is_some());

    let fetched_req = request_repo.get("req-ce-ok").unwrap().unwrap();
    assert_eq!(fetched_req.status, RequestStatus::Executed);
}

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
    assert_eq!(result, dbward_app::ports::CompletionOutcome::Normal);

    let fetched_exec = agent_repo.get_execution("exec-ce-fail").unwrap().unwrap();
    assert_eq!(fetched_exec.status, ExecutionStatus::Failed);

    let fetched_req = request_repo.get("req-ce-fail").unwrap().unwrap();
    assert_eq!(fetched_req.status, RequestStatus::Failed);
}

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
        no_result_store: false,
        workflow_snapshot_json: None,
        decision_trace_json: None,
        execution_plan_json: None,
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
    assert_eq!(
        result,
        dbward_app::ports::CompletionOutcome::RequestCancelled
    );

    // Execution is still updated
    let fetched_exec = agent_repo.get_execution("exec-ce-cancel").unwrap().unwrap();
    assert_eq!(fetched_exec.status, ExecutionStatus::Completed);

    // Request stays cancelled
    let fetched_req = request_repo.get("req-ce-cancel").unwrap().unwrap();
    assert_eq!(fetched_req.status, RequestStatus::Cancelled);
}

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
        no_result_store: false,
        workflow_snapshot_json: None,
        decision_trace_json: None,
        execution_plan_json: None,
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
    let result = agent_repo.complete_execution(
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
    );
    // Idempotent: already-completed request accepts result without error
    assert!(result.is_ok());
}

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
    };
    request_repo.create_and_dispatch(&req).unwrap();

    let fetched = request_repo.get("req-cad").unwrap().unwrap();
    assert_eq!(fetched.status, RequestStatus::Dispatched);
    assert_eq!(fetched.requester, "alice");
    assert_eq!(fetched.detail, "SELECT 1");
}

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
        no_result_store: false,
        workflow_snapshot_json: None,
        decision_trace_json: None,
        execution_plan_json: None,
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
        no_result_store: false,
        workflow_snapshot_json: Some(r#"{"approval_ttl_secs":60}"#.into()),
        decision_trace_json: None,
        execution_plan_json: None,
        cancel_reason: None,
        cancelled_by: None,
        created_at: two_min_ago,
        updated_at: two_min_ago,
        resolved_at: Some(two_min_ago),
        expires_at: None,
    };
    repo.insert(&req).unwrap();

    let now = Utc::now().to_rfc3339();
    let expired = repo.find_expired_approved(&now).unwrap();
    assert!(expired.contains(&"req-exp-appr".to_string()));
}

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
        no_result_store: false,
        workflow_snapshot_json: Some(r#"{"pending_ttl_secs":60}"#.into()),
        decision_trace_json: None,
        execution_plan_json: None,
        cancel_reason: None,
        cancelled_by: None,
        created_at: two_min_ago,
        updated_at: two_min_ago,
        resolved_at: None,
        expires_at: Some(two_min_ago + chrono::Duration::seconds(60)),
    };
    repo.insert(&req).unwrap();

    let now = Utc::now().to_rfc3339();
    let expired = repo.find_expired_pending(&now).unwrap();
    assert!(expired.contains(&"req-exp-pend".to_string()));
}

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
        no_result_store: false,
        workflow_snapshot_json: Some(r#"{"require_reason":true}"#.into()),
        decision_trace_json: None,
        execution_plan_json: None,
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
        no_result_store: false,
        workflow_snapshot_json: None,
        decision_trace_json: None,
        execution_plan_json: None,
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
