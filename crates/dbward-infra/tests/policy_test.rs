mod common;
use common::*;

use dbward_app::ports::*;
use dbward_domain::auth::*;
use dbward_domain::policies::*;
use dbward_domain::values::*;
use dbward_infra::sqlite::*;

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
            require_reason: false,
            allow_self_approve: false,
            allow_same_approver_across_steps: false,
            explain: true,
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
            require_reason: false,
            allow_self_approve: false,
            allow_same_approver_across_steps: false,
            explain: true,
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
            require_reason: true,
            allow_self_approve: false,
            allow_same_approver_across_steps: false,
            explain: true,
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
            require_reason: true,
            allow_self_approve: false,
            allow_same_approver_across_steps: false,
            explain: true,
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
        require_reason: true,
        allow_self_approve: false,
        allow_same_approver_across_steps: false,
        explain: true,
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
        max_rows: None,
        migration_lease_duration_secs: None,
        migration_statement_timeout_secs: None,
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

    // Round-trip with migration_statement_timeout_secs = Some(600)
    let ep2 = ExecutionPolicy {
        id: "ep-2".into(),
        migration_statement_timeout_secs: Some(600),
        ..ep.clone()
    };
    repo.create_execution_policy(&ep2).unwrap();
    let loaded = repo.get_execution_policy("ep-2").unwrap().unwrap();
    assert_eq!(loaded.migration_statement_timeout_secs, Some(600));
    repo.delete_execution_policy("ep-2").unwrap();
}

#[test]
fn role_crud() {
    let conn = setup();
    let repo = SqlitePolicyRepo::new(conn.clone());
    let initial_count = repo.count_roles().unwrap();

    let role = RoleDefinition {
        name: "dba".into(),
        permissions: vec![Permission::RequestExecute, Permission::RequestApprove],
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
