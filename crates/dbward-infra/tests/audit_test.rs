mod common;
use common::*;

use chrono::Utc;
use dbward_app::ports::*;
use dbward_domain::entities::*;
use dbward_infra::sqlite::*;

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
