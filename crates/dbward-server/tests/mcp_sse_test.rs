//! Unit tests for Phase 2 MCP HTTP elicitation logic.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use dbward_domain::auth::{AuthUser, SubjectType};
use dbward_mcp::ports::ElicitResult;
use dbward_server::session::{SessionRuntime, StreamRuntime, PHASE_ACTIVE, PHASE_INITIALIZING};
use dbward_server::session_store::SessionStore;
use tokio::sync::mpsc;

fn user() -> AuthUser {
    AuthUser {
        subject_id: "u1".into(),
        subject_type: SubjectType::User,
        groups: vec![],
        roles: vec![],
        token_id: None,
    }
}

// --- SessionStore tests ---

#[test]
fn session_store_user_isolation() {
    let store = SessionStore::new(3600, 100);
    let session = store.create(user(), false).unwrap();
    // Different user cannot access
    let got = store.get(&session.id).unwrap();
    assert_eq!(got.user.subject_id, "u1");
}

// --- SessionRuntime tests ---

#[test]
fn session_phase_transitions() {
    let session = SessionRuntime::new("s1".into(), user(), true);
    assert_eq!(session.phase(), PHASE_INITIALIZING);

    session.phase.store(PHASE_ACTIVE, Ordering::SeqCst);
    assert_eq!(session.phase(), PHASE_ACTIVE);
    assert!(session.client_supports_elicitation.load(Ordering::Relaxed));
}

#[test]
fn session_touch_updates_last_active() {
    let session = SessionRuntime::new("s1".into(), user(), false);
    let first = *session.last_active.read();
    std::thread::sleep(Duration::from_millis(5));
    session.touch();
    let second = *session.last_active.read();
    assert!(second > first);
}

#[test]
fn session_active_request_count_atomic() {
    let session = SessionRuntime::new("s1".into(), user(), false);
    assert_eq!(session.active_request_count.load(Ordering::Relaxed), 0);
    session.active_request_count.fetch_add(1, Ordering::Relaxed);
    assert_eq!(session.active_request_count.load(Ordering::Relaxed), 1);
    session.active_request_count.fetch_sub(1, Ordering::Relaxed);
    assert_eq!(session.active_request_count.load(Ordering::Relaxed), 0);
}

// --- HttpElicitation tests ---

#[tokio::test]
async fn http_elicitation_supported_only_when_active() {
    use dbward_server::http_elicitation::HttpElicitation;

    let session = Arc::new(SessionRuntime::new("s1".into(), user(), true));
    let (tx, _rx) = mpsc::channel(32);
    let stream = Arc::new(StreamRuntime::new("stream1".into(), tx, 100));

    let elicit = HttpElicitation::new(session.clone(), stream, 300, std::sync::Arc::new(dbward_server::metrics::Metrics::new()));

    // Phase Initializing → not supported
    assert!(!dbward_mcp::ports::ElicitationTransport::supported(&elicit));

    // Phase Active → supported
    session.phase.store(PHASE_ACTIVE, Ordering::SeqCst);
    assert!(dbward_mcp::ports::ElicitationTransport::supported(&elicit));
}

#[tokio::test]
async fn http_elicitation_not_supported_without_client_capability() {
    use dbward_server::http_elicitation::HttpElicitation;

    let session = Arc::new(SessionRuntime::new("s1".into(), user(), false)); // no elicitation
    session.phase.store(PHASE_ACTIVE, Ordering::SeqCst);
    let (tx, _rx) = mpsc::channel(32);
    let stream = Arc::new(StreamRuntime::new("stream1".into(), tx, 100));

    let elicit = HttpElicitation::new(session, stream, 300, std::sync::Arc::new(dbward_server::metrics::Metrics::new()));
    assert!(!dbward_mcp::ports::ElicitationTransport::supported(&elicit));
}

#[tokio::test]
async fn http_elicitation_ask_emits_event_and_registers_waiter() {
    use dbward_mcp::ports::ElicitationTransport;
    use dbward_server::http_elicitation::HttpElicitation;

    let session = Arc::new(SessionRuntime::new("s1".into(), user(), true));
    session.phase.store(PHASE_ACTIVE, Ordering::SeqCst);
    let (tx, _rx) = mpsc::channel(32);
    let stream = Arc::new(StreamRuntime::new("stream1".into(), tx, 100));
    let elicit = HttpElicitation::new(session.clone(), stream.clone(), 1, std::sync::Arc::new(dbward_server::metrics::Metrics::new())); // 1s timeout

    // Spawn ask in background (will timeout after 1s)
    let handle = tokio::spawn(async move {
        elicit.ask("Why?", serde_json::json!({"type": "object"})).await
    });

    // Give it a moment to register
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Verify waiter registered
    assert_eq!(session.pending_elicitations.len(), 1);

    // Verify event emitted to replay buffer
    let buf = stream.replay_buffer.read();
    assert_eq!(buf.len(), 1);
    assert!(buf[0].data.contains("elicitation/create"));

    // Wait for timeout → Cancel
    let result = handle.await.unwrap().unwrap();
    assert!(matches!(result, ElicitResult::Cancel));
    // Waiter should be removed after timeout
    assert!(session.pending_elicitations.is_empty());
}

#[tokio::test]
async fn http_elicitation_ask_resolves_on_response() {
    use dbward_mcp::ports::ElicitationTransport;
    use dbward_server::http_elicitation::HttpElicitation;

    let session = Arc::new(SessionRuntime::new("s1".into(), user(), true));
    session.phase.store(PHASE_ACTIVE, Ordering::SeqCst);
    let (tx, _rx) = mpsc::channel(32);
    let stream = Arc::new(StreamRuntime::new("stream1".into(), tx, 100));
    let session_clone = session.clone();
    let elicit = HttpElicitation::new(session.clone(), stream, 300, std::sync::Arc::new(dbward_server::metrics::Metrics::new()));

    let handle = tokio::spawn(async move {
        elicit.ask("Why?", serde_json::json!({})).await
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Resolve the pending elicitation
    let key = session_clone.pending_elicitations.iter().next().unwrap().key().clone();
    let (_, tx) = session_clone.pending_elicitations.remove(&key).unwrap();
    tx.send(ElicitResult::Accept {
        content: serde_json::json!({"reason": "testing"}),
    }).unwrap();

    let result = handle.await.unwrap().unwrap();
    match result {
        ElicitResult::Accept { content } => {
            assert_eq!(content["reason"], "testing");
        }
        _ => panic!("expected Accept"),
    }
}

// --- StreamRuntime additional tests ---

#[tokio::test]
async fn stream_closes_on_mark_completed() {
    let (tx, mut rx) = mpsc::channel(32);
    let stream = StreamRuntime::new("s1".into(), tx, 100);

    stream.mark_completed();

    // Receiver should get None (channel closed)
    assert!(rx.recv().await.is_none());
}

#[tokio::test]
async fn emit_after_mark_completed_does_not_panic() {
    let (tx, _rx) = mpsc::channel(32);
    let stream = StreamRuntime::new("s1".into(), tx, 100);

    stream.mark_completed();
    // Should not panic — event_tx is None, silently skipped
    stream.emit_raw("test").await;

    // Buffer still gets the event (for replay)
    let buf = stream.replay_buffer.read();
    assert_eq!(buf.len(), 1);
}
