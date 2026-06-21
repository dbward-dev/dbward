use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::time::Instant;

use dashmap::DashMap;
use parking_lot::{Mutex, RwLock};
use tokio::sync::{mpsc, oneshot};
use tokio::task::AbortHandle;
use tokio_util::sync::CancellationToken;

use dbward_domain::auth::AuthUser;
use dbward_mcp::ports::ElicitResult;

// --- Session phases ---

pub const PHASE_INITIALIZING: u8 = 0;
pub const PHASE_ACTIVE: u8 = 1;
pub const PHASE_CLOSING: u8 = 2;

// --- SSE Event ---

#[derive(Debug, Clone)]
pub struct SseEvent {
    pub id: String,
    pub data: String,
    pub timestamp: Instant,
}

// --- SessionRuntime ---

pub struct SessionRuntime {
    pub id: String,
    pub user: AuthUser,
    pub phase: AtomicU8,
    pub created_at: Instant,
    pub last_active: RwLock<Instant>,
    pub client_supports_elicitation: AtomicBool,

    pub streams: DashMap<String, std::sync::Arc<StreamRuntime>>,
    pub requests: DashMap<String, RequestRuntime>,
    pub active_request_count: AtomicU64,  // atomic counter for concurrency limit
    pub pending_elicitations: DashMap<String, oneshot::Sender<ElicitResult>>,
    pub resolved_elicitations: DashMap<String, Instant>,  // short-lived cache for "already resolved" detection
    pub elicit_id_counter: AtomicU64,
}

impl SessionRuntime {
    pub fn new(id: String, user: AuthUser, supports_elicitation: bool) -> Self {
        let now = Instant::now();
        Self {
            id,
            user,
            phase: AtomicU8::new(PHASE_INITIALIZING),
            created_at: now,
            last_active: RwLock::new(now),
            client_supports_elicitation: AtomicBool::new(supports_elicitation),
            streams: DashMap::new(),
            requests: DashMap::new(),
            active_request_count: AtomicU64::new(0),
            pending_elicitations: DashMap::new(),
            resolved_elicitations: DashMap::new(),
            elicit_id_counter: AtomicU64::new(0),
        }
    }

    pub fn phase(&self) -> u8 {
        self.phase.load(Ordering::Relaxed)
    }

    pub fn touch(&self) {
        *self.last_active.write() = Instant::now();
    }

    pub fn shutdown(&self) {
        self.phase.store(PHASE_CLOSING, Ordering::SeqCst);

        // Abort all in-flight requests
        for entry in self.requests.iter() {
            entry.value().cancel_token.cancel();
            entry.value().abort_handle.abort();
        }

        // Drop all pending elicitations (oneshot senders will be dropped)
        self.pending_elicitations.clear();

        // Mark all streams completed (closes SSE channels reliably)
        for entry in self.streams.iter() {
            entry.value().mark_completed();
        }

        // Clear maps
        self.streams.clear();
        self.requests.clear();
    }
}

// --- StreamRuntime ---

pub struct StreamRuntime {
    pub stream_id: String,
    pub event_tx: Mutex<Option<mpsc::Sender<axum::response::sse::Event>>>,
    pub subscribers: Mutex<Vec<mpsc::Sender<SseEvent>>>,
    pub replay_buffer: RwLock<VecDeque<SseEvent>>,
    pub replay_capacity: usize,
    pub next_seq: AtomicU64,
    pub completed: AtomicBool,
    pub completed_at: RwLock<Option<Instant>>,
}

impl StreamRuntime {
    pub fn new(stream_id: String, event_tx: mpsc::Sender<axum::response::sse::Event>, replay_capacity: usize) -> Self {
        Self {
            stream_id,
            event_tx: Mutex::new(Some(event_tx)),
            subscribers: Mutex::new(Vec::new()),
            replay_buffer: RwLock::new(VecDeque::new()),
            replay_capacity,
            next_seq: AtomicU64::new(0),
            completed: AtomicBool::new(false),
            completed_at: RwLock::new(None),
        }
    }

    /// Emit a JsonRpcResponse as an SSE event.
    pub async fn emit_json(&self, msg: &dbward_mcp::protocol::JsonRpcResponse) {
        let data = serde_json::to_string(msg).unwrap_or_default();
        self.emit_raw(&data).await;
    }

    /// Emit raw JSON string as an SSE event. Returns false if primary channel is closed.
    pub async fn emit_raw(&self, data: &str) -> bool {
        use axum::response::sse::Event;

        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        let event_id = format!("{}:{}", self.stream_id, seq);

        let sse_event = SseEvent {
            id: event_id.clone(),
            data: data.to_string(),
            timestamp: Instant::now(),
        };

        // 1. Persist to replay buffer
        {
            let mut buf = self.replay_buffer.write();
            buf.push_back(sse_event.clone());
            while buf.len() > self.replay_capacity {
                buf.pop_front();
            }
        }

        // 2. Fan-out to GET resume subscribers (drop slow/closed ones)
        {
            let mut subs = self.subscribers.lock();
            subs.retain(|tx| tx.try_send(sse_event.clone()).is_ok());
        }

        // 3. Send to primary SSE channel (if still open)
        let tx = self.event_tx.lock().clone();
        if let Some(tx) = tx {
            tx.send(Event::default().id(event_id).data(data)).await.is_ok()
        } else {
            false
        }
    }

    pub fn mark_completed(&self) {
        self.completed.store(true, Ordering::SeqCst);
        *self.completed_at.write() = Some(Instant::now());
        // Drop the primary SSE sender to close the client connection
        self.event_tx.lock().take();
        // Drop all subscriber senders so GET resume tasks terminate
        self.subscribers.lock().clear();
    }
}

// --- RequestRuntime ---

pub struct RequestRuntime {
    pub stream_id: String,
    pub cancel_token: CancellationToken,
    pub abort_handle: AbortHandle,
}

#[cfg(test)]
mod tests {
    use super::*;
    use dbward_domain::auth::SubjectType;

    fn test_user() -> AuthUser {
        AuthUser {
            subject_id: "u1".into(),
            subject_type: SubjectType::User,
            groups: vec![],
            roles: vec![],
            token_id: None,
        }
    }

    #[tokio::test]
    async fn emit_json_persists_to_replay_buffer() {
        let (tx, _rx) = mpsc::channel(32);
        let stream = StreamRuntime::new("s1".into(), tx, 100);
        let resp = dbward_mcp::protocol::JsonRpcResponse::success(
            Some(serde_json::json!(1)),
            serde_json::json!({"ok": true}),
        );
        stream.emit_json(&resp).await;

        let buf = stream.replay_buffer.read();
        assert_eq!(buf.len(), 1);
        assert_eq!(buf[0].id, "s1:0");
        assert!(buf[0].data.contains("\"ok\""));
    }

    #[tokio::test]
    async fn emit_raw_fans_out_to_subscribers() {
        let (tx, _rx) = mpsc::channel(32);
        let stream = StreamRuntime::new("s1".into(), tx, 100);

        let (sub_tx, mut sub_rx) = mpsc::channel(256);
        stream.subscribers.lock().push(sub_tx);

        stream.emit_raw(r#"{"test":true}"#).await;

        let event = sub_rx.recv().await.unwrap();
        assert_eq!(event.id, "s1:0");
        assert!(event.data.contains("test"));
    }

    #[tokio::test]
    async fn emit_trims_buffer_at_100() {
        let (tx, _rx) = mpsc::channel(128);
        let stream = StreamRuntime::new("s1".into(), tx, 100);
        for _ in 0..105 {
            stream.emit_raw("x").await;
        }
        let buf = stream.replay_buffer.read();
        assert_eq!(buf.len(), 100);
        // First event should be seq 5 (0-4 trimmed)
        assert_eq!(buf[0].id, "s1:5");
    }

    #[tokio::test]
    async fn emit_removes_closed_subscribers() {
        let (tx, _rx) = mpsc::channel(32);
        let stream = StreamRuntime::new("s1".into(), tx, 100);

        let (sub_tx, sub_rx) = mpsc::channel(256);
        stream.subscribers.lock().push(sub_tx);
        drop(sub_rx); // close receiver

        stream.emit_raw("data").await;

        // Subscriber should have been removed
        assert!(stream.subscribers.lock().is_empty());
    }

    #[test]
    fn shutdown_clears_all() {
        let session = SessionRuntime::new("sess1".into(), test_user(), true);

        // Add a pending elicitation
        let (tx, _rx) = oneshot::channel();
        session.pending_elicitations.insert("e1".into(), tx);

        session.shutdown();

        assert_eq!(session.phase(), PHASE_CLOSING);
        assert!(session.pending_elicitations.is_empty());
        assert!(session.streams.is_empty());
        assert!(session.requests.is_empty());
    }

    #[test]
    fn mark_completed_sets_flag_and_closes_channels() {
        let (tx, mut rx) = mpsc::channel(1);
        let stream = StreamRuntime::new("s1".into(), tx, 100);

        // Add a subscriber
        let (sub_tx, _sub_rx) = mpsc::channel(256);
        stream.subscribers.lock().push(sub_tx);

        assert!(!stream.completed.load(Ordering::Relaxed));

        stream.mark_completed();

        assert!(stream.completed.load(Ordering::Relaxed));
        assert!(stream.completed_at.read().is_some());
        // event_tx should be closed (taken)
        assert!(stream.event_tx.lock().is_none());
        // subscribers should be cleared
        assert!(stream.subscribers.lock().is_empty());
        // receiver should get None (channel closed)
        assert!(rx.try_recv().is_err());
    }
}
