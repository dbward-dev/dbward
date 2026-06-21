use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use dbward_domain::auth::AuthUser;

use crate::session::SessionRuntime;

pub struct SessionStore {
    sessions: DashMap<String, Arc<SessionRuntime>>,
    ttl: Duration,
    max_sessions: usize,
}

impl SessionStore {
    pub fn new(ttl_secs: u64, max_sessions: usize) -> Self {
        Self {
            sessions: DashMap::new(),
            ttl: Duration::from_secs(ttl_secs),
            max_sessions,
        }
    }

    pub fn create(
        &self,
        user: AuthUser,
        supports_elicitation: bool,
    ) -> Option<Arc<SessionRuntime>> {
        // Generate ID first, then use entry API to atomically check + insert.
        // If we exceed max_sessions after insert, remove immediately.
        let id = uuid::Uuid::new_v4().to_string();
        let session = Arc::new(SessionRuntime::new(id.clone(), user, supports_elicitation));
        self.sessions.insert(id.clone(), session.clone());

        // Post-insert enforcement: if over limit, undo
        if self.sessions.len() > self.max_sessions {
            self.sessions.remove(&id);
            return None;
        }

        Some(session)
    }

    pub fn get(&self, id: &str) -> Option<Arc<SessionRuntime>> {
        self.sessions.get(id).map(|e| e.value().clone())
    }

    pub fn remove(&self, id: &str) -> Option<Arc<SessionRuntime>> {
        self.sessions.remove(id).map(|(_, v)| v)
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Iterate over all sessions (for gauge computation).
    pub fn iter_sessions(&self) -> dashmap::iter::Iter<'_, String, Arc<SessionRuntime>> {
        self.sessions.iter()
    }

    /// Remove expired sessions and prune completed streams. Call from background task.
    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        let stream_ttl = Duration::from_secs(300); // replay buffer retention

        // 1. Prune completed streams and stale resolved_elicitations within live sessions
        for entry in self.sessions.iter() {
            let session = entry.value();

            // Prune resolved elicitation cache (keep 60s)
            let elicit_cutoff = now - Duration::from_secs(60);
            session
                .resolved_elicitations
                .retain(|_, ts| *ts > elicit_cutoff);

            let expired_streams: Vec<String> = session
                .streams
                .iter()
                .filter(|s| {
                    if let Some(completed_at) = *s.value().completed_at.read() {
                        now.duration_since(completed_at) > stream_ttl
                    } else {
                        false
                    }
                })
                .map(|s| s.key().clone())
                .collect();
            for sid in expired_streams {
                session.streams.remove(&sid);
            }
        }

        // 2. Remove expired sessions
        let expired: Vec<String> = self
            .sessions
            .iter()
            .filter(|entry| {
                let last = *entry.value().last_active.read();
                now.duration_since(last) > self.ttl
            })
            .map(|entry| entry.key().clone())
            .collect();

        for id in expired {
            if let Some((_, session)) = self.sessions.remove(&id) {
                session.shutdown();
                tracing::debug!(session_id = %id, "session expired and removed");
            }
        }
    }

    /// Spawn a background cleanup task that runs every 30 seconds.
    pub fn spawn_cleanup(self: &Arc<Self>, cancel: tokio_util::sync::CancellationToken) {
        let store = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                tokio::select! {
                    _ = interval.tick() => store.cleanup_expired(),
                    _ = cancel.cancelled() => break,
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dbward_domain::auth::SubjectType;

    fn user() -> AuthUser {
        AuthUser {
            subject_id: "u1".into(),
            subject_type: SubjectType::User,
            groups: vec![],
            roles: vec![],
            token_id: None,
        }
    }

    #[test]
    fn create_and_get() {
        let store = SessionStore::new(3600, 100);
        let session = store.create(user(), false).unwrap();
        let got = store.get(&session.id).unwrap();
        assert_eq!(got.id, session.id);
    }

    #[test]
    fn max_sessions_enforced() {
        let store = SessionStore::new(3600, 2);
        store.create(user(), false).unwrap();
        store.create(user(), false).unwrap();
        assert!(store.create(user(), false).is_none());
    }

    #[test]
    fn remove_works() {
        let store = SessionStore::new(3600, 100);
        let session = store.create(user(), false).unwrap();
        let id = session.id.clone();
        store.remove(&id);
        assert!(store.get(&id).is_none());
    }

    #[test]
    fn cleanup_removes_expired() {
        let store = SessionStore::new(0, 100); // TTL = 0s → everything expires immediately
        let session = store.create(user(), false).unwrap();
        let id = session.id.clone();
        // Force last_active to be in the past
        std::thread::sleep(Duration::from_millis(10));
        store.cleanup_expired();
        assert!(store.get(&id).is_none());
    }

    #[test]
    fn cleanup_prunes_completed_streams() {
        let store = SessionStore::new(3600, 100);
        let session = store.create(user(), false).unwrap();
        let id = session.id.clone();

        // Add a completed stream with old completed_at
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let stream = std::sync::Arc::new(crate::session::StreamRuntime::new("s1".into(), tx, 100));
        stream
            .completed
            .store(true, std::sync::atomic::Ordering::Relaxed);
        // Set completed_at to 400s ago (exceeds 300s TTL)
        *stream.completed_at.write() = Some(Instant::now() - Duration::from_secs(400));
        session.streams.insert("s1".into(), stream);

        store.cleanup_expired();

        // Session still alive but stream pruned
        assert!(store.get(&id).is_some());
        assert!(store.get(&id).unwrap().streams.is_empty());
    }

    #[test]
    fn cleanup_prunes_resolved_elicitations() {
        let store = SessionStore::new(3600, 100);
        let session = store.create(user(), false).unwrap();

        // Add a resolved elicitation from 120s ago (exceeds 60s cutoff)
        session
            .resolved_elicitations
            .insert("e1".into(), Instant::now() - Duration::from_secs(120));

        store.cleanup_expired();

        assert!(session.resolved_elicitations.is_empty());
    }
}
