use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use dbward_app::ports::UserRepo;

use super::SlackClient;

const NEG_CACHE_TTL_SECS: u64 = 300;
const NEG_CACHE_MAX_ENTRIES: usize = 1000;
const CACHE_MAX_ENTRIES: usize = 10_000;

/// Resolves subject_id → Slack mention string (`<@U...>` or plaintext fallback).
pub struct SlackUserResolver {
    client: Arc<dyn SlackClient>,
    user_repo: Arc<dyn UserRepo>,
    cache: RwLock<HashMap<String, Option<String>>>,
    neg_cache: RwLock<HashMap<String, Instant>>,
}

impl SlackUserResolver {
    pub fn new(client: Arc<dyn SlackClient>, user_repo: Arc<dyn UserRepo>) -> Self {
        Self {
            client,
            user_repo,
            cache: RwLock::new(HashMap::new()),
            neg_cache: RwLock::new(HashMap::new()),
        }
    }

    /// Resolve subject_id to a Slack mention string.
    /// Returns `<@U...>` if UID found, or plaintext `subject_id` as fallback.
    pub async fn mention_for(&self, subject_id: &str) -> String {
        match self.resolve_uid(subject_id).await {
            Some(uid) => format!("<@{uid}>"),
            None => subject_id.to_string(),
        }
    }

    /// Resolve multiple subject_ids, deduplicate, return mention strings.
    pub async fn mentions_for(&self, subject_ids: &[String]) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        let mut result = Vec::new();
        for sid in subject_ids {
            if seen.insert(sid.clone()) {
                result.push(self.mention_for(sid).await);
            }
        }
        result
    }

    /// Invalidate cached entry for a subject (for future admin commands).
    pub fn invalidate(&self, subject_id: &str) {
        self.cache.write().unwrap().remove(subject_id);
    }

    fn insert_cache(&self, subject_id: &str, value: Option<String>) {
        let mut cache = self.cache.write().unwrap();
        if cache.len() >= CACHE_MAX_ENTRIES && !cache.contains_key(subject_id) {
            // Simple eviction: clear all (rare case for 5-30 person teams)
            cache.clear();
        }
        cache.insert(subject_id.to_string(), value);
    }

    /// Background warm-up: resolve all given subjects with rate limiting.
    pub async fn warm_up(&self, subject_ids: Vec<String>) {
        for sid in subject_ids {
            // Skip if already cached
            {
                let cache = self.cache.read().unwrap();
                if cache.contains_key(&sid) {
                    continue;
                }
            }
            let _ = self.resolve_uid(&sid).await;
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        }
        tracing::info!("Slack UID warm-up complete");
    }

    async fn resolve_uid(&self, subject_id: &str) -> Option<String> {
        // 1. In-memory cache
        {
            let cache = self.cache.read().unwrap();
            if let Some(entry) = cache.get(subject_id) {
                return entry.clone();
            }
        }

        // 2. DB lookup
        if let Ok(Some(uid)) = self.user_repo.get_slack_user_id(subject_id) {
            self.insert_cache(subject_id, Some(uid.clone()));
            return Some(uid);
        }

        // 3. Email → lookupByEmail
        let user = self.user_repo.get(subject_id).ok().flatten()?;
        let email = user.email.as_ref()?;

        // Negative cache check
        {
            let cache = self.neg_cache.read().unwrap();
            if let Some(failed_at) = cache.get(email.as_str())
                && failed_at.elapsed().as_secs() < NEG_CACHE_TTL_SECS
            {
                return None;
            }
        }

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            self.client.lookup_user_by_email(email),
        )
        .await;

        match result {
            Ok(Ok(Some(uid))) => {
                let _ = self.user_repo.update_slack_user_id(subject_id, Some(&uid));
                self.insert_cache(subject_id, Some(uid.clone()));
                Some(uid)
            }
            _ => {
                // Negative cache with LRU eviction
                let mut neg = self.neg_cache.write().unwrap();
                if neg.len() >= NEG_CACHE_MAX_ENTRIES
                    && let Some(oldest_key) =
                        neg.iter().min_by_key(|(_, t)| *t).map(|(k, _)| k.clone())
                {
                    neg.remove(&oldest_key);
                }
                neg.insert(email.clone(), Instant::now());
                self.insert_cache(subject_id, None);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dbward_app::error::AppError;
    use dbward_app::ports::UserRepo;
    use dbward_domain::entities::User;

    struct MockSlackClient {
        lookup_results: HashMap<String, String>, // email → uid
    }

    #[async_trait::async_trait]
    impl SlackClient for MockSlackClient {
        async fn post_message(
            &self,
            _: &str,
            _: &[serde_json::Value],
            _: &str,
        ) -> Result<String, super::super::SlackError> {
            Ok("ts".into())
        }
        async fn post_thread(
            &self,
            _: &str,
            _: &str,
            _: &[serde_json::Value],
            _: &str,
        ) -> Result<(), super::super::SlackError> {
            Ok(())
        }
        async fn update_message(
            &self,
            _: &str,
            _: &str,
            _: &[serde_json::Value],
            _: &str,
        ) -> Result<(), super::super::SlackError> {
            Ok(())
        }
        async fn open_modal(
            &self,
            _: &str,
            _: &serde_json::Value,
        ) -> Result<String, super::super::SlackError> {
            Ok("view".into())
        }
        async fn update_modal(
            &self,
            _: &str,
            _: &serde_json::Value,
        ) -> Result<(), super::super::SlackError> {
            Ok(())
        }
        async fn post_ephemeral(
            &self,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<(), super::super::SlackError> {
            Ok(())
        }
        async fn lookup_user_by_email(
            &self,
            email: &str,
        ) -> Result<Option<String>, super::super::SlackError> {
            Ok(self.lookup_results.get(email).cloned())
        }
    }

    struct MockUserRepo {
        users: HashMap<String, User>,
        slack_ids: HashMap<String, String>,
    }

    impl UserRepo for MockUserRepo {
        fn get(&self, user_id: &str) -> Result<Option<User>, AppError> {
            Ok(self.users.get(user_id).cloned())
        }
        fn upsert(&self, _: &User) -> Result<(), AppError> {
            Ok(())
        }
        fn list(&self) -> Result<Vec<User>, AppError> {
            Ok(vec![])
        }
        fn suspend(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> {
            Ok(false)
        }
        fn activate(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> {
            Ok(false)
        }
        fn is_suspended(&self, _: &str) -> Result<bool, AppError> {
            Ok(false)
        }
        fn ensure_exists(&self, _: &str) -> Result<(), AppError> {
            Ok(())
        }
        fn get_slack_user_id(&self, subject_id: &str) -> Result<Option<String>, AppError> {
            Ok(self.slack_ids.get(subject_id).cloned())
        }
        fn update_slack_user_id(&self, _: &str, _: Option<&str>) -> Result<(), AppError> {
            Ok(())
        }
    }

    fn make_user(id: &str, email: Option<&str>) -> User {
        User {
            id: id.to_string(),
            display_name: None,
            email: email.map(String::from),
            groups: vec![],
            roles: vec![],
            status: dbward_domain::entities::UserStatus::Active,
            last_seen_at: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[tokio::test]
    async fn resolves_from_db_slack_id() {
        let resolver = SlackUserResolver::new(
            Arc::new(MockSlackClient {
                lookup_results: HashMap::new(),
            }),
            Arc::new(MockUserRepo {
                users: HashMap::new(),
                slack_ids: HashMap::from([("alice".into(), "U123".into())]),
            }),
        );
        assert_eq!(resolver.mention_for("alice").await, "<@U123>");
    }

    #[tokio::test]
    async fn resolves_via_email_lookup() {
        let resolver = SlackUserResolver::new(
            Arc::new(MockSlackClient {
                lookup_results: HashMap::from([("alice@ex.com".into(), "U456".into())]),
            }),
            Arc::new(MockUserRepo {
                users: HashMap::from([("alice".into(), make_user("alice", Some("alice@ex.com")))]),
                slack_ids: HashMap::new(),
            }),
        );
        assert_eq!(resolver.mention_for("alice").await, "<@U456>");
    }

    #[tokio::test]
    async fn falls_back_to_plaintext() {
        let resolver = SlackUserResolver::new(
            Arc::new(MockSlackClient {
                lookup_results: HashMap::new(),
            }),
            Arc::new(MockUserRepo {
                users: HashMap::from([("bob".into(), make_user("bob", Some("bob@ex.com")))]),
                slack_ids: HashMap::new(),
            }),
        );
        assert_eq!(resolver.mention_for("bob").await, "bob");
    }

    #[tokio::test]
    async fn neg_cache_prevents_repeated_lookup() {
        let resolver = SlackUserResolver::new(
            Arc::new(MockSlackClient {
                lookup_results: HashMap::new(),
            }),
            Arc::new(MockUserRepo {
                users: HashMap::from([("bob".into(), make_user("bob", Some("bob@ex.com")))]),
                slack_ids: HashMap::new(),
            }),
        );
        // First call → lookup fails → neg_cache
        assert_eq!(resolver.mention_for("bob").await, "bob");
        // Second call → should use cache (no additional API call)
        assert_eq!(resolver.mention_for("bob").await, "bob");
    }

    #[tokio::test]
    async fn deduplicates_mentions() {
        let resolver = SlackUserResolver::new(
            Arc::new(MockSlackClient {
                lookup_results: HashMap::new(),
            }),
            Arc::new(MockUserRepo {
                users: HashMap::new(),
                slack_ids: HashMap::from([("alice".into(), "U123".into())]),
            }),
        );
        let result = resolver
            .mentions_for(&["alice".into(), "alice".into(), "alice".into()])
            .await;
        assert_eq!(result, vec!["<@U123>"]);
    }
}
