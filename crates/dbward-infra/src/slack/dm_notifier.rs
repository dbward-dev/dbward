use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use dbward_app::ports::{UserRepo, WebhookEvent};

use super::{SlackClient, SlackError};

/// Sends DM notifications to requester/approver via Slack Bot API.
pub struct SlackDmNotifier {
    client: Arc<dyn SlackClient>,
    user_repo: Arc<dyn UserRepo>,
    neg_cache: RwLock<HashMap<String, Instant>>,
    pub notify_requester: bool,
    pub notify_approver: bool,
}

const NEG_CACHE_TTL_SECS: u64 = 300;

impl SlackDmNotifier {
    pub fn new(
        client: Arc<dyn SlackClient>,
        user_repo: Arc<dyn UserRepo>,
        notify_requester: bool,
        notify_approver: bool,
    ) -> Self {
        Self {
            client,
            user_repo,
            neg_cache: RwLock::new(HashMap::new()),
            notify_requester,
            notify_approver,
        }
    }

    /// Dispatch DM notifications for a webhook event.
    pub async fn dispatch(&self, event: &WebhookEvent) {
        if self.notify_requester
            && let Some(text) = format_requester_dm(event)
            && let Some(requester) = &event.requester
        {
            self.send_dm(requester, &text).await;
        }

        if self.notify_approver
            && let Some(text) = format_approver_dm(event)
            && let Some(approvers) = &event.approvers
        {
            for approver in approvers {
                self.send_dm(approver, &text).await;
            }
        }
    }

    async fn send_dm(&self, subject_id: &str, text: &str) {
        let slack_uid = match self.resolve_slack_uid(subject_id).await {
            Some(uid) => uid,
            None => {
                tracing::debug!(subject_id, "DM skipped: could not resolve Slack UID");
                return;
            }
        };

        match self.open_and_send(&slack_uid, text).await {
            Ok(()) => tracing::debug!(subject_id, slack_uid, "DM sent"),
            Err(e) => tracing::warn!(subject_id, slack_uid, error = %e, "DM delivery failed"),
        }
    }

    async fn resolve_slack_uid(&self, subject_id: &str) -> Option<String> {
        // 1. Pre-configured slack_user_id
        if let Ok(Some(uid)) = self.user_repo.get_slack_user_id(subject_id) {
            return Some(uid);
        }

        // 2. Email → lookupByEmail
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

        match self.client.lookup_user_by_email(email).await {
            Ok(Some(uid)) => {
                let _ = self.user_repo.update_slack_user_id(subject_id, Some(&uid));
                Some(uid)
            }
            Ok(None) => {
                let mut cache = self.neg_cache.write().unwrap();
                cache.insert(email.clone(), Instant::now());
                None
            }
            Err(e) => {
                tracing::warn!(email, error = %e, "Slack lookupByEmail failed");
                None
            }
        }
    }

    async fn open_and_send(&self, slack_uid: &str, text: &str) -> Result<(), SlackError> {
        let channel = self.client.conversations_open(slack_uid).await?;
        self.client
            .post_message(&channel, &[], text)
            .await
            .map(|_| ())
    }
}

/// Format requester DM text. Returns None if event type is not relevant.
pub fn format_requester_dm(event: &WebhookEvent) -> Option<String> {
    let db = event.database.as_deref().unwrap_or("?");
    let env = event.environment.as_deref().unwrap_or("?");
    let req_id = event.request_id.as_deref().unwrap_or("?");
    let short_id = req_id.get(..8).unwrap_or(req_id);

    let (emoji, title) = match event.event_type.as_str() {
        "request_approved" => ("\u{2705}", "Your request was approved"),
        "request_rejected" => ("\u{274c}", "Your request was rejected"),
        "request_completed" => ("\u{1f389}", "Your request completed successfully"),
        "request_failed" => ("\u{26a0}\u{fe0f}", "Your request failed"),
        "request_expired" => ("\u{23f0}", "Your request expired"),
        _ => return None,
    };

    let mut msg = format!("{emoji} {title}\n\nDatabase: {db} ({env})\nRequest: {short_id}");

    if let Some(ref reason) = event.reason {
        msg.push_str(&format!("\nReason: {reason}"));
    }
    if let Some(ref actor) = event.actor
        && (event.event_type == "request_approved" || event.event_type == "request_rejected")
    {
        msg.push_str(&format!("\nBy: {actor}"));
    }

    msg.push_str(&format!("\n\n\u{2192} dbward request show {short_id}"));
    Some(msg)
}

/// Format approver DM text. Returns None if event type is not relevant.
pub fn format_approver_dm(event: &WebhookEvent) -> Option<String> {
    // Only send for request_created (not auto_approved, not break_glass)
    if event.event_type != "request_created" {
        return None;
    }

    let db = event.database.as_deref().unwrap_or("?");
    let env = event.environment.as_deref().unwrap_or("?");
    let requester = event.requester.as_deref().unwrap_or("someone");
    let req_id = event.request_id.as_deref().unwrap_or("?");
    let short_id = req_id.get(..8).unwrap_or(req_id);
    let op = event.operation.as_deref().unwrap_or("query");

    Some(format!(
        "\u{1f4cb} Approval needed\n\n\
         {requester} submitted a {op} on {db} ({env})\n\
         Request: {short_id}\n\n\
         \u{2192} dbward request approve {short_id}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event(event_type: &str) -> WebhookEvent {
        WebhookEvent {
            event_type: event_type.to_string(),
            request_id: Some("fea3b6f6-1234-5678-abcd-ef0123456789".to_string()),
            database: Some("app".to_string()),
            environment: Some("production".to_string()),
            actor: Some("alice".to_string()),
            requester: Some("bob".to_string()),
            operation: Some("execute_query".to_string()),
            detail: None,
            reason: None,
            redacted_detail: None,
            error_summary: None,
            approval_hint: None,
            step_index: None,
            total_steps: None,
            expires_at: None,
            approvers: Some(vec!["alice".to_string(), "carol".to_string()]),
        }
    }

    #[test]
    fn requester_dm_approved() {
        let msg = format_requester_dm(&sample_event("request_approved")).unwrap();
        assert!(msg.contains("approved"));
        assert!(msg.contains("app (production)"));
        assert!(msg.contains("fea3b6f6"));
        assert!(msg.contains("By: alice"));
    }

    #[test]
    fn requester_dm_ignores_created() {
        assert!(format_requester_dm(&sample_event("request_created")).is_none());
    }

    #[test]
    fn approver_dm_created() {
        let msg = format_approver_dm(&sample_event("request_created")).unwrap();
        assert!(msg.contains("Approval needed"));
        assert!(msg.contains("bob"));
        assert!(msg.contains("execute_query"));
    }

    #[test]
    fn approver_dm_ignores_auto_approved() {
        assert!(format_approver_dm(&sample_event("request_auto_approved")).is_none());
    }

    #[test]
    fn approver_dm_ignores_break_glass() {
        assert!(format_approver_dm(&sample_event("break_glass")).is_none());
    }
}
