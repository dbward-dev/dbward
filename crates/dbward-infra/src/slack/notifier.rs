use std::sync::Arc;

use dbward_app::ports::{Notifier, WebhookEvent};

use super::{SlackClient, SlackConfig, SlackMessageRepo, block_kit};

/// Outbound Slack notifier. Implements `Notifier` trait for use as
/// `CompositeEventDispatcher.request_notifier`.
#[derive(Clone)]
pub struct SlackNotifier {
    client: Arc<dyn SlackClient>,
    message_repo: Arc<dyn SlackMessageRepo>,
    config: SlackConfig,
}

impl SlackNotifier {
    pub fn new(
        client: Arc<dyn SlackClient>,
        message_repo: Arc<dyn SlackMessageRepo>,
        config: SlackConfig,
    ) -> Self {
        Self {
            client,
            message_repo,
            config,
        }
    }

    fn should_notify(event: &WebhookEvent) -> bool {
        !matches!(
            event.event_type.as_str(),
            "request_dispatched" | "execution_started"
        )
    }

    async fn handle_event(&self, event: WebhookEvent) {
        match event.event_type.as_str() {
            "request_created" | "break_glass" | "request_auto_approved" => {
                self.send_initial_message(&event).await;
            }
            _ => {
                self.send_thread_reply(&event).await;
            }
        }
    }

    async fn send_initial_message(&self, event: &WebhookEvent) {
        let env = event.environment.as_deref().unwrap_or("default");
        let channel = self.config.channel_for_env(env);
        let blocks = block_kit::build_request_created(event);
        let text = block_kit::fallback_text(event);

        match self.client.post_message(channel, &blocks, &text).await {
            Ok(ts) => {
                if let Some(ref req_id) = event.request_id
                    && let Err(e) = self.message_repo.save(req_id, channel, &ts)
                {
                    tracing::warn!(error = %e, "failed to save slack message ref");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to send slack message");
            }
        }
    }

    async fn send_thread_reply(&self, event: &WebhookEvent) {
        let request_id = match event.request_id.as_deref() {
            Some(id) => id,
            None => return,
        };

        // Retry to get message_ts (handles race with initial send)
        let msg_ref = self.get_message_ref_with_retry(request_id).await;
        let msg_ref = match msg_ref {
            Some(r) => r,
            None => {
                tracing::warn!(request_id, "skipping thread reply: root message not found");
                return;
            }
        };

        let blocks = block_kit::build_thread_reply(event);
        let text = block_kit::fallback_text(event);

        if let Err(e) = self
            .client
            .post_thread(&msg_ref.channel, &msg_ref.message_ts, &blocks, &text)
            .await
        {
            tracing::warn!(error = %e, "failed to post thread reply");
        }

        // Update original message for terminal events (remove buttons)
        if matches!(
            event.event_type.as_str(),
            "request_approved" | "request_rejected" | "request_expired" | "request_cancelled"
        ) {
            let updated_blocks =
                block_kit::build_resolved_message(event, &block_kit::build_request_created(event));
            let _ = self
                .client
                .update_message(
                    &msg_ref.channel,
                    &msg_ref.message_ts,
                    &updated_blocks,
                    &text,
                )
                .await;
        }
    }

    async fn get_message_ref_with_retry(&self, request_id: &str) -> Option<super::SlackMessageRef> {
        for attempt in 0..3 {
            if let Ok(Some(r)) = self.message_repo.get(request_id) {
                return Some(r);
            }
            if attempt < 2 {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        }
        None
    }
}

impl Notifier for SlackNotifier {
    fn dispatch(&self, event: WebhookEvent) {
        if !Self::should_notify(&event) {
            return;
        }
        let this = self.clone();
        tokio::spawn(async move {
            this.handle_event(event).await;
        });
    }
}
