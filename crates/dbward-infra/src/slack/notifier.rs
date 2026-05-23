use std::sync::Arc;

use dbward_app::ports::{ApprovalRepo, ContextRepo, Notifier, RequestReader, WebhookEvent};

use super::{SlackClient, SlackConfig, SlackMessageRepo, block_kit};

/// Outbound Slack notifier. Implements `Notifier` trait for use as
/// `CompositeEventDispatcher.request_notifier`.
#[derive(Clone)]
pub struct SlackNotifier {
    client: Arc<dyn SlackClient>,
    message_repo: Arc<dyn SlackMessageRepo>,
    context_repo: Arc<dyn ContextRepo>,
    request_reader: Arc<dyn RequestReader>,
    approval_repo: Arc<dyn ApprovalRepo>,
    config: SlackConfig,
}

impl SlackNotifier {
    pub fn new(
        client: Arc<dyn SlackClient>,
        message_repo: Arc<dyn SlackMessageRepo>,
        context_repo: Arc<dyn ContextRepo>,
        request_reader: Arc<dyn RequestReader>,
        approval_repo: Arc<dyn ApprovalRepo>,
        config: SlackConfig,
    ) -> Self {
        Self {
            client,
            message_repo,
            context_repo,
            request_reader,
            approval_repo,
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

        // Fetch context enrichment (best-effort)
        let context = event
            .request_id
            .as_deref()
            .and_then(|id| self.context_repo.get(id).ok().flatten());

        // Enrich event with formatted approvers from workflow snapshot
        let mut event = event.clone();
        if event.approvers.is_none()
            && let Some(ref req_id) = event.request_id
            && let Ok(Some(req)) = self.request_reader.get(req_id)
            && let Some(ref wf_json) = req.workflow_snapshot_json
        {
            let current_step = event.step_index.unwrap_or(0);
            if let Some(formatted) = block_kit::format_approvers_field(wf_json, current_step) {
                event.approvers = Some(vec![formatted]);
            }
        }

        let blocks = block_kit::build_request_created(&event, context.as_ref());
        let text = block_kit::fallback_text(&event);

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

        // PRIMARY: Update original message from canonical state
        if let Ok(Some(req)) = self.request_reader.get(request_id) {
            let workflow_json = req.workflow_snapshot_json.as_deref();
            let context = self.context_repo.get(request_id).ok().flatten();

            // Compute current_step from approvals
            let approvals = self
                .approval_repo
                .get_approvals(request_id)
                .unwrap_or_default();
            let current_step = workflow_json
                .and_then(|wj| {
                    serde_json::from_str::<dbward_domain::policies::workflow::Workflow>(wj).ok()
                })
                .map(|wf| {
                    dbward_domain::services::workflow_matcher::find_current_step(
                        &wf.steps, &approvals,
                    )
                })
                .unwrap_or(0);

            // Get reject reason from last rejection approval
            let reject_reason = approvals
                .iter()
                .rev()
                .find(|a| a.action == dbward_domain::entities::ApprovalAction::Reject)
                .and_then(|a| a.comment.clone());

            let updated_blocks = block_kit::build_message_from_state(
                &req,
                workflow_json,
                context.as_ref(),
                current_step,
                reject_reason.as_deref(),
            );
            let text = block_kit::fallback_text(event);
            if let Err(e) = self
                .client
                .update_message(
                    &msg_ref.channel,
                    &msg_ref.message_ts,
                    &updated_blocks,
                    &text,
                )
                .await
            {
                tracing::warn!(error = %e, "failed to update original slack message");
            }
        }

        // SECONDARY: Thread reply (always attempt, best-effort)
        let reply_blocks = block_kit::build_thread_reply(event);
        let reply_text = block_kit::fallback_text(event);
        if let Err(e) = self
            .client
            .post_thread(
                &msg_ref.channel,
                &msg_ref.message_ts,
                &reply_blocks,
                &reply_text,
            )
            .await
        {
            tracing::warn!(error = %e, "failed to post slack thread reply");
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
