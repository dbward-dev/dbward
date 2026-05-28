use std::sync::Arc;

use dbward_app::ports::{
    ApprovalRepo, ContextRepo, Notifier, RequestReader, RoleResolver, WebhookEvent,
};

use super::{SlackClient, SlackConfig, SlackMessageRepo, SlackUserResolver, block_kit};

/// Outbound Slack notifier. Implements `Notifier` trait for use as
/// `CompositeEventDispatcher.request_notifier`.
#[derive(Clone)]
pub struct SlackNotifier {
    client: Arc<dyn SlackClient>,
    message_repo: Arc<dyn SlackMessageRepo>,
    context_repo: Arc<dyn ContextRepo>,
    request_reader: Arc<dyn RequestReader>,
    approval_repo: Arc<dyn ApprovalRepo>,
    user_resolver: Arc<SlackUserResolver>,
    role_resolver: Arc<dyn RoleResolver>,
    config: SlackConfig,
}

impl SlackNotifier {
    pub fn new(
        client: Arc<dyn SlackClient>,
        message_repo: Arc<dyn SlackMessageRepo>,
        context_repo: Arc<dyn ContextRepo>,
        request_reader: Arc<dyn RequestReader>,
        approval_repo: Arc<dyn ApprovalRepo>,
        user_resolver: Arc<SlackUserResolver>,
        role_resolver: Arc<dyn RoleResolver>,
        config: SlackConfig,
    ) -> Self {
        Self {
            client,
            message_repo,
            context_repo,
            request_reader,
            approval_repo,
            user_resolver,
            role_resolver,
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

        // Replace requester with mention format for Block Kit display
        if let Some(ref r) = event.requester {
            let mention = self.user_resolver.mention_for(r).await;
            event.requester = Some(mention);
        }

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

        // Enrich reason from request if not already set
        if event.reason.is_none()
            && let Some(ref req_id) = event.request_id
            && let Ok(Some(req)) = self.request_reader.get(req_id)
            && let Some(ref reason) = req.reason
            && !reason.is_empty()
        {
            event.reason = Some(reason.clone());
        }
        // Resolve approver mentions for notification
        let mention_suffix = self.resolve_approver_mentions(&event).await;

        let mut blocks = block_kit::build_request_created(&event, context.as_ref());
        // Add mention block so it's visible in the channel
        if !mention_suffix.is_empty() {
            blocks.push(serde_json::json!({
                "type": "section",
                "text": {"type": "mrkdwn", "text": mention_suffix}
            }));
        }
        let text = if mention_suffix.is_empty() {
            block_kit::fallback_text(&event)
        } else {
            format!("{} — {}", block_kit::fallback_text(&event), mention_suffix)
        };

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

            // Resolve requester mention for updated message
            let requester_mention = if let Some(ref r) = event.requester {
                Some(self.user_resolver.mention_for(r).await)
            } else {
                None
            };

            let updated_blocks = block_kit::build_message_from_state(
                &req,
                workflow_json,
                context.as_ref(),
                current_step,
                reject_reason.as_deref(),
                requester_mention.as_deref(),
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
        let mention_suffix = self.resolve_reply_mentions(event).await;
        let reply_blocks = block_kit::build_thread_reply(event, &mention_suffix);
        let reply_text = if mention_suffix.is_empty() {
            block_kit::fallback_text(event)
        } else {
            format!("{} — {}", block_kit::fallback_text(event), mention_suffix)
        };
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

    /// Resolve mentions for initial message (request_created/break_glass/auto_approved).
    /// Returns formatted lines like "📋 Requester: @xxx\n👉 Next Approver: @yyy"
    async fn resolve_approver_mentions(&self, event: &WebhookEvent) -> String {
        let mut lines = Vec::new();

        // Requester mention (already resolved to <@U...> by caller)
        if let Some(ref r) = event.requester {
            lines.push(format!("📋 Requester: {r}"));
        }

        if event.event_type == "request_auto_approved" {
            return lines.join("\n");
        }

        // Next approver mention
        let subjects = self.resolve_approver_subjects(event);
        if !subjects.is_empty() {
            let mentions = self.user_resolver.mentions_for(&subjects).await;
            lines.push(format!("👉 Next Approver: {}", mentions.join(" ")));
        }

        lines.join("\n")
    }

    /// Resolve mention target for thread replies.
    async fn resolve_reply_mentions(&self, event: &WebhookEvent) -> String {
        let actor = event.actor.as_deref().unwrap_or("");

        match event.event_type.as_str() {
            "step_approved" => {
                let subjects = self.resolve_next_step_subjects(event);
                if subjects.is_empty() {
                    return String::new();
                }
                let mentions = self.user_resolver.mentions_for(&subjects).await;
                format!("👉 Next Approver: {}", mentions.join(" "))
            }
            "request_approved" | "request_rejected" | "request_completed" | "request_failed"
            | "execution_lost" => {
                if let Some(ref r) = event.requester {
                    let mention = self.user_resolver.mention_for(r).await;
                    format!("📋 Requester: {mention}")
                } else {
                    String::new()
                }
            }
            "request_expired" => {
                let mut lines = Vec::new();
                if let Some(ref r) = event.requester {
                    let mention = self.user_resolver.mention_for(r).await;
                    lines.push(format!("📋 Requester: {mention}"));
                }
                let subjects = self.resolve_approver_subjects(event);
                if !subjects.is_empty() {
                    let mentions = self.user_resolver.mentions_for(&subjects).await;
                    lines.push(format!("👉 Approver: {}", mentions.join(" ")));
                }
                lines.join("\n")
            }
            "request_cancelled" => {
                let mut lines = Vec::new();
                if let Some(ref r) = event.requester
                    && r != actor
                {
                    let mention = self.user_resolver.mention_for(r).await;
                    lines.push(format!("📋 Requester: {mention}"));
                }
                let subjects: Vec<String> = self
                    .resolve_approver_subjects(event)
                    .into_iter()
                    .filter(|s| s != actor)
                    .collect();
                if !subjects.is_empty() {
                    let mentions = self.user_resolver.mentions_for(&subjects).await;
                    lines.push(format!("👉 Approver: {}", mentions.join(" ")));
                }
                lines.join("\n")
            }
            _ => String::new(),
        }
    }

    /// Extract subject_ids from workflow_snapshot approvers for current step.
    fn resolve_approver_subjects(&self, event: &WebhookEvent) -> Vec<String> {
        let req_id = match event.request_id.as_deref() {
            Some(id) => id,
            None => return vec![],
        };
        let req = match self.request_reader.get(req_id) {
            Ok(Some(r)) => r,
            Ok(None) => {
                tracing::debug!(req_id, "mention: request not found");
                return vec![];
            }
            Err(e) => {
                tracing::debug!(req_id, error = %e, "mention: failed to read request");
                return vec![];
            }
        };
        let wf_json = match req.workflow_snapshot_json.as_deref() {
            Some(j) => j,
            None => return vec![],
        };
        let step = event.step_index.unwrap_or(0);
        self.extract_subjects_from_step(wf_json, step)
    }

    /// Extract subjects for the NEXT step (after current approval).
    fn resolve_next_step_subjects(&self, event: &WebhookEvent) -> Vec<String> {
        let req_id = match event.request_id.as_deref() {
            Some(id) => id,
            None => return vec![],
        };
        let req = match self.request_reader.get(req_id) {
            Ok(Some(r)) => r,
            _ => return vec![],
        };
        let wf_json = match req.workflow_snapshot_json.as_deref() {
            Some(j) => j,
            None => return vec![],
        };
        let next_step = event.step_index.unwrap_or(0) + 1;
        self.extract_subjects_from_step(wf_json, next_step)
    }

    /// Parse workflow JSON and resolve selectors for a given step index.
    fn extract_subjects_from_step(&self, wf_json: &str, step_index: u32) -> Vec<String> {
        let wf: serde_json::Value = match serde_json::from_str(wf_json) {
            Ok(v) => v,
            Err(_) => return vec![],
        };
        let steps = match wf["steps"].as_array() {
            Some(s) => s,
            None => return vec![],
        };
        let step = match steps.get(step_index as usize) {
            Some(s) => s,
            None => return vec![],
        };
        let approvers = match step["approvers"].as_array() {
            Some(a) => a,
            None => return vec![],
        };

        let mut subjects = std::collections::HashSet::new();
        for approver in approvers {
            let selector = approver["selector"].as_str().unwrap_or("");
            if let Some(user) = selector.strip_prefix("user:") {
                subjects.insert(user.to_string());
            } else if let Some(role) = selector.strip_prefix("role:") {
                for s in self.role_resolver.subjects_for_role(role) {
                    subjects.insert(s);
                }
            } else if let Some(group) = selector.strip_prefix("group:") {
                for s in self
                    .role_resolver
                    .subjects_for_selector(&format!("group:{group}"))
                {
                    subjects.insert(s);
                }
            }
        }
        subjects.into_iter().collect()
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
