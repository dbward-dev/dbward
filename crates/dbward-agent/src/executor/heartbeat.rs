use std::sync::Arc;
use std::time::Duration;

use tracing::warn;

use crate::cancel::CancelToken;
use crate::client::AgentClient;

/// Independent heartbeat component. Auto-aborts on drop.
pub(crate) struct HeartbeatTask {
    handle: tokio::task::JoinHandle<()>,
}

impl HeartbeatTask {
    pub fn spawn(
        client: Arc<AgentClient>,
        execution_id: String,
        cancel_token: CancelToken,
    ) -> Self {
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(2));
            interval.tick().await;
            loop {
                interval.tick().await;
                if cancel_token.is_cancelled() {
                    break;
                }
                match client.heartbeat(&execution_id).await {
                    Ok(resp) if resp.cancelled => {
                        warn!(execution_id = %execution_id, "cancellation requested by server");
                        cancel_token.trigger_cancel().await;
                        break;
                    }
                    Err(e) => warn!("heartbeat failed: {e}"),
                    _ => {}
                }
            }
        });
        Self { handle }
    }
}

impl Drop for HeartbeatTask {
    fn drop(&mut self) {
        self.handle.abort();
    }
}
