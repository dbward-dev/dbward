use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};
use tokio::sync::oneshot;

use dbward_mcp::ports::{ElicitResult, ElicitationTransport};

use crate::session::{SessionRuntime, StreamRuntime, PHASE_ACTIVE};

/// HTTP-based elicitation transport. Emits elicitation request on SSE,
/// waits for client to respond via separate POST with matching id.
pub struct HttpElicitation {
    session: Arc<SessionRuntime>,
    stream_rt: Arc<StreamRuntime>,
    timeout_secs: u64,
}

impl HttpElicitation {
    pub fn new(session: Arc<SessionRuntime>, stream_rt: Arc<StreamRuntime>, timeout_secs: u64) -> Self {
        Self { session, stream_rt, timeout_secs }
    }
}

#[async_trait]
impl ElicitationTransport for HttpElicitation {
    fn supported(&self) -> bool {
        self.session.phase.load(Ordering::Relaxed) == PHASE_ACTIVE
            && self.session.client_supports_elicitation.load(Ordering::Relaxed)
    }

    async fn ask(&self, message: &str, schema: Value) -> Result<ElicitResult, String> {
        let seq = self.session.elicit_id_counter.fetch_add(1, Ordering::Relaxed);
        let elicit_id = format!("elicit-{seq}");

        // Register oneshot waiter
        let (tx, rx) = oneshot::channel();
        self.session.pending_elicitations.insert(elicit_id.clone(), tx);

        // Emit elicitation request as SSE event
        let raw = json!({
            "jsonrpc": "2.0",
            "id": elicit_id,
            "method": "elicitation/create",
            "params": {"message": message, "requestedSchema": schema}
        });
        self.stream_rt.emit_raw(&serde_json::to_string(&raw).unwrap()).await;

        // Wait with timeout
        match tokio::time::timeout(Duration::from_secs(self.timeout_secs), rx).await {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(_)) => Ok(ElicitResult::Cancel), // sender dropped (session closed)
            Err(_) => {
                // Timeout — remove the pending waiter
                self.session.pending_elicitations.remove(&elicit_id);
                Ok(ElicitResult::Cancel)
            }
        }
    }
}
