use serde::{Deserialize, Serialize};

/// All possible request statuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestStatus {
    Pending,
    Approved,
    AutoApproved,
    BreakGlass,
    Dispatched,
    Running,
    Executed,
    Failed,
    Rejected,
    Cancelled,
    ExecutionLost,
}

impl RequestStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::AutoApproved => "auto_approved",
            Self::BreakGlass => "break_glass",
            Self::Dispatched => "dispatched",
            Self::Running => "running",
            Self::Executed => "executed",
            Self::Failed => "failed",
            Self::Rejected => "rejected",
            Self::Cancelled => "cancelled",
            Self::ExecutionLost => "execution_lost",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "approved" => Some(Self::Approved),
            "auto_approved" => Some(Self::AutoApproved),
            "break_glass" => Some(Self::BreakGlass),
            "dispatched" => Some(Self::Dispatched),
            "running" => Some(Self::Running),
            "executed" => Some(Self::Executed),
            "failed" => Some(Self::Failed),
            "rejected" => Some(Self::Rejected),
            "cancelled" => Some(Self::Cancelled),
            "execution_lost" => Some(Self::ExecutionLost),
            _ => None,
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Rejected | Self::Cancelled)
    }

    pub fn is_dispatchable(&self) -> bool {
        matches!(
            self,
            Self::Approved
                | Self::AutoApproved
                | Self::BreakGlass
                | Self::Executed
                | Self::Failed
                | Self::ExecutionLost
        )
    }

    pub fn is_expirable(&self) -> bool {
        matches!(self, Self::Approved | Self::AutoApproved | Self::BreakGlass)
    }

    pub fn is_cancellable(&self) -> bool {
        !matches!(
            self,
            Self::Executed | Self::Failed | Self::Rejected | Self::Cancelled
        )
    }

    pub fn is_waiting(&self) -> bool {
        matches!(
            self,
            Self::Pending | Self::Approved | Self::Dispatched | Self::Running
        )
    }
}

impl std::fmt::Display for RequestStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Determine initial status for a new request.
pub fn initial_status(needs_approval: bool, emergency: bool) -> RequestStatus {
    match (needs_approval, emergency) {
        (_, true) => RequestStatus::BreakGlass,
        (true, false) => RequestStatus::Pending,
        (false, false) => RequestStatus::AutoApproved,
    }
}

/// Events that trigger state transitions.
#[derive(Debug, Clone)]
pub enum RequestEvent {
    Approve,
    Reject,
    Cancel,
    Dispatch,
    Claim,
    Complete { success: bool },
    LeaseExpired,
}

#[derive(Debug, thiserror::Error)]
#[error("invalid transition: {current} + {event}")]
pub struct InvalidTransition {
    pub current: RequestStatus,
    pub event: String,
}

/// Pure state transition function. No side effects.
/// Precondition checks (TTL, execution policy) are the caller's responsibility.
pub fn transition(
    current: RequestStatus,
    event: &RequestEvent,
) -> Result<RequestStatus, InvalidTransition> {
    use RequestEvent::*;
    use RequestStatus::*;

    let next = match (current, event) {
        (Pending, Approve) => Approved,
        (Pending, Reject) => Rejected,
        (s, Cancel) if s.is_cancellable() => Cancelled,
        (s, Dispatch) if s.is_dispatchable() => Dispatched,
        (Dispatched, Dispatch) => Dispatched, // idempotent
        (Dispatched, Claim) => Running,
        (Running, Complete { success: true }) => Executed,
        (Running, Complete { success: false }) => Failed,
        (Running, LeaseExpired) => ExecutionLost,
        _ => {
            return Err(InvalidTransition {
                current,
                event: format!("{event:?}"),
            });
        }
    };

    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_pending() {
        assert_eq!(initial_status(true, false), RequestStatus::Pending);
    }

    #[test]
    fn initial_auto_approved() {
        assert_eq!(initial_status(false, false), RequestStatus::AutoApproved);
    }

    #[test]
    fn initial_break_glass() {
        assert_eq!(initial_status(true, true), RequestStatus::BreakGlass);
    }

    #[test]
    fn approve_to_approved() {
        assert_eq!(
            transition(RequestStatus::Pending, &RequestEvent::Approve).unwrap(),
            RequestStatus::Approved
        );
    }

    #[test]
    fn dispatch_approved() {
        assert_eq!(
            transition(RequestStatus::Approved, &RequestEvent::Dispatch).unwrap(),
            RequestStatus::Dispatched
        );
    }

    #[test]
    fn dispatch_auto_approved() {
        assert_eq!(
            transition(RequestStatus::AutoApproved, &RequestEvent::Dispatch).unwrap(),
            RequestStatus::Dispatched
        );
    }

    #[test]
    fn dispatch_idempotent() {
        assert_eq!(
            transition(RequestStatus::Dispatched, &RequestEvent::Dispatch).unwrap(),
            RequestStatus::Dispatched
        );
    }

    #[test]
    fn claim() {
        assert_eq!(
            transition(RequestStatus::Dispatched, &RequestEvent::Claim).unwrap(),
            RequestStatus::Running
        );
    }

    #[test]
    fn complete_success() {
        assert_eq!(
            transition(
                RequestStatus::Running,
                &RequestEvent::Complete { success: true }
            )
            .unwrap(),
            RequestStatus::Executed
        );
    }

    #[test]
    fn complete_failure() {
        assert_eq!(
            transition(
                RequestStatus::Running,
                &RequestEvent::Complete { success: false }
            )
            .unwrap(),
            RequestStatus::Failed
        );
    }

    #[test]
    fn lease_expired() {
        assert_eq!(
            transition(RequestStatus::Running, &RequestEvent::LeaseExpired).unwrap(),
            RequestStatus::ExecutionLost
        );
    }

    #[test]
    fn reject_pending() {
        assert_eq!(
            transition(RequestStatus::Pending, &RequestEvent::Reject).unwrap(),
            RequestStatus::Rejected
        );
    }

    #[test]
    fn cancel_running() {
        assert_eq!(
            transition(RequestStatus::Running, &RequestEvent::Cancel).unwrap(),
            RequestStatus::Cancelled
        );
    }

    #[test]
    fn cancel_pending() {
        assert_eq!(
            transition(RequestStatus::Pending, &RequestEvent::Cancel).unwrap(),
            RequestStatus::Cancelled
        );
    }

    #[test]
    fn cannot_cancel_executed() {
        assert!(transition(RequestStatus::Executed, &RequestEvent::Cancel).is_err());
    }

    #[test]
    fn cannot_approve_dispatched() {
        assert!(transition(RequestStatus::Dispatched, &RequestEvent::Approve).is_err());
    }

    #[test]
    fn cannot_dispatch_pending() {
        assert!(transition(RequestStatus::Pending, &RequestEvent::Dispatch).is_err());
    }

    #[test]
    fn redispatch_executed() {
        assert_eq!(
            transition(RequestStatus::Executed, &RequestEvent::Dispatch).unwrap(),
            RequestStatus::Dispatched
        );
    }

    #[test]
    fn redispatch_execution_lost() {
        assert_eq!(
            transition(RequestStatus::ExecutionLost, &RequestEvent::Dispatch).unwrap(),
            RequestStatus::Dispatched
        );
    }

    #[test]
    fn serde_roundtrip() {
        let s = RequestStatus::AutoApproved;
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, "\"auto_approved\"");
        let parsed: RequestStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, s);
    }

    #[test]
    fn parse_all() {
        for s in [
            "pending",
            "approved",
            "auto_approved",
            "break_glass",
            "dispatched",
            "running",
            "executed",
            "failed",
            "rejected",
            "cancelled",
            "execution_lost",
        ] {
            assert_eq!(RequestStatus::parse(s).unwrap().as_str(), s);
        }
    }
}
