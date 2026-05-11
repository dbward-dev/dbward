use crate::entities::RequestStatus;

/// Events that trigger state transitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestEvent {
    Approve,
    Reject,
    Cancel,
    Dispatch,
    Claim,
    Complete { success: bool },
    LeaseExpired,
    Expire,
    DispatchTimeout,
}

#[derive(Debug, thiserror::Error)]
#[error("invalid transition: {current} + {event:?}")]
pub struct InvalidTransition {
    pub current: RequestStatus,
    pub event: RequestEvent,
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
        // Approval flow
        (Pending, Approve) => Approved,
        (Pending, Reject) => Rejected,

        // Expiration
        (Pending, Expire) => Expired,
        (Approved, Expire) => Expired,
        (AutoApproved, Expire) => Expired,
        (BreakGlass, Expire) => Expired,

        // Cancel from any non-terminal state
        (s, Cancel) if s.is_cancellable() => Cancelled,

        // Dispatch (initial or re-dispatch)
        (Approved, Dispatch) => Dispatched,
        (AutoApproved, Dispatch) => Dispatched,
        (BreakGlass, Dispatch) => Dispatched,
        (Executed, Dispatch) => Dispatched,
        (Failed, Dispatch) => Dispatched,
        (ExecutionLost, Dispatch) => Dispatched,

        // Dispatch timeout: dispatched → approved (no agent claimed)
        (Dispatched, DispatchTimeout) => Approved,

        // Agent lifecycle
        (Dispatched, Claim) => Running,
        (Running, Complete { success: true }) => Executed,
        (Running, Complete { success: false }) => Failed,
        (Running, LeaseExpired) => ExecutionLost,

        _ => {
            return Err(InvalidTransition {
                current,
                event: event.clone(),
            });
        }
    };

    Ok(next)
}

/// Determine initial status for a new request.
pub fn initial_status(needs_approval: bool, emergency: bool) -> RequestStatus {
    match (needs_approval, emergency) {
        (_, true) => RequestStatus::BreakGlass,
        (true, false) => RequestStatus::Pending,
        (false, false) => RequestStatus::AutoApproved,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use RequestEvent::*;
    use RequestStatus::*;

    #[test]
    fn initial_pending() {
        assert_eq!(initial_status(true, false), Pending);
    }

    #[test]
    fn initial_auto_approved() {
        assert_eq!(initial_status(false, false), AutoApproved);
    }

    #[test]
    fn initial_break_glass() {
        assert_eq!(initial_status(true, true), BreakGlass);
    }

    #[test]
    fn approve_pending() {
        assert_eq!(transition(Pending, &Approve).unwrap(), Approved);
    }

    #[test]
    fn reject_pending() {
        assert_eq!(transition(Pending, &Reject).unwrap(), Rejected);
    }

    #[test]
    fn dispatch_approved() {
        assert_eq!(transition(Approved, &Dispatch).unwrap(), Dispatched);
    }

    #[test]
    fn dispatch_auto_approved() {
        assert_eq!(transition(AutoApproved, &Dispatch).unwrap(), Dispatched);
    }

    #[test]
    fn dispatch_break_glass() {
        assert_eq!(transition(BreakGlass, &Dispatch).unwrap(), Dispatched);
    }

    #[test]
    fn claim_dispatched() {
        assert_eq!(transition(Dispatched, &Claim).unwrap(), Running);
    }

    #[test]
    fn complete_success() {
        assert_eq!(
            transition(Running, &Complete { success: true }).unwrap(),
            Executed
        );
    }

    #[test]
    fn complete_failure() {
        assert_eq!(
            transition(Running, &Complete { success: false }).unwrap(),
            Failed
        );
    }

    #[test]
    fn lease_expired() {
        assert_eq!(transition(Running, &LeaseExpired).unwrap(), ExecutionLost);
    }

    #[test]
    fn redispatch_executed() {
        assert_eq!(transition(Executed, &Dispatch).unwrap(), Dispatched);
    }

    #[test]
    fn redispatch_failed() {
        assert_eq!(transition(Failed, &Dispatch).unwrap(), Dispatched);
    }

    #[test]
    fn redispatch_execution_lost() {
        assert_eq!(transition(ExecutionLost, &Dispatch).unwrap(), Dispatched);
    }

    #[test]
    fn cancel_pending() {
        assert_eq!(transition(Pending, &Cancel).unwrap(), Cancelled);
    }

    #[test]
    fn cancel_running() {
        assert_eq!(transition(Running, &Cancel).unwrap(), Cancelled);
    }

    #[test]
    fn cancel_execution_lost() {
        assert_eq!(transition(ExecutionLost, &Cancel).unwrap(), Cancelled);
    }

    #[test]
    fn cannot_cancel_executed() {
        assert!(transition(Executed, &Cancel).is_err());
    }

    #[test]
    fn cannot_cancel_rejected() {
        assert!(transition(Rejected, &Cancel).is_err());
    }

    #[test]
    fn cannot_approve_dispatched() {
        assert!(transition(Dispatched, &Approve).is_err());
    }

    #[test]
    fn cannot_dispatch_pending() {
        assert!(transition(Pending, &Dispatch).is_err());
    }

    #[test]
    fn expire_pending() {
        assert_eq!(transition(Pending, &Expire).unwrap(), Expired);
    }

    #[test]
    fn expire_approved() {
        assert_eq!(transition(Approved, &Expire).unwrap(), Expired);
    }

    #[test]
    fn dispatch_timeout_returns_to_approved() {
        assert_eq!(transition(Dispatched, &DispatchTimeout).unwrap(), Approved);
    }
}
