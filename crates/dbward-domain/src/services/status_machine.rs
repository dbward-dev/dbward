use chrono::{DateTime, Utc};

use crate::auth::SubjectType;
use crate::entities::RequestStatus;
use crate::values::{DatabaseName, Environment, Operation};

/// Triggers that cause state transitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestTrigger {
    Create {
        emergency: bool,
        needs_approval: bool,
    },
    ApproveStep,
    ApproveFinal,
    Reject,
    Cancel,
    Dispatch,
    Claim,
    Complete {
        success: bool,
    },
    LeaseExpired,
    Expire,
    DispatchTimeout,
}

/// Metadata attached to a transition event.
#[derive(Debug, Clone)]
pub enum EventMetadata {
    Created {
        detail: String,
        emergency: bool,
    },
    StepApproved {
        step_index: u32,
        total_steps: u32,
        comment: Option<String>,
    },
    Approved {
        comment: Option<String>,
    },
    Rejected {
        comment: Option<String>,
    },
    Cancelled {
        reason: Option<String>,
    },
    Dispatched,
    Claimed {
        execution_id: String,
        agent_id: String,
    },
    Completed {
        success: bool,
        execution_id: String,
    },
    ExecutionLost {
        execution_id: String,
    },
    Expired,
}

/// Context needed to build a TransitionEvent.
#[derive(Debug, Clone)]
pub struct TransitionContext {
    pub request_id: String,
    pub actor_id: String,
    pub actor_type: SubjectType,
    pub database: DatabaseName,
    pub environment: Environment,
    pub operation: Operation,
    pub timestamp: DateTime<Utc>,
    pub metadata: EventMetadata,
    pub requester_id: String,
    pub audit_context: crate::entities::AuditContext,
}

/// Event emitted after a successful state transition.
#[derive(Debug, Clone)]
pub struct TransitionEvent {
    pub request_id: String,
    pub previous_status: RequestStatus,
    pub new_status: RequestStatus,
    pub actor_id: String,
    pub actor_type: SubjectType,
    pub database: DatabaseName,
    pub environment: Environment,
    pub operation: Operation,
    pub timestamp: DateTime<Utc>,
    pub metadata: EventMetadata,
    pub requester_id: String,
    pub audit_context: crate::entities::AuditContext,
}

/// Result of a state transition. Must be committed via .commit().
#[must_use = "TransitionResult must be consumed via .into_event()"]
pub struct TransitionResult {
    pub new_status: RequestStatus,
    event: TransitionEvent,
}

impl TransitionResult {
    /// Consume self and return the event for manual handling (e.g., UoW pattern).
    pub fn into_event(self) -> TransitionEvent {
        self.event
    }

    pub fn status(&self) -> RequestStatus {
        self.new_status
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid transition: {current} + {trigger:?}")]
pub struct InvalidTransition {
    pub current: RequestStatus,
    pub trigger: RequestTrigger,
}

/// Pure state transition function.
/// Returns TransitionResult containing new status + event to dispatch.
pub fn transition(
    current: RequestStatus,
    trigger: &RequestTrigger,
    context: TransitionContext,
) -> Result<TransitionResult, InvalidTransition> {
    let new_status = compute_next_status(current, trigger)?;

    let event = TransitionEvent {
        request_id: context.request_id,
        previous_status: current,
        new_status,
        actor_id: context.actor_id,
        actor_type: context.actor_type,
        database: context.database,
        environment: context.environment,
        operation: context.operation,
        timestamp: context.timestamp,
        metadata: context.metadata,
        requester_id: context.requester_id,
        audit_context: context.audit_context,
    };

    Ok(TransitionResult { new_status, event })
}

/// Determine initial status for a new request.
pub fn initial_status(needs_approval: bool, emergency: bool) -> RequestStatus {
    match (needs_approval, emergency) {
        (_, true) => RequestStatus::BreakGlass,
        (true, false) => RequestStatus::Pending,
        (false, false) => RequestStatus::AutoApproved,
    }
}

/// Build a TransitionResult for request creation (no previous state).
pub fn create_event(new_status: RequestStatus, context: TransitionContext) -> TransitionResult {
    let event = TransitionEvent {
        request_id: context.request_id,
        previous_status: new_status, // no previous state; use self
        new_status,
        actor_id: context.actor_id,
        actor_type: context.actor_type,
        database: context.database,
        environment: context.environment,
        operation: context.operation,
        timestamp: context.timestamp,
        metadata: context.metadata,
        requester_id: context.requester_id,
        audit_context: context.audit_context,
    };
    TransitionResult { new_status, event }
}

/// Internal: compute next status from current + trigger.
fn compute_next_status(
    current: RequestStatus,
    trigger: &RequestTrigger,
) -> Result<RequestStatus, InvalidTransition> {
    use RequestStatus::*;
    use RequestTrigger::*;

    let next = match (current, trigger) {
        // Approval flow
        (Pending, ApproveStep) => Pending,
        (Pending, ApproveFinal) => Approved,
        (Pending, Reject) => Rejected,

        // Expiration
        (Pending, Expire) => Expired,
        (Approved, Expire) => Expired,

        // Cancel from any non-terminal state (including running — ADR-003)
        (s, Cancel) if s.is_cancellable() => Cancelled,

        // Dispatch (initial or re-dispatch)
        (Approved, Dispatch) => Dispatched,
        (AutoApproved, Dispatch) => Dispatched,
        (BreakGlass, Dispatch) => Dispatched,
        (Executed, Dispatch) => Dispatched,
        (Failed, Dispatch) => Dispatched,
        (ExecutionLost, Dispatch) => Dispatched,

        // Dispatch timeout
        (Dispatched, DispatchTimeout) => Approved,

        // Agent lifecycle
        (Dispatched, Claim) => Running,
        (Running, Complete { success: true }) => Executed,
        (Running, Complete { success: false }) => Failed,
        (Running, LeaseExpired) => ExecutionLost,

        // Cancelled request accepts completion (ADR-003/004)
        (Cancelled, Complete { .. }) => Cancelled,

        // Late completion: agent reports result after lease expired
        (ExecutionLost, Complete { success: true }) => Executed,
        (ExecutionLost, Complete { success: false }) => Failed,

        _ => {
            return Err(InvalidTransition {
                current,
                trigger: trigger.clone(),
            });
        }
    };

    Ok(next)
}

// --- Legacy API (for gradual migration) ---

/// Legacy event type (used by existing use_cases during migration).
#[cfg(test)]
mod tests {
    use super::*;
    use RequestStatus::*;
    use RequestTrigger::*;

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
    fn approve_step_stays_pending() {
        assert_eq!(compute_next_status(Pending, &ApproveStep).unwrap(), Pending);
    }

    #[test]
    fn approve_final_to_approved() {
        assert_eq!(
            compute_next_status(Pending, &ApproveFinal).unwrap(),
            Approved
        );
    }

    #[test]
    fn reject_pending() {
        assert_eq!(compute_next_status(Pending, &Reject).unwrap(), Rejected);
    }

    #[test]
    fn dispatch_approved() {
        assert_eq!(
            compute_next_status(Approved, &Dispatch).unwrap(),
            Dispatched
        );
    }

    #[test]
    fn dispatch_auto_approved() {
        assert_eq!(
            compute_next_status(AutoApproved, &Dispatch).unwrap(),
            Dispatched
        );
    }

    #[test]
    fn dispatch_break_glass() {
        assert_eq!(
            compute_next_status(BreakGlass, &Dispatch).unwrap(),
            Dispatched
        );
    }

    #[test]
    fn claim_dispatched() {
        assert_eq!(compute_next_status(Dispatched, &Claim).unwrap(), Running);
    }

    #[test]
    fn complete_success() {
        assert_eq!(
            compute_next_status(Running, &Complete { success: true }).unwrap(),
            Executed
        );
    }

    #[test]
    fn complete_failure() {
        assert_eq!(
            compute_next_status(Running, &Complete { success: false }).unwrap(),
            Failed
        );
    }

    #[test]
    fn cancelled_accepts_complete() {
        assert_eq!(
            compute_next_status(Cancelled, &Complete { success: false }).unwrap(),
            Cancelled
        );
        assert_eq!(
            compute_next_status(Cancelled, &Complete { success: true }).unwrap(),
            Cancelled
        );
    }

    #[test]
    fn lease_expired() {
        assert_eq!(
            compute_next_status(Running, &LeaseExpired).unwrap(),
            ExecutionLost
        );
    }

    #[test]
    fn redispatch_executed() {
        assert_eq!(
            compute_next_status(Executed, &Dispatch).unwrap(),
            Dispatched
        );
    }

    #[test]
    fn cancel_pending() {
        assert_eq!(compute_next_status(Pending, &Cancel).unwrap(), Cancelled);
    }

    #[test]
    fn cancel_running() {
        assert_eq!(compute_next_status(Running, &Cancel).unwrap(), Cancelled);
    }

    #[test]
    fn cannot_cancel_executed() {
        assert!(compute_next_status(Executed, &Cancel).is_err());
    }

    #[test]
    fn cannot_dispatch_pending() {
        assert!(compute_next_status(Pending, &Dispatch).is_err());
    }

    #[test]
    fn expire_pending() {
        assert_eq!(compute_next_status(Pending, &Expire).unwrap(), Expired);
    }

    #[test]
    fn expire_approved() {
        assert_eq!(compute_next_status(Approved, &Expire).unwrap(), Expired);
    }

    #[test]
    fn dispatch_timeout() {
        assert_eq!(
            compute_next_status(Dispatched, &DispatchTimeout).unwrap(),
            Approved
        );
    }

    #[test]
    fn execution_lost_accepts_late_completion() {
        assert_eq!(
            compute_next_status(ExecutionLost, &Complete { success: true }).unwrap(),
            Executed
        );
        assert_eq!(
            compute_next_status(ExecutionLost, &Complete { success: false }).unwrap(),
            Failed
        );
    }
}
