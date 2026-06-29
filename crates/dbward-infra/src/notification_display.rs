/// Shared event_type → (emoji, title) mapping for Slack notifications.
/// Used by both webhook dispatcher (format="slack") and SlackNotifier (interactive).
pub fn event_display(event_type: &str) -> (&'static str, &'static str) {
    match event_type {
        "request.created" => ("📋", "New Approval Request"),
        "request.break_glass" => ("🚨", "Break-Glass Request"),
        "request.auto_approved" => ("⚡", "Auto-Approved"),
        "step.approved" => ("☑️", "Step Approved"),
        "request.approved" => ("✅", "Request Approved"),
        "request.rejected" => ("❌", "Rejected"),
        "execution.completed" => ("🎉", "Completed"),
        "execution.failed" => ("⚠️", "Execution Failed"),
        "request.expired" => ("⏰", "Expired"),
        "request.cancelled" => ("🚫", "Cancelled"),
        "execution.lost" => ("💀", "Execution Lost"),
        "request.dispatch_timeout" => ("🔄", "Dispatch Timeout"),
        "license_grace_warning" => ("⚠️", "License Grace Warning"),
        "license_downgraded" => ("🔒", "License Downgraded"),
        _ => ("🔔", "Notification"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_display_covers_all_event_types() {
        let cases = [
            ("request.created", "📋", "New Approval Request"),
            ("request.break_glass", "🚨", "Break-Glass Request"),
            ("request.auto_approved", "⚡", "Auto-Approved"),
            ("step.approved", "☑️", "Step Approved"),
            ("request.approved", "✅", "Request Approved"),
            ("request.rejected", "❌", "Rejected"),
            ("execution.completed", "🎉", "Completed"),
            ("execution.failed", "⚠️", "Execution Failed"),
            ("request.expired", "⏰", "Expired"),
            ("request.cancelled", "🚫", "Cancelled"),
            ("execution.lost", "💀", "Execution Lost"),
            ("request.dispatch_timeout", "🔄", "Dispatch Timeout"),
            ("license_grace_warning", "⚠️", "License Grace Warning"),
            ("license_downgraded", "🔒", "License Downgraded"),
        ];
        for (event_type, expected_emoji, expected_title) in cases {
            let (emoji, title) = event_display(event_type);
            assert_eq!(emoji, expected_emoji, "emoji mismatch for {event_type}");
            assert_eq!(title, expected_title, "title mismatch for {event_type}");
        }
    }

    #[test]
    fn unknown_event_type_returns_default() {
        let (emoji, title) = event_display("unknown_event");
        assert_eq!(emoji, "🔔");
        assert_eq!(title, "Notification");
    }
}
