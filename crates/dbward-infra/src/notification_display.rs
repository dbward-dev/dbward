/// Shared event_type → (emoji, title) mapping for Slack notifications.
/// Used by both webhook dispatcher (format="slack") and SlackNotifier (interactive).
pub fn event_display(event_type: &str) -> (&'static str, &'static str) {
    match event_type {
        "request_created" => ("📋", "New Approval Request"),
        "break_glass" => ("🚨", "Break-Glass Request"),
        "request_auto_approved" => ("⚡", "Auto-Approved"),
        "step_approved" => ("☑️", "Step Approved"),
        "request_approved" => ("✅", "Request Approved"),
        "request_rejected" => ("❌", "Rejected"),
        "request_completed" => ("🎉", "Completed"),
        "request_failed" => ("⚠️", "Execution Failed"),
        "request_expired" => ("⏰", "Expired"),
        "request_cancelled" => ("🚫", "Cancelled"),
        "execution_lost" => ("💀", "Execution Lost"),
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
            ("request_created", "📋", "New Approval Request"),
            ("break_glass", "🚨", "Break-Glass Request"),
            ("request_auto_approved", "⚡", "Auto-Approved"),
            ("step_approved", "☑️", "Step Approved"),
            ("request_approved", "✅", "Request Approved"),
            ("request_rejected", "❌", "Rejected"),
            ("request_completed", "🎉", "Completed"),
            ("request_failed", "⚠️", "Execution Failed"),
            ("request_expired", "⏰", "Expired"),
            ("request_cancelled", "🚫", "Cancelled"),
            ("execution_lost", "💀", "Execution Lost"),
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
