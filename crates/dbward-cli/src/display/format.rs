use unicode_width::UnicodeWidthChar;
use unicode_width::UnicodeWidthStr;

pub(crate) fn truncate_table_cell(value: &str, max_width: usize) -> String {
    if display_width(value) <= max_width {
        return value.to_string();
    }
    if max_width <= 3 {
        return ".".repeat(max_width);
    }
    let target = max_width - 3;
    let mut width = 0;
    let mut end = 0;
    for (i, c) in value.char_indices() {
        let w = UnicodeWidthChar::width(c).unwrap_or(0);
        if width + w > target {
            break;
        }
        width += w;
        end = i + c.len_utf8();
    }
    format!("{}...", &value[..end])
}

pub(crate) fn display_width(value: &str) -> usize {
    UnicodeWidthStr::width(value)
}

pub(crate) fn pad_table_cell(value: &str, width: usize) -> String {
    let padding = width.saturating_sub(display_width(value));
    format!(" {value}{} ", " ".repeat(padding))
}

pub(crate) fn sanitize_table_cell(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            '\n' | '\r' | '\t' => ' ',
            _ => ch,
        })
        .collect()
}

pub(crate) fn short_request_id(id: &str) -> &str {
    &id[..id.len().min(8)]
}

pub(crate) fn format_created_time(created_at: &str) -> String {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(created_at) {
        return dt.format("%H:%M").to_string();
    }

    for format in [
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H:%M",
    ] {
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(created_at, format) {
            return dt.format("%H:%M").to_string();
        }
    }

    "?".to_string()
}

pub(crate) fn format_duration_ago(secs: i64) -> String {
    if secs < 60 {
        format!("{}s ago", secs)
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else {
        format!("{}h ago", secs / 3600)
    }
}

pub(crate) fn format_duration_short(secs: i64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86400)
    }
}

/// Collapse all whitespace (newlines, tabs, carriage returns, consecutive spaces) into a single space.
#[allow(dead_code)]
pub(crate) fn normalize_whitespace(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}
