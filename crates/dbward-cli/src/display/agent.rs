use super::format::{format_duration_ago, format_duration_short};

pub(crate) fn print_agents_status(body: &serde_json::Value) {
    let agents = match body["agents"].as_array() {
        Some(a) => a,
        None => {
            eprintln!("No agents registered.");
            return;
        }
    };
    if agents.is_empty() {
        eprintln!("No agents registered.");
        return;
    }

    println!(
        "{:<20} {:<10} {:<7} {:<12} {:<10}",
        "AGENT", "STATUS", "LOAD", "LAST SEEN", "UPTIME"
    );
    for a in agents {
        let id = a["id"].as_str().unwrap_or("?");
        let status = a["status"].as_str().unwrap_or("?");
        let in_flight = a["in_flight"].as_i64().unwrap_or(0);
        let max_concurrent = a["max_concurrent"].as_i64().unwrap_or(1);
        let ago = a["last_poll_ago_secs"].as_i64().unwrap_or(9999);
        let uptime = a["uptime_secs"].as_i64().unwrap_or(0);

        let load = format!("{}/{}", in_flight, max_concurrent);
        let last_seen = format_duration_ago(ago);
        let uptime_str = format_duration_short(uptime);

        println!(
            "{:<20} {:<10} {:<7} {:<12} {:<10}",
            id, status, load, last_seen, uptime_str
        );
    }

    // Print active jobs if any
    let has_active: Vec<_> = agents
        .iter()
        .filter(|a| {
            a["active_jobs"]
                .as_array()
                .map(|j| !j.is_empty())
                .unwrap_or(false)
        })
        .collect();

    if !has_active.is_empty() {
        println!("\nActive jobs:");
        for a in has_active {
            let id = a["id"].as_str().unwrap_or("?");
            println!("  {}:", id);
            if let Some(jobs) = a["active_jobs"].as_array() {
                for j in jobs {
                    let req_id = j["request_id"].as_str().unwrap_or("?");
                    let op = j["operation"].as_str().unwrap_or("?");
                    let short_id: String = req_id.chars().take(8).collect();
                    println!("    {}  {}", short_id, op);
                }
            }
        }
    }
}
