use std::array;
use std::collections::BTreeMap;
use std::fmt::Write;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rusqlite::Connection;

const HISTOGRAM_BUCKETS: [f64; 11] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];
const GAUGE_CACHE_TTL: Duration = Duration::from_secs(1);
const REQUEST_STATUSES: [&str; 8] = [
    "pending",
    "approved",
    "auto_approved",
    "break_glass",
    "dispatched",
    "running",
    "executed",
    "failed",
];
const AUTH_FAILURE_REASONS: [&str; 3] = ["expired", "invalid", "revoked"];
const AGENT_EXECUTION_STATUSES: [&str; 3] = ["succeeded", "failed", "execution_lost"];

struct Histogram {
    buckets: [AtomicU64; HISTOGRAM_BUCKETS.len()],
    count: AtomicU64,
    sum_micros: AtomicU64,
}

impl Histogram {
    fn new() -> Self {
        Self {
            buckets: array::from_fn(|_| AtomicU64::new(0)),
            count: AtomicU64::new(0),
            sum_micros: AtomicU64::new(0),
        }
    }

    fn observe(&self, seconds: f64) {
        let bucket_index = HISTOGRAM_BUCKETS
            .iter()
            .position(|bucket| seconds <= *bucket);
        if let Some(index) = bucket_index {
            self.buckets[index].fetch_add(1, Ordering::Relaxed);
        }
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_micros
            .fetch_add((seconds * 1_000_000.0) as u64, Ordering::Relaxed);
    }
}

#[derive(Clone)]
struct GaugeSnapshot {
    cached_at: Instant,
    requests_current: Vec<(String, u64)>,
    oldest_pending_seconds: u64,
    agents_active: u64,
}

pub struct Metrics {
    requests_total: Mutex<BTreeMap<(String, String, String), Arc<AtomicU64>>>,
    approvals_total: Mutex<BTreeMap<String, Arc<AtomicU64>>>,
    break_glass_total: AtomicU64,
    auth_failures_total: Mutex<BTreeMap<String, Arc<AtomicU64>>>,
    webhook_deliveries_total: Mutex<BTreeMap<String, Arc<AtomicU64>>>,
    agent_executions_total: Mutex<BTreeMap<String, Arc<AtomicU64>>>,
    agent_lease_expirations_total: AtomicU64,
    http_requests_total: Mutex<BTreeMap<(String, String, u16), Arc<AtomicU64>>>,
    http_request_duration_seconds: Mutex<BTreeMap<(String, String), Arc<Histogram>>>,
    gauge_cache: Mutex<Option<GaugeSnapshot>>,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        let approvals_total = Mutex::new(BTreeMap::from([
            ("approve".to_string(), Arc::new(AtomicU64::new(0))),
            ("reject".to_string(), Arc::new(AtomicU64::new(0))),
        ]));
        let auth_failures_total = Mutex::new(BTreeMap::from(
            AUTH_FAILURE_REASONS.map(|reason| (reason.to_string(), Arc::new(AtomicU64::new(0)))),
        ));
        let webhook_deliveries_total = Mutex::new(BTreeMap::from([
            ("success".to_string(), Arc::new(AtomicU64::new(0))),
            ("failed".to_string(), Arc::new(AtomicU64::new(0))),
        ]));
        let agent_executions_total = Mutex::new(BTreeMap::from(
            AGENT_EXECUTION_STATUSES
                .map(|status| (status.to_string(), Arc::new(AtomicU64::new(0)))),
        ));

        Self {
            requests_total: Mutex::new(BTreeMap::new()),
            approvals_total,
            break_glass_total: AtomicU64::new(0),
            auth_failures_total,
            webhook_deliveries_total,
            agent_executions_total,
            agent_lease_expirations_total: AtomicU64::new(0),
            http_requests_total: Mutex::new(BTreeMap::new()),
            http_request_duration_seconds: Mutex::new(BTreeMap::new()),
            gauge_cache: Mutex::new(None),
        }
    }

    pub fn record_request_created(&self, status: &str, environment: &str, database: &str) {
        increment_map_counter(
            &self.requests_total,
            (
                status.to_string(),
                environment.to_string(),
                database.to_string(),
            ),
        );
    }

    pub fn record_approval(&self, action: &str) {
        increment_map_counter(&self.approvals_total, action.to_string());
    }

    pub fn record_break_glass(&self) {
        self.break_glass_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_auth_failure(&self, reason: &str) {
        increment_map_counter(&self.auth_failures_total, reason.to_string());
    }

    pub fn record_webhook_delivery(&self, success: bool) {
        let status = if success { "success" } else { "failed" };
        increment_map_counter(&self.webhook_deliveries_total, status.to_string());
    }

    pub fn record_agent_execution(&self, status: &str) {
        increment_map_counter(&self.agent_executions_total, status.to_string());
    }

    pub fn record_agent_lease_expirations(&self, count: u64) {
        self.agent_lease_expirations_total
            .fetch_add(count, Ordering::Relaxed);
        if count > 0 {
            for _ in 0..count {
                self.record_agent_execution("execution_lost");
            }
        }
    }

    pub fn record_http_request(&self, method: &str, route: &str, status_code: u16, seconds: f64) {
        increment_map_counter(
            &self.http_requests_total,
            (method.to_string(), route.to_string(), status_code),
        );
        let histogram = {
            let mut map = self
                .http_request_duration_seconds
                .lock()
                .expect("http histogram mutex poisoned");
            map.entry((method.to_string(), route.to_string()))
                .or_insert_with(|| Arc::new(Histogram::new()))
                .clone()
        };
        histogram.observe(seconds);
    }

    pub async fn render(&self, sqlite: &tokio::sync::Mutex<Connection>) -> Result<String, String> {
        let gauges = self.load_gauges(sqlite).await?;
        let mut out = String::new();

        write_help_type(
            &mut out,
            "dbward_requests_total",
            "counter",
            "Request creations by initial status, environment, and database.",
        );
        for ((status, environment, database), value) in snapshot_map(&self.requests_total) {
            write_metric_line(
                &mut out,
                "dbward_requests_total",
                &[
                    ("status", status.as_str()),
                    ("environment", environment.as_str()),
                    ("database", database.as_str()),
                ],
                value,
            );
        }

        write_help_type(
            &mut out,
            "dbward_requests_current",
            "gauge",
            "Current number of requests by status.",
        );
        let mut requests_current = BTreeMap::new();
        for status in REQUEST_STATUSES {
            requests_current.insert(status.to_string(), 0);
        }
        for (status, count) in &gauges.requests_current {
            requests_current.insert(status.clone(), *count);
        }
        for (status, value) in requests_current {
            write_metric_line(
                &mut out,
                "dbward_requests_current",
                &[("status", status.as_str())],
                value,
            );
        }

        write_help_type(
            &mut out,
            "dbward_requests_oldest_pending_seconds",
            "gauge",
            "Age in seconds of the oldest pending request.",
        );
        write_metric_line_no_labels(
            &mut out,
            "dbward_requests_oldest_pending_seconds",
            gauges.oldest_pending_seconds,
        );

        write_help_type(
            &mut out,
            "dbward_approvals_total",
            "counter",
            "Approval and rejection actions.",
        );
        for (action, value) in snapshot_map(&self.approvals_total) {
            write_metric_line(
                &mut out,
                "dbward_approvals_total",
                &[("action", &action)],
                value,
            );
        }

        write_help_type(
            &mut out,
            "dbward_break_glass_total",
            "counter",
            "Break-glass usage count.",
        );
        write_metric_line_no_labels(
            &mut out,
            "dbward_break_glass_total",
            self.break_glass_total.load(Ordering::Relaxed),
        );

        write_help_type(
            &mut out,
            "dbward_agents_active",
            "gauge",
            "Number of active agents.",
        );
        write_metric_line_no_labels(&mut out, "dbward_agents_active", gauges.agents_active);

        write_help_type(
            &mut out,
            "dbward_agent_executions_total",
            "counter",
            "Agent execution outcomes.",
        );
        for (status, value) in snapshot_map(&self.agent_executions_total) {
            write_metric_line(
                &mut out,
                "dbward_agent_executions_total",
                &[("status", &status)],
                value,
            );
        }

        write_help_type(
            &mut out,
            "dbward_agent_lease_expirations_total",
            "counter",
            "Agent lease expiration count.",
        );
        write_metric_line_no_labels(
            &mut out,
            "dbward_agent_lease_expirations_total",
            self.agent_lease_expirations_total.load(Ordering::Relaxed),
        );

        write_help_type(
            &mut out,
            "dbward_http_requests_total",
            "counter",
            "HTTP requests by method, route, and status code.",
        );
        for ((method, route, status_code), value) in snapshot_map(&self.http_requests_total) {
            write_metric_line(
                &mut out,
                "dbward_http_requests_total",
                &[
                    ("method", method.as_str()),
                    ("route", route.as_str()),
                    ("status_code", &status_code.to_string()),
                ],
                value,
            );
        }

        write_help_type(
            &mut out,
            "dbward_http_request_duration_seconds",
            "histogram",
            "HTTP request duration in seconds.",
        );
        for ((method, route), histogram) in snapshot_histograms(&self.http_request_duration_seconds)
        {
            let mut cumulative = 0u64;
            for (idx, bucket) in HISTOGRAM_BUCKETS.iter().enumerate() {
                cumulative += histogram.buckets[idx].load(Ordering::Relaxed);
                write_metric_line(
                    &mut out,
                    "dbward_http_request_duration_seconds_bucket",
                    &[
                        ("method", method.as_str()),
                        ("route", route.as_str()),
                        ("le", &bucket.to_string()),
                    ],
                    cumulative,
                );
            }
            let count = histogram.count.load(Ordering::Relaxed);
            write_metric_line(
                &mut out,
                "dbward_http_request_duration_seconds_bucket",
                &[
                    ("method", method.as_str()),
                    ("route", route.as_str()),
                    ("le", "+Inf"),
                ],
                count,
            );
            write_metric_line(
                &mut out,
                "dbward_http_request_duration_seconds_sum",
                &[("method", method.as_str()), ("route", route.as_str())],
                format_seconds(histogram.sum_micros.load(Ordering::Relaxed)),
            );
            write_metric_line(
                &mut out,
                "dbward_http_request_duration_seconds_count",
                &[("method", method.as_str()), ("route", route.as_str())],
                count,
            );
        }

        write_help_type(
            &mut out,
            "dbward_webhook_deliveries_total",
            "counter",
            "Webhook delivery outcomes.",
        );
        for (status, value) in snapshot_map(&self.webhook_deliveries_total) {
            write_metric_line(
                &mut out,
                "dbward_webhook_deliveries_total",
                &[("status", &status)],
                value,
            );
        }

        write_help_type(
            &mut out,
            "dbward_auth_failures_total",
            "counter",
            "Authentication failures by reason.",
        );
        for (reason, value) in snapshot_map(&self.auth_failures_total) {
            write_metric_line(
                &mut out,
                "dbward_auth_failures_total",
                &[("reason", &reason)],
                value,
            );
        }

        Ok(out)
    }

    async fn load_gauges(
        &self,
        sqlite: &tokio::sync::Mutex<Connection>,
    ) -> Result<GaugeSnapshot, String> {
        if let Some(snapshot) = self
            .gauge_cache
            .lock()
            .expect("gauge cache mutex poisoned")
            .clone()
            && snapshot.cached_at.elapsed() < GAUGE_CACHE_TTL
        {
            return Ok(snapshot);
        }

        let conn = sqlite.lock().await;

        let requests_current = {
            let mut stmt = conn
                .prepare("SELECT status, COUNT(*) FROM requests GROUP BY status")
                .map_err(|e| e.to_string())?;
            stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?))
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?
        };

        let oldest_pending_seconds = conn
            .query_row(
                "SELECT created_at FROM requests WHERE status = 'pending' ORDER BY created_at ASC LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .ok()
            .and_then(|created_at| chrono::DateTime::parse_from_rfc3339(&created_at).ok())
            .map(|created_at| {
                let elapsed = chrono::Utc::now().signed_duration_since(created_at.with_timezone(&chrono::Utc));
                elapsed.num_seconds().max(0) as u64
            })
            .unwrap_or(0);

        let agents_active = conn
            .query_row(
                "SELECT COUNT(*) FROM agents WHERE status = 'active'",
                [],
                |row| row.get::<_, u64>(0),
            )
            .map_err(|e| e.to_string())?;

        let snapshot = GaugeSnapshot {
            cached_at: Instant::now(),
            requests_current,
            oldest_pending_seconds,
            agents_active,
        };
        *self.gauge_cache.lock().expect("gauge cache mutex poisoned") = Some(snapshot.clone());
        Ok(snapshot)
    }
}

fn increment_map_counter<K>(map: &Mutex<BTreeMap<K, Arc<AtomicU64>>>, key: K)
where
    K: Ord,
{
    let counter = {
        let mut map = map.lock().expect("metrics map mutex poisoned");
        map.entry(key)
            .or_insert_with(|| Arc::new(AtomicU64::new(0)))
            .clone()
    };
    counter.fetch_add(1, Ordering::Relaxed);
}

fn snapshot_map<K>(map: &Mutex<BTreeMap<K, Arc<AtomicU64>>>) -> Vec<(K, u64)>
where
    K: Clone + Ord,
{
    map.lock()
        .expect("metrics map mutex poisoned")
        .iter()
        .map(|(key, value)| (key.clone(), value.load(Ordering::Relaxed)))
        .collect()
}

fn snapshot_histograms<K>(map: &Mutex<BTreeMap<K, Arc<Histogram>>>) -> Vec<(K, Arc<Histogram>)>
where
    K: Clone + Ord,
{
    map.lock()
        .expect("metrics map mutex poisoned")
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn write_help_type(out: &mut String, name: &str, metric_type: &str, help: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {metric_type}");
}

fn write_metric_line<T>(out: &mut String, name: &str, labels: &[(&str, &str)], value: T)
where
    T: std::fmt::Display,
{
    let _ = write!(out, "{name}");
    if !labels.is_empty() {
        let _ = write!(out, "{{");
        for (idx, (key, label)) in labels.iter().enumerate() {
            if idx > 0 {
                let _ = write!(out, ",");
            }
            let _ = write!(out, "{key}=\"{}\"", escape_label_value(label));
        }
        let _ = write!(out, "}}");
    }
    let _ = writeln!(out, " {value}");
}

fn write_metric_line_no_labels<T>(out: &mut String, name: &str, value: T)
where
    T: std::fmt::Display,
{
    let _ = writeln!(out, "{name} {value}");
}

fn escape_label_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('"', "\\\"")
}

fn format_seconds(sum_micros: u64) -> String {
    format!("{:.6}", sum_micros as f64 / 1_000_000.0)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_request_created_increments() {
        let m = Metrics::new();
        m.record_request_created("pending", "production", "app");
        m.record_request_created("pending", "production", "app");
        m.record_request_created("auto_approved", "dev", "app");

        let map = m.requests_total.lock().unwrap();
        let key = ("pending".into(), "production".into(), "app".into());
        assert_eq!(map[&key].load(Ordering::Relaxed), 2);
    }

    #[test]
    fn record_approval_increments() {
        let m = Metrics::new();
        m.record_approval("approve");
        m.record_approval("approve");
        m.record_approval("reject");

        let map = m.approvals_total.lock().unwrap();
        assert_eq!(map["approve"].load(Ordering::Relaxed), 2);
        assert_eq!(map["reject"].load(Ordering::Relaxed), 1);
    }

    #[test]
    fn record_lease_expirations_also_records_execution_lost() {
        let m = Metrics::new();
        m.record_agent_lease_expirations(3);
        assert_eq!(m.agent_lease_expirations_total.load(Ordering::Relaxed), 3);

        let map = m.agent_executions_total.lock().unwrap();
        assert_eq!(map["execution_lost"].load(Ordering::Relaxed), 3);
    }

    #[test]
    fn record_http_request_no_panic() {
        let m = Metrics::new();
        m.record_http_request("GET", "/api/requests", 200, 0.05);
        m.record_http_request("GET", "/api/requests", 200, 0.15);
        m.record_http_request("POST", "/api/requests", 201, 1.5);

        let map = m.http_requests_total.lock().unwrap();
        let key = ("GET".into(), "/api/requests".into(), 200u16);
        assert_eq!(map[&key].load(Ordering::Relaxed), 2);
    }

    #[test]
    fn format_seconds_precision() {
        assert_eq!(format_seconds(1_500_000), "1.500000");
        assert_eq!(format_seconds(0), "0.000000");
        assert_eq!(format_seconds(123), "0.000123");
    }
}
