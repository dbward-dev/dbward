use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use dbward_app::ports::{AgentRepo, RequestRepo};

/// Prometheus-compatible metrics registry.
pub struct Metrics {
    // Counters
    pub requests_total: CounterVec<3>,
    pub approvals_total: CounterVec<1>,
    pub break_glass_total: AtomicU64,
    pub agent_executions_total: CounterVec<1>,
    pub auth_failures_total: CounterVec<1>,
    pub http_requests_total: CounterVec<3>,
    pub agent_lease_expirations_total: AtomicU64,
    pub webhook_deliveries_total: CounterVec<1>,
    pub result_storage_total: CounterVec<1>,

    // Histograms
    pub http_request_duration: HistogramVec<2>,
    pub approval_wait: Histogram,
    pub execution_duration: HistogramVec<2>,

    // Gauge snapshots are computed at render time from repos
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            requests_total: CounterVec::new(),
            approvals_total: CounterVec::new(),
            break_glass_total: AtomicU64::new(0),
            agent_executions_total: CounterVec::new(),
            auth_failures_total: CounterVec::new(),
            http_requests_total: CounterVec::new(),
            agent_lease_expirations_total: AtomicU64::new(0),
            webhook_deliveries_total: CounterVec::new(),
            result_storage_total: CounterVec::new(),
            http_request_duration: HistogramVec::new(),
            approval_wait: Histogram::new(),
            execution_duration: HistogramVec::new(),
        }
    }
}

/// Render all metrics in Prometheus text exposition format.
pub fn render(
    metrics: &Metrics,
    request_repo: &dyn RequestRepo,
    agent_repo: &dyn AgentRepo,
) -> String {
    let mut out = String::with_capacity(4096);

    // Counters
    write_counter_vec(&mut out, "dbward_requests_total", &["status", "environment", "database"], &metrics.requests_total);
    write_counter_vec(&mut out, "dbward_approvals_total", &["action"], &metrics.approvals_total);
    writeln!(out, "# TYPE dbward_break_glass_total counter").ok();
    writeln!(out, "dbward_break_glass_total {}", metrics.break_glass_total.load(Ordering::Relaxed)).ok();
    write_counter_vec(&mut out, "dbward_agent_executions_total", &["status"], &metrics.agent_executions_total);
    write_counter_vec(&mut out, "dbward_auth_failures_total", &["reason"], &metrics.auth_failures_total);
    write_counter_vec(&mut out, "dbward_http_requests_total", &["method", "path", "status"], &metrics.http_requests_total);
    writeln!(out, "# TYPE dbward_agent_lease_expirations_total counter").ok();
    writeln!(out, "dbward_agent_lease_expirations_total {}", metrics.agent_lease_expirations_total.load(Ordering::Relaxed)).ok();
    write_counter_vec(&mut out, "dbward_webhook_deliveries_total", &["status"], &metrics.webhook_deliveries_total);
    write_counter_vec(&mut out, "dbward_result_storage_total", &["status"], &metrics.result_storage_total);

    // Histograms
    write_histogram_vec(&mut out, "dbward_http_request_duration_seconds", &["method", "path"], &metrics.http_request_duration);
    write_histogram_single(&mut out, "dbward_approval_wait_seconds", &metrics.approval_wait);
    write_histogram_vec(&mut out, "dbward_execution_duration_seconds", &["database", "environment"], &metrics.execution_duration);

    // Gauges (queried at render time)
    writeln!(out, "# TYPE dbward_requests_current gauge").ok();
    for status in &["pending", "approved", "dispatched", "running"] {
        let count = request_repo.count_by_status(status).unwrap_or(0);
        writeln!(out, "dbward_requests_current{{status=\"{status}\"}} {count}").ok();
    }

    writeln!(out, "# TYPE dbward_agents_active gauge").ok();
    let agents = agent_repo.list().unwrap_or_default();
    let active = agents.iter().filter(|a| a.status == dbward_domain::entities::AgentStatus::Active).count();
    writeln!(out, "dbward_agents_active {active}").ok();

    writeln!(out, "# TYPE dbward_agents_saturated gauge").ok();
    let saturated = agents.iter().filter(|a| a.in_flight >= a.max_concurrent).count();
    writeln!(out, "dbward_agents_saturated {saturated}").ok();

    out
}

// --- Counter infrastructure ---

pub struct CounterVec<const N: usize> {
    entries: std::sync::Mutex<Vec<([String; N], u64)>>,
}

impl<const N: usize> Default for CounterVec<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> CounterVec<N> {
    pub fn new() -> Self {
        Self { entries: std::sync::Mutex::new(Vec::new()) }
    }

    pub fn inc(&self, labels: [&str; N]) {
        let mut entries = self.entries.lock().unwrap();
        for (k, v) in entries.iter_mut() {
            if k.iter().zip(labels.iter()).all(|(a, b)| a == b) {
                *v += 1;
                return;
            }
        }
        entries.push((labels.map(|s| s.to_string()), 1));
    }

    fn snapshot(&self) -> Vec<([String; N], u64)> {
        self.entries.lock().unwrap().clone()
    }
}

// --- Histogram infrastructure ---

const BUCKETS: &[f64] = &[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0];

pub struct Histogram {
    buckets: Vec<AtomicU64>,
    sum: AtomicU64, // stored as f64 bits
    count: AtomicU64,
}

impl Default for Histogram {
    fn default() -> Self {
        Self::new()
    }
}

impl Histogram {
    pub fn new() -> Self {
        Self {
            buckets: (0..BUCKETS.len()).map(|_| AtomicU64::new(0)).collect(),
            sum: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    pub fn observe(&self, value: f64) {
        self.count.fetch_add(1, Ordering::Relaxed);
        loop {
            let old_bits = self.sum.load(Ordering::Relaxed);
            let old = f64::from_bits(old_bits);
            let new = old + value;
            if self.sum.compare_exchange(old_bits, new.to_bits(), Ordering::Relaxed, Ordering::Relaxed).is_ok() {
                break;
            }
        }
        // Increment only the first matching bucket (render does cumulative sum)
        for (i, &bound) in BUCKETS.iter().enumerate() {
            if value <= bound {
                self.buckets[i].fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
    }
}

pub struct HistogramVec<const N: usize> {
    entries: std::sync::Mutex<Vec<([String; N], Arc<Histogram>)>>,
}

impl<const N: usize> Default for HistogramVec<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> HistogramVec<N> {
    pub fn new() -> Self {
        Self { entries: std::sync::Mutex::new(Vec::new()) }
    }

    pub fn observe(&self, labels: [&str; N], value: f64) {
        let mut entries = self.entries.lock().unwrap();
        for (k, h) in entries.iter() {
            if k.iter().zip(labels.iter()).all(|(a, b)| a == b) {
                h.observe(value);
                return;
            }
        }
        let h = Arc::new(Histogram::new());
        h.observe(value);
        entries.push((labels.map(|s| s.to_string()), h));
    }

    fn snapshot(&self) -> Vec<([String; N], Arc<Histogram>)> {
        self.entries.lock().unwrap().clone()
    }
}

// --- Rendering helpers ---

fn write_counter_vec<const N: usize>(out: &mut String, name: &str, label_names: &[&str; N], cv: &CounterVec<N>) {
    let entries = cv.snapshot();
    if entries.is_empty() {
        return;
    }
    writeln!(out, "# TYPE {name} counter").ok();
    for (labels, value) in &entries {
        let pairs: Vec<String> = label_names.iter().zip(labels.iter())
            .map(|(k, v)| format!("{k}=\"{v}\""))
            .collect();
        writeln!(out, "{name}{{{pairs}}} {value}", pairs = pairs.join(",")).ok();
    }
}

fn write_histogram_single(out: &mut String, name: &str, h: &Histogram) {
    let count = h.count.load(Ordering::Relaxed);
    if count == 0 {
        return;
    }
    writeln!(out, "# TYPE {name} histogram").ok();
    let mut cumulative = 0u64;
    for (i, &bound) in BUCKETS.iter().enumerate() {
        cumulative += h.buckets[i].load(Ordering::Relaxed);
        writeln!(out, "{name}_bucket{{le=\"{bound}\"}} {cumulative}").ok();
    }
    writeln!(out, "{name}_bucket{{le=\"+Inf\"}} {count}").ok();
    let sum = f64::from_bits(h.sum.load(Ordering::Relaxed));
    writeln!(out, "{name}_sum {sum}").ok();
    writeln!(out, "{name}_count {count}").ok();
}

fn write_histogram_vec<const N: usize>(out: &mut String, name: &str, label_names: &[&str; N], hv: &HistogramVec<N>) {
    let entries = hv.snapshot();
    if entries.is_empty() {
        return;
    }
    writeln!(out, "# TYPE {name} histogram").ok();
    for (labels, h) in &entries {
        let count = h.count.load(Ordering::Relaxed);
        if count == 0 {
            continue;
        }
        let pairs: Vec<String> = label_names.iter().zip(labels.iter())
            .map(|(k, v)| format!("{k}=\"{v}\""))
            .collect();
        let label_str = pairs.join(",");
        let mut cumulative = 0u64;
        for (i, &bound) in BUCKETS.iter().enumerate() {
            cumulative += h.buckets[i].load(Ordering::Relaxed);
            writeln!(out, "{name}_bucket{{{label_str},le=\"{bound}\"}} {cumulative}").ok();
        }
        writeln!(out, "{name}_bucket{{{label_str},le=\"+Inf\"}} {count}").ok();
        let sum = f64::from_bits(h.sum.load(Ordering::Relaxed));
        writeln!(out, "{name}_sum{{{label_str}}} {sum}").ok();
        writeln!(out, "{name}_count{{{label_str}}} {count}").ok();
    }
}
