/// Centralized status string constants to prevent typos across layers.
// TODO(v0.2): Replace with proper enums (ContextStatus, DryRunStatus, SchemaStatus string repr).
pub mod context {
    pub const COLLECTING: &str = "collecting";
    pub const READY: &str = "ready";
    pub const PARTIAL: &str = "partial";
    pub const UNAVAILABLE: &str = "unavailable";
}

pub mod dry_run {
    pub const PENDING: &str = "pending";
    pub const CLAIMED: &str = "claimed";
    pub const COMPLETED: &str = "completed";
    pub const FAILED: &str = "failed";
}

pub mod schema {
    pub const READY: &str = "ready";
    pub const FAILED: &str = "failed";
}

pub mod dialect {
    pub const POSTGRESQL: &str = "postgresql";
    pub const MYSQL: &str = "mysql";
}
