//! SyncScope: transactional scope for config sync operations.
//!
//! Replaces SyncTransaction with UoW-based atomic config sync.
//! All config mutations + audit + cancel happen in a single DB transaction.

use chrono::{DateTime, Utc};

use dbward_domain::auth::RoleDefinition;
use dbward_domain::entities::{User, Webhook};
use dbward_domain::policies::{ExecutionPolicy, NotificationPolicy, ResultPolicy, Workflow};
use dbward_domain::values::{DatabaseName, Environment};

use crate::error::AppError;
use crate::ports::transaction::{AuditWriterOps, RequestWriterOps};

pub trait SyncDatabaseOps {
    fn register(&self, db: &DatabaseName, env: &Environment) -> Result<(), AppError>;
    fn list_active_databases(&self) -> Result<Vec<(DatabaseName, Environment)>, AppError>;
    fn reconcile_stale_databases(&self, active_ids: &[String]) -> Result<(u64, u64), AppError>;
}

pub trait SyncUserOps {
    fn upsert_user(&self, user: &User) -> Result<(), AppError>;
    fn suspend_user(&self, user_id: &str, now: DateTime<Utc>) -> Result<bool, AppError>;
    fn activate_user(&self, user_id: &str, now: DateTime<Utc>) -> Result<bool, AppError>;
    fn set_user_source(&self, user_id: &str, source: &str) -> Result<(), AppError>;
    fn get_user_source(&self, user_id: &str) -> Result<Option<String>, AppError>;
    fn list_stale_config_user_ids(&self, active_ids: &[String]) -> Result<Vec<String>, AppError>;
    fn list_active_user_ids(&self) -> Result<Vec<String>, AppError>;
    fn count_active_users(&self) -> Result<u32, AppError>;
    fn delete_stale_config_users(&self, active_ids: &[String]) -> Result<u64, AppError>;
}

pub trait SyncGroupOps {
    fn create_group(&self, name: &str, members: &[String], source: &str) -> Result<(), AppError>;
    fn delete_stale_config_groups(&self, active_names: &[String]) -> Result<u64, AppError>;
}

pub trait SyncRoleBindingOps {
    fn create_role_binding(
        &self,
        id: &str,
        role: &str,
        subjects: &[String],
        groups: &[String],
        source: &str,
    ) -> Result<(), AppError>;
    fn delete_stale_config_role_bindings(&self, active_ids: &[String]) -> Result<u64, AppError>;
}

pub trait SyncTokenOps {
    fn revoke_all_tokens_for_user(
        &self,
        user_id: &str,
        now: DateTime<Utc>,
    ) -> Result<u32, AppError>;
}

pub trait SyncPolicyOps {
    fn create_workflow(&self, workflow: &Workflow) -> Result<(), AppError>;
    fn delete_stale_workflows(&self, active_ids: &[String]) -> Result<u64, AppError>;
    fn count_workflows(&self) -> Result<u32, AppError>;
    fn create_execution_policy(&self, policy: &ExecutionPolicy) -> Result<(), AppError>;
    fn delete_stale_execution_policies(&self, active_ids: &[String]) -> Result<u64, AppError>;
    fn create_notification_policy(&self, policy: &NotificationPolicy) -> Result<(), AppError>;
    fn delete_stale_notification_policies(&self, active_ids: &[String]) -> Result<u64, AppError>;
    fn create_result_policy(&self, policy: &ResultPolicy) -> Result<(), AppError>;
    fn delete_stale_result_policies(&self, active_ids: &[String]) -> Result<u64, AppError>;
    fn create_role(&self, role: &RoleDefinition) -> Result<(), AppError>;
    fn delete_stale_config_roles(&self, active_names: &[String]) -> Result<u64, AppError>;
    fn count_roles(&self) -> Result<u32, AppError>;
}

pub trait SyncWebhookOps {
    fn create_webhook(&self, webhook: &Webhook) -> Result<(), AppError>;
    fn delete_stale_config_webhooks(&self, active_ids: &[String]) -> Result<u64, AppError>;
    fn list_active_webhooks(&self) -> Result<Vec<Webhook>, AppError>;
}

pub trait SyncConfigGenerationOps {
    fn record_generation(
        &self,
        digest: &str,
        synced_at: DateTime<Utc>,
        summary_json: &str,
    ) -> Result<(), AppError>;
}

/// Combined scope for config sync operations.
pub trait SyncScope:
    SyncDatabaseOps
    + SyncUserOps
    + SyncGroupOps
    + SyncRoleBindingOps
    + SyncTokenOps
    + SyncPolicyOps
    + SyncWebhookOps
    + SyncConfigGenerationOps
    + AuditWriterOps
    + RequestWriterOps
{
}

impl<T> SyncScope for T where
    T: SyncDatabaseOps
        + SyncUserOps
        + SyncGroupOps
        + SyncRoleBindingOps
        + SyncTokenOps
        + SyncPolicyOps
        + SyncWebhookOps
        + SyncConfigGenerationOps
        + AuditWriterOps
        + RequestWriterOps
{
}
