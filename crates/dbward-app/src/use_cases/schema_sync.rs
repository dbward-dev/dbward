use std::sync::Arc;

use dbward_domain::auth::Permission;

use crate::error::{AppError, AuthzError};
use crate::ports::*;

pub struct SchemaSyncInput {
    pub agent_id: String,
    pub database: String,
    pub environment: String,
    pub dialect: String,
    pub status: String,
    pub snapshot: Option<serde_json::Value>,
    pub error_message: Option<String>,
}

pub struct SchemaSync {
    pub agent_repo: Arc<dyn AgentRepo>,
    pub schema_repo: Arc<dyn SchemaRepo>,
    pub database_registry: Arc<dyn DatabaseRegistry>,
    pub audit_logger: Arc<dyn AuditLogger>,
    pub clock: Arc<dyn Clock>,
}

impl SchemaSync {
    pub fn execute(&self, input: SchemaSyncInput) -> Result<(), AppError> {
        // 1. Validate dialect
        if !matches!(input.dialect.as_str(), "postgresql" | "mysql") {
            return Err(AppError::Validation("invalid dialect".into()));
        }
        // 2. Validate status
        if !matches!(input.status.as_str(), "ready" | "failed" | "partial") {
            return Err(AppError::Validation("invalid status".into()));
        }
        // 3. Validate consistency
        if input.status == "ready" && input.snapshot.is_none() {
            return Err(AppError::Validation(
                "snapshot required when status=ready".into(),
            ));
        }

        // 4. Scope check: agent must have capability for this database+environment
        let agent = self.agent_repo.get(&input.agent_id)?.ok_or_else(|| {
            AppError::Forbidden(AuthzError::Forbidden {
                permission: Permission::AgentOperate,
                reason: "agent not registered".into(),
            })
        })?;
        let scope_match = agent.databases.iter().any(|d| {
            d.database.as_str() == input.database && d.environment.as_str() == input.environment
        });
        if !scope_match {
            return Err(AppError::Forbidden(AuthzError::Forbidden {
                permission: Permission::AgentOperate,
                reason: "agent not authorized for this database/environment".into(),
            }));
        }

        // 5. Verify database+environment is registered
        use dbward_domain::values::{DatabaseName, Environment};
        if let (Ok(db), Ok(env)) = (
            DatabaseName::new(&input.database),
            Environment::new(&input.environment),
        ) && !self.database_registry.exists(&db, &env)?
        {
            return Err(AppError::Validation(
                "database/environment not registered".into(),
            ));
        }

        // 6. Upsert snapshot
        let now = self.clock.now().to_rfc3339();
        let record = SchemaSnapshotRecord {
            database_name: input.database.clone(),
            environment: input.environment.clone(),
            status: input.status.clone(),
            snapshot_json: input.snapshot.map(|v| v.to_string()),
            error_message: input.error_message,
            dialect: input.dialect,
            collected_at: now,
            agent_id: input.agent_id.clone(),
        };
        self.schema_repo.upsert_snapshot(&record)?;

        // 7. Audit event
        let event_type = if record.status == "ready" {
            "schema_snapshot_updated"
        } else {
            "schema_snapshot_failed"
        };
        let audit_ctx = dbward_domain::entities::AuditContext::Agent {
            agent_id: input.agent_id.clone(),
        };
        let mut event = dbward_domain::entities::AuditEvent::simple(
            event_type,
            "agent",
            &input.agent_id,
            None,
            self.clock.now(),
            &audit_ctx,
        );
        event.database_name = Some(record.database_name);
        event.environment = Some(record.environment);
        let _ = self.audit_logger.record(&event);

        Ok(())
    }
}

// Tests for schema_sync validation are covered by integration tests (dev/e2e/agent.sh).
// Unit tests require a full AgentRepo fake which is deferred to a follow-up.
