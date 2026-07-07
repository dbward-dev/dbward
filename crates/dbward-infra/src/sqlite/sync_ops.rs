//! Sync*Ops implementations for SqliteTxScope.

use chrono::{DateTime, Utc};
use rusqlite::params;

use dbward_app::error::AppError;
use dbward_app::ports::sync_scope::*;
use dbward_domain::auth::RoleDefinition;
use dbward_domain::entities::{User, Webhook, WebhookFormat, WebhookStatus};
use dbward_domain::policies::{ExecutionPolicy, NotificationPolicy, ResultPolicy, Workflow};
use dbward_domain::values::{DatabaseName, Environment};

use super::error::db_err;
use super::unit_of_work::SqliteTxScope;

impl SyncDatabaseOps for SqliteTxScope<'_> {
    fn register(&self, db: &DatabaseName, env: &Environment) -> Result<(), AppError> {
        let id = format!("{db}:{env}");
        self.conn.execute(
            "INSERT INTO databases (id, name, environment, source, lifecycle_state, created_at) \
             VALUES (?1, ?2, ?3, 'config', 'active', ?4) \
             ON CONFLICT(id) DO UPDATE SET source='config', lifecycle_state='active'",
            params![id, db.to_string(), env.to_string(), Utc::now().to_rfc3339()],
        ).map_err(db_err("sync: register"))?;
        Ok(())
    }

    fn list_active_databases(&self) -> Result<Vec<(DatabaseName, Environment)>, AppError> {
        let mut stmt = self
            .conn
            .prepare("SELECT name, environment FROM databases WHERE lifecycle_state = 'active'")
            .map_err(db_err("sync: list_active_databases"))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(db_err("sync: list_active_databases"))?;
        let mut results = Vec::new();
        for row in rows {
            let (name, env) = row.map_err(db_err("sync: list_active_databases"))?;
            let db = DatabaseName::new(name).map_err(|e| AppError::Internal(e.to_string()))?;
            let environment =
                Environment::new(env).map_err(|e| AppError::Internal(e.to_string()))?;
            results.push((db, environment));
        }
        Ok(results)
    }

    fn reconcile_stale_databases(&self, active_ids: &[String]) -> Result<(u64, u64), AppError> {
        if active_ids.is_empty() {
            let orphaned = self.conn.execute(
                "UPDATE databases SET lifecycle_state = 'orphan' WHERE source = 'config' AND lifecycle_state = 'active' AND EXISTS (SELECT 1 FROM requests WHERE requests.database_id = databases.id)",
                [],
            ).map_err(db_err("sync: reconcile orphan"))? as u64;
            let deleted = self.conn.execute(
                "DELETE FROM databases WHERE source = 'config' AND lifecycle_state = 'active' AND NOT EXISTS (SELECT 1 FROM requests WHERE requests.database_id = databases.id)",
                [],
            ).map_err(db_err("sync: reconcile delete"))? as u64;
            return Ok((orphaned, deleted));
        }
        let placeholders: String = (1..=active_ids.len())
            .map(|i| format!("?{i}"))
            .collect::<Vec<_>>()
            .join(",");
        let params: Vec<&dyn rusqlite::types::ToSql> = active_ids
            .iter()
            .map(|s| s as &dyn rusqlite::types::ToSql)
            .collect();
        let sql_orphan = format!(
            "UPDATE databases SET lifecycle_state = 'orphan' WHERE source = 'config' AND lifecycle_state = 'active' AND id NOT IN ({placeholders}) AND EXISTS (SELECT 1 FROM requests WHERE requests.database_id = databases.id)"
        );
        let orphaned = self
            .conn
            .execute(&sql_orphan, params.as_slice())
            .map_err(db_err("sync: reconcile orphan"))? as u64;
        let sql_delete = format!(
            "DELETE FROM databases WHERE source = 'config' AND lifecycle_state = 'active' AND id NOT IN ({placeholders}) AND NOT EXISTS (SELECT 1 FROM requests WHERE requests.database_id = databases.id)"
        );
        let deleted = self
            .conn
            .execute(&sql_delete, params.as_slice())
            .map_err(db_err("sync: reconcile delete"))? as u64;
        Ok((orphaned, deleted))
    }
}

impl SyncUserOps for SqliteTxScope<'_> {
    fn upsert_user(&self, user: &User) -> Result<(), AppError> {
        let roles_json = serde_json::to_string(&user.roles)
            .map_err(|e| AppError::Internal(format!("json: {e}")))?;
        self.conn.execute(
            "INSERT INTO users (id, display_name, email, roles_json, status, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
             ON CONFLICT(id) DO UPDATE SET display_name=?2, email=?3, roles_json=?4, updated_at=?7",
            params![
                user.id, user.display_name, user.email, roles_json,
                match user.status {
                    dbward_domain::entities::UserStatus::Active => "active",
                    dbward_domain::entities::UserStatus::Suspended => "suspended",
                },
                user.created_at.to_rfc3339(), user.updated_at.to_rfc3339()
            ],
        ).map_err(db_err("sync: upsert_user"))?;
        Ok(())
    }

    fn suspend_user(&self, user_id: &str, now: DateTime<Utc>) -> Result<bool, AppError> {
        let n = self.conn.execute(
            "UPDATE users SET status = 'suspended', updated_at = ?2 WHERE id = ?1 AND status != 'suspended'",
            params![user_id, now.to_rfc3339()],
        ).map_err(db_err("sync: suspend_user"))?;
        Ok(n > 0)
    }

    fn activate_user(&self, user_id: &str, now: DateTime<Utc>) -> Result<bool, AppError> {
        let n = self.conn.execute(
            "UPDATE users SET status = 'active', updated_at = ?2 WHERE id = ?1 AND status != 'active'",
            params![user_id, now.to_rfc3339()],
        ).map_err(db_err("sync: activate_user"))?;
        Ok(n > 0)
    }

    fn set_user_source(&self, user_id: &str, source: &str) -> Result<(), AppError> {
        self.conn
            .execute(
                "UPDATE users SET source = ?2 WHERE id = ?1",
                params![user_id, source],
            )
            .map_err(db_err("sync: set_user_source"))?;
        Ok(())
    }

    fn get_user_source(&self, user_id: &str) -> Result<Option<String>, AppError> {
        let result: Result<String, _> = self.conn.query_row(
            "SELECT source FROM users WHERE id = ?1",
            params![user_id],
            |row| row.get(0),
        );
        match result {
            Ok(s) => Ok(Some(s)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(db_err("sync: get_user_source")(e)),
        }
    }

    fn list_stale_config_user_ids(&self, active_ids: &[String]) -> Result<Vec<String>, AppError> {
        if active_ids.is_empty() {
            let mut stmt = self
                .conn
                .prepare("SELECT id FROM users WHERE source = 'config'")
                .map_err(db_err("sync: list_stale_users"))?;
            let rows = stmt
                .query_map([], |row| row.get(0))
                .map_err(db_err("sync: list_stale_users"))?;
            return rows
                .collect::<Result<Vec<_>, _>>()
                .map_err(db_err("sync: list_stale_users"));
        }
        let placeholders: String = (1..=active_ids.len())
            .map(|i| format!("?{i}"))
            .collect::<Vec<_>>()
            .join(",");
        let sql =
            format!("SELECT id FROM users WHERE source = 'config' AND id NOT IN ({placeholders})");
        let params: Vec<&dyn rusqlite::types::ToSql> = active_ids
            .iter()
            .map(|s| s as &dyn rusqlite::types::ToSql)
            .collect();
        let mut stmt = self
            .conn
            .prepare(&sql)
            .map_err(db_err("sync: list_stale_users"))?;
        let rows = stmt
            .query_map(params.as_slice(), |row| row.get(0))
            .map_err(db_err("sync: list_stale_users"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(db_err("sync: list_stale_users"))
    }

    fn list_active_user_ids(&self) -> Result<Vec<String>, AppError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id FROM users WHERE status = 'active'")
            .map_err(db_err("sync: list_active_user_ids"))?;
        let rows = stmt
            .query_map([], |row| row.get(0))
            .map_err(db_err("sync: list_active_user_ids"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(db_err("sync: list_active_user_ids"))
    }

    fn count_active_users(&self) -> Result<u32, AppError> {
        let count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM users WHERE status = 'active'",
                [],
                |row| row.get(0),
            )
            .map_err(db_err("sync: count_active_users"))?;
        Ok(count as u32)
    }

    fn delete_stale_config_users(&self, active_ids: &[String]) -> Result<u64, AppError> {
        if active_ids.is_empty() {
            let n = self
                .conn
                .execute("DELETE FROM users WHERE source = 'config'", [])
                .map_err(db_err("sync: delete_stale_users"))?;
            return Ok(n as u64);
        }
        let placeholders: String = (1..=active_ids.len())
            .map(|i| format!("?{i}"))
            .collect::<Vec<_>>()
            .join(",");
        let sql =
            format!("DELETE FROM users WHERE source = 'config' AND id NOT IN ({placeholders})");
        let params: Vec<&dyn rusqlite::types::ToSql> = active_ids
            .iter()
            .map(|s| s as &dyn rusqlite::types::ToSql)
            .collect();
        let n = self
            .conn
            .execute(&sql, params.as_slice())
            .map_err(db_err("sync: delete_stale_users"))?;
        Ok(n as u64)
    }
}

impl SyncGroupOps for SqliteTxScope<'_> {
    fn create_group(&self, name: &str, members: &[String], source: &str) -> Result<(), AppError> {
        // V25: groups table is name-only. members/source are ignored (legacy trait sig).
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO groups (name, created_at) VALUES (?1, ?2) \
             ON CONFLICT(name) DO NOTHING",
                params![name, now],
            )
            .map_err(db_err("sync: create_group"))?;
        let _ = (members, source); // suppress unused warnings
        Ok(())
    }

    fn delete_stale_config_groups(&self, active_names: &[String]) -> Result<u64, AppError> {
        if active_names.is_empty() {
            let n = self
                .conn
                .execute("DELETE FROM groups", [])
                .map_err(db_err("sync: delete_stale_groups"))?;
            return Ok(n as u64);
        }
        let placeholders: String = (1..=active_names.len())
            .map(|i| format!("?{i}"))
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!("DELETE FROM groups WHERE name NOT IN ({placeholders})");
        let params: Vec<&dyn rusqlite::types::ToSql> = active_names
            .iter()
            .map(|s| s as &dyn rusqlite::types::ToSql)
            .collect();
        let n = self
            .conn
            .execute(&sql, params.as_slice())
            .map_err(db_err("sync: delete_stale_groups"))?;
        Ok(n as u64)
    }
}

impl SyncTokenOps for SqliteTxScope<'_> {
    fn revoke_all_tokens_for_user(
        &self,
        user_id: &str,
        now: DateTime<Utc>,
    ) -> Result<u32, AppError> {
        let n = self
            .conn
            .execute(
                "UPDATE tokens SET status = 'revoked', revoked_at = ?2 WHERE subject_id = ?1 AND status = 'active'",
                params![user_id, now.to_rfc3339()],
            )
            .map_err(db_err("sync: revoke_all_tokens"))?;
        Ok(n as u32)
    }
}

impl SyncPolicyOps for SqliteTxScope<'_> {
    fn create_workflow(&self, wf: &Workflow) -> Result<(), AppError> {
        let steps_json = serde_json::to_string(&wf.steps)
            .map_err(|e| AppError::Internal(format!("json: {e}")))?;
        let ops_json = serde_json::to_string(&wf.operations)
            .map_err(|e| AppError::Internal(format!("json: {e}")))?;
        let aa_json: Option<String> = wf
            .auto_approve
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| AppError::Internal(format!("json: {e}")))?;
        self.conn.execute(
            "INSERT INTO workflows (id, database_name, environment, operations_json, steps_json, auto_approve_json, require_reason, allow_self_approve, allow_same_approver_across_steps, explain, pending_ttl_secs, approval_ttl_secs, statement_timeout_secs, source, lifecycle_state) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,'config','active') ON CONFLICT(id) DO UPDATE SET operations_json=excluded.operations_json, steps_json=excluded.steps_json, auto_approve_json=excluded.auto_approve_json, require_reason=excluded.require_reason, allow_self_approve=excluded.allow_self_approve, allow_same_approver_across_steps=excluded.allow_same_approver_across_steps, explain=excluded.explain, pending_ttl_secs=excluded.pending_ttl_secs, approval_ttl_secs=excluded.approval_ttl_secs, statement_timeout_secs=excluded.statement_timeout_secs, lifecycle_state='active'",
            params![wf.id, wf.database.as_str(), wf.environment.as_str(), ops_json, steps_json, aa_json, wf.require_reason, wf.allow_self_approve, wf.allow_same_approver_across_steps, wf.explain, wf.pending_ttl_secs.map(|v| v as i64), wf.approval_ttl_secs.map(|v| v as i64), wf.statement_timeout_secs.map(|v| v as i64)],
        ).map_err(db_err("sync: create_workflow"))?;
        Ok(())
    }

    fn delete_stale_workflows(&self, active_ids: &[String]) -> Result<u64, AppError> {
        if active_ids.is_empty() {
            let n = self
                .conn
                .execute("DELETE FROM workflows WHERE source = 'config'", [])
                .map_err(db_err("sync: delete_stale_wf"))?;
            return Ok(n as u64);
        }
        let placeholders: String = (1..=active_ids.len())
            .map(|i| format!("?{i}"))
            .collect::<Vec<_>>()
            .join(",");
        let sql =
            format!("DELETE FROM workflows WHERE source = 'config' AND id NOT IN ({placeholders})");
        let params: Vec<&dyn rusqlite::types::ToSql> = active_ids
            .iter()
            .map(|s| s as &dyn rusqlite::types::ToSql)
            .collect();
        let n = self
            .conn
            .execute(&sql, params.as_slice())
            .map_err(db_err("sync: delete_stale_wf"))?;
        Ok(n as u64)
    }

    fn count_workflows(&self) -> Result<u32, AppError> {
        let c: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM workflows", [], |r| r.get(0))
            .map_err(db_err("sync: count_workflows"))?;
        Ok(c as u32)
    }

    fn create_execution_policy(&self, ep: &ExecutionPolicy) -> Result<(), AppError> {
        self.conn.execute(
            "INSERT INTO execution_policies (id, database_name, environment, max_executions, execution_window_secs, retry_on_failure, statement_timeout_secs, max_statement_timeout_secs, max_rows, migration_lease_duration_secs, migration_statement_timeout_secs, source, lifecycle_state) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,'config','active') ON CONFLICT(id) DO UPDATE SET max_executions=excluded.max_executions, execution_window_secs=excluded.execution_window_secs, retry_on_failure=excluded.retry_on_failure, statement_timeout_secs=excluded.statement_timeout_secs, max_statement_timeout_secs=excluded.max_statement_timeout_secs, max_rows=excluded.max_rows, migration_lease_duration_secs=excluded.migration_lease_duration_secs, migration_statement_timeout_secs=excluded.migration_statement_timeout_secs, lifecycle_state='active'",
            params![ep.id, ep.database.as_str(), ep.environment.as_str(), ep.max_executions, ep.execution_window_secs as i64, ep.retry_on_failure, ep.statement_timeout_secs, ep.max_statement_timeout_secs, ep.max_rows.map(|v| v as i64), ep.migration_lease_duration_secs.map(|v| v as i64), ep.migration_statement_timeout_secs.map(|v| v as i64)],
        ).map_err(db_err("sync: create_ep"))?;
        Ok(())
    }

    fn delete_stale_execution_policies(&self, active_ids: &[String]) -> Result<u64, AppError> {
        if active_ids.is_empty() {
            let n = self
                .conn
                .execute("DELETE FROM execution_policies WHERE source = 'config'", [])
                .map_err(db_err("sync: del_ep"))?;
            return Ok(n as u64);
        }
        let placeholders: String = (1..=active_ids.len())
            .map(|i| format!("?{i}"))
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "DELETE FROM execution_policies WHERE source = 'config' AND id NOT IN ({placeholders})"
        );
        let params: Vec<&dyn rusqlite::types::ToSql> = active_ids
            .iter()
            .map(|s| s as &dyn rusqlite::types::ToSql)
            .collect();
        let n = self
            .conn
            .execute(&sql, params.as_slice())
            .map_err(db_err("sync: del_ep"))?;
        Ok(n as u64)
    }

    fn create_sql_review_policy(
        &self,
        policy: &dbward_domain::policies::SqlReviewPolicy,
    ) -> Result<(), AppError> {
        let rules_json = serde_json::to_string(&policy.rules)
            .map_err(|e| AppError::Internal(format!("json: {e}")))?;
        self.conn
            .execute(
                "INSERT INTO sql_review_policies (id, database_name, environment, rules_json, source, lifecycle_state) \
                 VALUES (?1, ?2, ?3, ?4, 'config', 'active') \
                 ON CONFLICT(id) DO UPDATE SET \
                   database_name=excluded.database_name, \
                   environment=excluded.environment, \
                   rules_json=excluded.rules_json, \
                   lifecycle_state='active'",
                rusqlite::params![
                    policy.id,
                    policy.database.as_str(),
                    policy.environment.as_str(),
                    rules_json,
                ],
            )
            .map_err(db_err("sync: create_sql_review_policy"))?;
        Ok(())
    }

    fn delete_stale_sql_review_policies(&self, active_ids: &[String]) -> Result<u64, AppError> {
        if active_ids.is_empty() {
            let n = self
                .conn
                .execute(
                    "DELETE FROM sql_review_policies WHERE source = 'config'",
                    [],
                )
                .map_err(db_err("sync: del_srp"))?;
            return Ok(n as u64);
        }
        let placeholders: String = (1..=active_ids.len())
            .map(|i| format!("?{i}"))
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "DELETE FROM sql_review_policies WHERE source = 'config' AND id NOT IN ({placeholders})"
        );
        let params: Vec<&dyn rusqlite::types::ToSql> = active_ids
            .iter()
            .map(|s| s as &dyn rusqlite::types::ToSql)
            .collect();
        let n = self
            .conn
            .execute(&sql, params.as_slice())
            .map_err(db_err("sync: del_srp"))?;
        Ok(n as u64)
    }

    fn create_notification_policy(&self, np: &NotificationPolicy) -> Result<(), AppError> {
        let webhooks_json = serde_json::to_string(&np.webhooks)
            .map_err(|e| AppError::Internal(format!("json: {e}")))?;
        let events_json = serde_json::to_string(&np.events)
            .map_err(|e| AppError::Internal(format!("json: {e}")))?;
        self.conn.execute(
            "INSERT INTO notification_policies (id, database_name, environment, webhooks_json, events_json, source, lifecycle_state) VALUES (?1,?2,?3,?4,?5,'config','active') ON CONFLICT(id) DO UPDATE SET webhooks_json=excluded.webhooks_json, events_json=excluded.events_json, lifecycle_state='active'",
            params![np.id, np.database.as_str(), np.environment.as_str(), webhooks_json, events_json],
        ).map_err(db_err("sync: create_np"))?;
        Ok(())
    }

    fn delete_stale_notification_policies(&self, active_ids: &[String]) -> Result<u64, AppError> {
        if active_ids.is_empty() {
            let n = self
                .conn
                .execute(
                    "DELETE FROM notification_policies WHERE source = 'config'",
                    [],
                )
                .map_err(db_err("sync: del_np"))?;
            return Ok(n as u64);
        }
        let placeholders: String = (1..=active_ids.len())
            .map(|i| format!("?{i}"))
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "DELETE FROM notification_policies WHERE source = 'config' AND id NOT IN ({placeholders})"
        );
        let params: Vec<&dyn rusqlite::types::ToSql> = active_ids
            .iter()
            .map(|s| s as &dyn rusqlite::types::ToSql)
            .collect();
        let n = self
            .conn
            .execute(&sql, params.as_slice())
            .map_err(db_err("sync: del_np"))?;
        Ok(n as u64)
    }

    fn create_result_policy(&self, rp: &ResultPolicy) -> Result<(), AppError> {
        let access_json = serde_json::to_string(&rp.access)
            .map_err(|e| AppError::Internal(format!("json: {e}")))?;
        let dm = match rp.delivery_mode {
            dbward_domain::policies::DeliveryMode::StoreOnly => "store_only",
            dbward_domain::policies::DeliveryMode::Stream => "stream",
            dbward_domain::policies::DeliveryMode::Both => "both",
        };
        self.conn.execute(
            "INSERT INTO result_policies (id, database_name, environment, retention_days, delivery_mode, access_json, source, lifecycle_state) VALUES (?1,?2,?3,?4,?5,?6,'config','active') ON CONFLICT(id) DO UPDATE SET retention_days=excluded.retention_days, delivery_mode=excluded.delivery_mode, access_json=excluded.access_json, lifecycle_state='active'",
            params![rp.id, rp.database.as_str(), rp.environment.as_str(), rp.retention_days, dm, access_json],
        ).map_err(db_err("sync: create_rp"))?;
        Ok(())
    }

    fn delete_stale_result_policies(&self, active_ids: &[String]) -> Result<u64, AppError> {
        if active_ids.is_empty() {
            let n = self
                .conn
                .execute("DELETE FROM result_policies WHERE source = 'config'", [])
                .map_err(db_err("sync: del_rp"))?;
            return Ok(n as u64);
        }
        let placeholders: String = (1..=active_ids.len())
            .map(|i| format!("?{i}"))
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "DELETE FROM result_policies WHERE source = 'config' AND id NOT IN ({placeholders})"
        );
        let params: Vec<&dyn rusqlite::types::ToSql> = active_ids
            .iter()
            .map(|s| s as &dyn rusqlite::types::ToSql)
            .collect();
        let n = self
            .conn
            .execute(&sql, params.as_slice())
            .map_err(db_err("sync: del_rp"))?;
        Ok(n as u64)
    }

    fn create_role(&self, role: &RoleDefinition) -> Result<(), AppError> {
        let perms_json = serde_json::to_string(&role.permissions)
            .map_err(|e| AppError::Internal(format!("json: {e}")))?;
        let dbs_json = serde_json::to_string(&role.databases)
            .map_err(|e| AppError::Internal(format!("json: {e}")))?;
        let envs_json = serde_json::to_string(&role.environments)
            .map_err(|e| AppError::Internal(format!("json: {e}")))?;
        self.conn.execute(
            "INSERT INTO roles (name, permissions_json, databases_json, environments_json, built_in, config_synced) \
             VALUES (?1, ?2, ?3, ?4, 0, 1) \
             ON CONFLICT(name) DO UPDATE SET permissions_json = ?2, databases_json = ?3, environments_json = ?4, config_synced = 1 \
             WHERE config_synced = 1 OR built_in = 0",
            params![role.name, perms_json, dbs_json, envs_json],
        ).map_err(db_err("sync: create_role"))?;
        Ok(())
    }

    fn delete_stale_config_roles(&self, active_names: &[String]) -> Result<u64, AppError> {
        if active_names.is_empty() {
            let n = self
                .conn
                .execute("DELETE FROM roles WHERE config_synced = 1", [])
                .map_err(db_err("sync: del_roles"))?;
            return Ok(n as u64);
        }
        let placeholders: String = (1..=active_names.len())
            .map(|i| format!("?{i}"))
            .collect::<Vec<_>>()
            .join(",");
        let sql =
            format!("DELETE FROM roles WHERE config_synced = 1 AND name NOT IN ({placeholders})");
        let params: Vec<&dyn rusqlite::types::ToSql> = active_names
            .iter()
            .map(|s| s as &dyn rusqlite::types::ToSql)
            .collect();
        let n = self
            .conn
            .execute(&sql, params.as_slice())
            .map_err(db_err("sync: del_roles"))?;
        Ok(n as u64)
    }

    fn count_roles(&self) -> Result<u32, AppError> {
        let c: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM roles", [], |r| r.get(0))
            .map_err(db_err("sync: count_roles"))?;
        Ok(c as u32)
    }
}

impl SyncWebhookOps for SqliteTxScope<'_> {
    fn create_webhook(&self, wh: &Webhook) -> Result<(), AppError> {
        let events_json = serde_json::to_string(&wh.events)
            .map_err(|e| AppError::Internal(format!("json: {e}")))?;
        let now = Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO webhooks (id, url, events_json, format, secret, status, source, created_at, updated_at) \
             VALUES (?1,?2,?3,?4,?5,?6,'config',?7,?7) \
             ON CONFLICT(id) DO UPDATE SET url=?2, events_json=?3, format=?4, secret=?5, status=?6, source='config', updated_at=?7",
            params![wh.id, wh.url, events_json,
                match wh.format { WebhookFormat::Slack => "slack", WebhookFormat::Generic => "generic" },
                wh.secret,
                match wh.status { WebhookStatus::Active => "active", WebhookStatus::Inactive => "inactive" },
                now],
        ).map_err(db_err("sync: create_webhook"))?;
        Ok(())
    }

    fn delete_stale_config_webhooks(&self, active_ids: &[String]) -> Result<u64, AppError> {
        if active_ids.is_empty() {
            let n = self
                .conn
                .execute("DELETE FROM webhooks WHERE source = 'config'", [])
                .map_err(db_err("sync: del_wh"))?;
            return Ok(n as u64);
        }
        let placeholders: String = (1..=active_ids.len())
            .map(|i| format!("?{i}"))
            .collect::<Vec<_>>()
            .join(",");
        let sql =
            format!("DELETE FROM webhooks WHERE source = 'config' AND id NOT IN ({placeholders})");
        let params: Vec<&dyn rusqlite::types::ToSql> = active_ids
            .iter()
            .map(|s| s as &dyn rusqlite::types::ToSql)
            .collect();
        let n = self
            .conn
            .execute(&sql, params.as_slice())
            .map_err(db_err("sync: del_wh"))?;
        Ok(n as u64)
    }

    fn list_active_webhooks(&self) -> Result<Vec<Webhook>, AppError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, url, events_json, format, secret, status, created_at, updated_at FROM webhooks WHERE status = 'active'"
        ).map_err(db_err("sync: list_webhooks"))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                ))
            })
            .map_err(db_err("sync: list_webhooks"))?;
        let mut webhooks = Vec::new();
        for row in rows {
            let (id, url, events_json, format_str, secret, _status, created_at, updated_at) =
                row.map_err(db_err("sync: list_webhooks"))?;
            let events: Vec<String> = serde_json::from_str(&events_json)
                .map_err(|e| AppError::Internal(format!("webhook events json: {e}")))?;
            let format = match format_str.as_str() {
                "slack" => WebhookFormat::Slack,
                _ => WebhookFormat::Generic,
            };
            webhooks.push(Webhook {
                id,
                url,
                events,
                format,
                secret,
                status: WebhookStatus::Active,
                created_at: created_at.and_then(|s| {
                    chrono::DateTime::parse_from_rfc3339(&s)
                        .ok()
                        .map(|d| d.with_timezone(&Utc))
                }),
                updated_at: updated_at.and_then(|s| {
                    chrono::DateTime::parse_from_rfc3339(&s)
                        .ok()
                        .map(|d| d.with_timezone(&Utc))
                }),
            });
        }
        Ok(webhooks)
    }
}

impl SyncConfigGenerationOps for SqliteTxScope<'_> {
    fn record_generation(
        &self,
        digest: &str,
        synced_at: DateTime<Utc>,
        summary_json: &str,
    ) -> Result<(), AppError> {
        self.conn.execute(
            "INSERT INTO config_generations (config_digest, synced_at, summary_json) VALUES (?1, ?2, ?3)",
            params![digest, synced_at.to_rfc3339(), summary_json],
        ).map_err(db_err("sync: record_generation"))?;
        Ok(())
    }
}
