use rusqlite::{OptionalExtension, params};

use dbward_app::error::AppError;
use dbward_app::ports::{PolicyEvaluator, PolicyRepo};
use dbward_domain::auth::{Permission, RoleDefinition};
use dbward_domain::policies::{ExecutionPolicy, Workflow};
use dbward_domain::values::{DatabaseName, Environment, Operation};

use crate::sqlite::DbConn;

// --- SqlitePolicyRepo ---

pub struct SqlitePolicyRepo {
    conn: DbConn,
}

impl SqlitePolicyRepo {
    pub fn new(conn: DbConn) -> Self {
        Self { conn }
    }
}

impl PolicyRepo for SqlitePolicyRepo {
    fn create_workflow(&self, wf: &Workflow) -> Result<(), AppError> {
        let conn = self.conn.lock().unwrap();
        let operations_json =
            serde_json::to_string(&wf.operations).map_err(|e| AppError::Internal(e.to_string()))?;
        let steps_json =
            serde_json::to_string(&wf.steps).map_err(|e| AppError::Internal(e.to_string()))?;
        let skip_json = serde_json::to_string(&wf.skip_approval_for)
            .map_err(|e| AppError::Internal(e.to_string()))?;
        conn.execute(
            "INSERT INTO workflows (id, database_name, environment, operations_json, steps_json, skip_approval_for_json, require_reason, allow_self_approve, allow_same_approver_across_steps, pending_ttl_secs, approval_ttl_secs, statement_timeout_secs)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                wf.id,
                wf.database.as_str(),
                wf.environment.as_str(),
                operations_json,
                steps_json,
                skip_json,
                wf.require_reason,
                wf.allow_self_approve,
                wf.allow_same_approver_across_steps,
                wf.pending_ttl_secs.map(|v| v as i64),
                wf.approval_ttl_secs.map(|v| v as i64),
                wf.statement_timeout_secs.map(|v| v as i64),
            ],
        ).map_err(|e| {
            if e.to_string().contains("UNIQUE constraint failed") {
                AppError::Conflict("already exists".into())
            } else {
                AppError::Internal(e.to_string())
            }
        })?;
        Ok(())
    }

    fn get_workflow(&self, id: &str) -> Result<Option<Workflow>, AppError> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT id, database_name, environment, operations_json, steps_json, skip_approval_for_json, require_reason, allow_self_approve, allow_same_approver_across_steps, pending_ttl_secs, approval_ttl_secs, statement_timeout_secs
             FROM workflows WHERE id = ?1",
            params![id],
            row_to_workflow,
        )
        .optional()
        .map_err(|e| AppError::Internal(e.to_string()))?
        .transpose()
    }

    fn list_workflows(&self) -> Result<Vec<Workflow>, AppError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, database_name, environment, operations_json, steps_json, skip_approval_for_json, require_reason, allow_self_approve, allow_same_approver_across_steps, pending_ttl_secs, approval_ttl_secs, statement_timeout_secs FROM workflows",
        ).map_err(|e| AppError::Internal(e.to_string()))?;
        let rows = stmt
            .query_map([], row_to_workflow)
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let mut results = Vec::new();
        for row in rows {
            let r = row.map_err(|e| AppError::Internal(e.to_string()))?;
            results.push(r.map_err(|e| AppError::Internal(e.to_string()))?);
        }
        Ok(results)
    }

    fn delete_workflow(&self, id: &str) -> Result<bool, AppError> {
        let conn = self.conn.lock().unwrap();
        let changed = conn
            .execute("DELETE FROM workflows WHERE id = ?1", params![id])
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(changed > 0)
    }

    fn count_workflows(&self) -> Result<u32, AppError> {
        let conn = self.conn.lock().unwrap();
        let count: u32 = conn
            .query_row("SELECT COUNT(*) FROM workflows", [], |row| row.get(0))
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(count)
    }

    fn create_execution_policy(&self, ep: &ExecutionPolicy) -> Result<(), AppError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO execution_policies (id, database_name, environment, max_executions, execution_window_secs, retry_on_failure, statement_timeout_secs, max_statement_timeout_secs, max_rows)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                ep.id,
                ep.database.as_str(),
                ep.environment.as_str(),
                ep.max_executions,
                ep.execution_window_secs as i64,
                ep.retry_on_failure,
                ep.statement_timeout_secs,
                ep.max_statement_timeout_secs,
                ep.max_rows.map(|v| v as i64),
            ],
        ).map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(())
    }

    fn get_execution_policy(&self, id: &str) -> Result<Option<ExecutionPolicy>, AppError> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT id, database_name, environment, max_executions, execution_window_secs, retry_on_failure, statement_timeout_secs, max_statement_timeout_secs, max_rows
             FROM execution_policies WHERE id = ?1",
            params![id],
            row_to_execution_policy,
        )
        .optional()
        .map_err(|e| AppError::Internal(e.to_string()))?
        .transpose()
    }

    fn list_execution_policies(&self) -> Result<Vec<ExecutionPolicy>, AppError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, database_name, environment, max_executions, execution_window_secs, retry_on_failure, statement_timeout_secs, max_statement_timeout_secs, max_rows FROM execution_policies",
        ).map_err(|e| AppError::Internal(e.to_string()))?;
        let rows = stmt
            .query_map([], row_to_execution_policy)
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let mut results = Vec::new();
        for row in rows {
            let r = row.map_err(|e| AppError::Internal(e.to_string()))?;
            results.push(r.map_err(|e| AppError::Internal(e.to_string()))?);
        }
        Ok(results)
    }

    fn delete_execution_policy(&self, id: &str) -> Result<bool, AppError> {
        let conn = self.conn.lock().unwrap();
        let changed = conn
            .execute("DELETE FROM execution_policies WHERE id = ?1", params![id])
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(changed > 0)
    }

    fn find_result_policy(
        &self,
        db: &DatabaseName,
        env: &Environment,
    ) -> Result<Option<dbward_domain::policies::ResultPolicy>, AppError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, database_name, environment, retention_days, delivery_mode, access_json FROM result_policies",
        ).map_err(|e| AppError::Internal(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, u32>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let mut best: Option<dbward_domain::policies::ResultPolicy> = None;
        let mut best_score: u8 = 0;

        for row in rows {
            let (id, db_str, env_str, retention_days, delivery_str, access_json) =
                row.map_err(|e| AppError::Internal(e.to_string()))?;
            let policy_db =
                DatabaseName::new(&db_str).map_err(|e| AppError::Internal(e.to_string()))?;
            let policy_env =
                Environment::new(&env_str).map_err(|e| AppError::Internal(e.to_string()))?;

            if !scope_matches_db(&policy_db, db) || !scope_matches_env(&policy_env, env) {
                continue;
            }
            let score = specificity_score_ep(&policy_db, &policy_env, db, env);
            if score > best_score || best.is_none() {
                let delivery_mode: dbward_domain::policies::DeliveryMode =
                    serde_json::from_value(serde_json::Value::String(delivery_str))
                        .unwrap_or_default();
                let access_strs: Vec<String> =
                    serde_json::from_str(&access_json).unwrap_or_default();
                let access = access_strs
                    .iter()
                    .filter_map(|s| dbward_domain::values::Selector::parse(s).ok())
                    .collect();
                best = Some(dbward_domain::policies::ResultPolicy {
                    id,
                    database: policy_db,
                    environment: policy_env,
                    retention_days,
                    delivery_mode,
                    access,
                    created_at: None,
                    updated_at: None,
                });
                best_score = score;
            }
        }
        Ok(best)
    }

    fn create_result_policy(
        &self,
        policy: &dbward_domain::policies::ResultPolicy,
    ) -> Result<(), AppError> {
        let conn = self.conn.lock().unwrap();
        let access_json = serde_json::to_string(
            &policy
                .access
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;
        let delivery_str = serde_json::to_string(&policy.delivery_mode)
            .map_err(|e| AppError::Internal(e.to_string()))?
            .trim_matches('"')
            .to_string();
        conn.execute(
            "INSERT INTO result_policies (id, database_name, environment, retention_days, delivery_mode, access_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                policy.id,
                policy.database.as_str(),
                policy.environment.as_str(),
                policy.retention_days,
                delivery_str,
                access_json,
            ],
        )
        .map_err(|e| {
            if let rusqlite::Error::SqliteFailure(ref err, _) = e
                && err.extended_code == 2067
            {
                return AppError::Conflict(
                    "result policy already exists for this database/environment".into(),
                );
            }
            AppError::Internal(e.to_string())
        })?;
        Ok(())
    }

    fn get_result_policy(
        &self,
        id: &str,
    ) -> Result<Option<dbward_domain::policies::ResultPolicy>, AppError> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT id, database_name, environment, retention_days, delivery_mode, access_json FROM result_policies WHERE id = ?1",
            params![id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, u32>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        )
        .optional()
        .map_err(|e| AppError::Internal(e.to_string()))?
        .map(|(id, db_str, env_str, retention_days, delivery_str, access_json)| {
            let database =
                DatabaseName::new(&db_str).map_err(|e| AppError::Internal(e.to_string()))?;
            let environment =
                Environment::new(&env_str).map_err(|e| AppError::Internal(e.to_string()))?;
            let delivery_mode: dbward_domain::policies::DeliveryMode =
                serde_json::from_value(serde_json::Value::String(delivery_str))
                    .unwrap_or_default();
            let access_strs: Vec<String> = serde_json::from_str(&access_json)
                .map_err(|e| AppError::Internal(e.to_string()))?;
            let access = access_strs
                .iter()
                .filter_map(|s| dbward_domain::values::Selector::parse(s).ok())
                .collect();
            Ok(dbward_domain::policies::ResultPolicy {
                id,
                database,
                environment,
                retention_days,
                delivery_mode,
                access,
                created_at: None,
                updated_at: None,
            })
        })
        .transpose()
    }

    fn list_result_policies(&self) -> Result<Vec<dbward_domain::policies::ResultPolicy>, AppError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT id, database_name, environment, retention_days, delivery_mode, access_json FROM result_policies")
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, u32>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let mut result = Vec::new();
        for row in rows {
            let (id, db_str, env_str, retention_days, delivery_str, access_json) =
                row.map_err(|e| AppError::Internal(e.to_string()))?;
            let database =
                DatabaseName::new(&db_str).map_err(|e| AppError::Internal(e.to_string()))?;
            let environment =
                Environment::new(&env_str).map_err(|e| AppError::Internal(e.to_string()))?;
            let delivery_mode: dbward_domain::policies::DeliveryMode =
                serde_json::from_value(serde_json::Value::String(delivery_str)).unwrap_or_default();
            let access_strs: Vec<String> = serde_json::from_str(&access_json).unwrap_or_default();
            let access = access_strs
                .iter()
                .filter_map(|s| dbward_domain::values::Selector::parse(s).ok())
                .collect();
            result.push(dbward_domain::policies::ResultPolicy {
                id,
                database,
                environment,
                retention_days,
                delivery_mode,
                access,
                created_at: None,
                updated_at: None,
            });
        }
        Ok(result)
    }

    fn update_result_policy(
        &self,
        policy: &dbward_domain::policies::ResultPolicy,
    ) -> Result<bool, AppError> {
        let conn = self.conn.lock().unwrap();
        let access_json = serde_json::to_string(
            &policy
                .access
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;
        let delivery_str = serde_json::to_string(&policy.delivery_mode)
            .map_err(|e| AppError::Internal(e.to_string()))?
            .trim_matches('"')
            .to_string();
        let changed = conn
            .execute(
                "UPDATE result_policies SET retention_days = ?1, delivery_mode = ?2, access_json = ?3 WHERE id = ?4",
                params![policy.retention_days, delivery_str, access_json, policy.id],
            )
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(changed > 0)
    }

    fn delete_result_policy(&self, id: &str) -> Result<bool, AppError> {
        let conn = self.conn.lock().unwrap();
        let changed = conn
            .execute("DELETE FROM result_policies WHERE id = ?1", params![id])
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(changed > 0)
    }

    fn create_notification_policy(
        &self,
        policy: &dbward_domain::policies::NotificationPolicy,
    ) -> Result<(), AppError> {
        let conn = self.conn.lock().unwrap();
        let webhooks_json = serde_json::to_string(&policy.webhooks)
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let events_json =
            serde_json::to_string(&policy.events).map_err(|e| AppError::Internal(e.to_string()))?;
        conn.execute(
            "INSERT INTO notification_policies (id, database_name, environment, webhooks_json, events_json) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                policy.id,
                policy.database.as_str(),
                policy.environment.as_str(),
                webhooks_json,
                events_json,
            ],
        )
        .map_err(|e| {
            if let rusqlite::Error::SqliteFailure(ref err, _) = e
                && err.extended_code == 2067
            {
                return AppError::Conflict(
                    "notification policy already exists for this database/environment".into(),
                );
            }
            AppError::Internal(e.to_string())
        })?;
        Ok(())
    }

    fn get_notification_policy(
        &self,
        id: &str,
    ) -> Result<Option<dbward_domain::policies::NotificationPolicy>, AppError> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT id, database_name, environment, webhooks_json, events_json FROM notification_policies WHERE id = ?1",
            params![id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()
        .map_err(|e| AppError::Internal(e.to_string()))?
        .map(|(id, db_str, env_str, webhooks_json, events_json)| {
            let database =
                DatabaseName::new(&db_str).map_err(|e| AppError::Internal(e.to_string()))?;
            let environment =
                Environment::new(&env_str).map_err(|e| AppError::Internal(e.to_string()))?;
            let webhooks: Vec<String> = serde_json::from_str(&webhooks_json)
                .map_err(|e| AppError::Internal(e.to_string()))?;
            let events: Vec<String> = serde_json::from_str(&events_json)
                .map_err(|e| AppError::Internal(e.to_string()))?;
            Ok(dbward_domain::policies::NotificationPolicy {
                id,
                database,
                environment,
                webhooks,
                events,
            })
        })
        .transpose()
    }

    fn list_notification_policies(
        &self,
    ) -> Result<Vec<dbward_domain::policies::NotificationPolicy>, AppError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT id, database_name, environment, webhooks_json, events_json FROM notification_policies")
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let mut result = Vec::new();
        for row in rows {
            let (id, db_str, env_str, webhooks_json, events_json) =
                row.map_err(|e| AppError::Internal(e.to_string()))?;
            let database =
                DatabaseName::new(&db_str).map_err(|e| AppError::Internal(e.to_string()))?;
            let environment =
                Environment::new(&env_str).map_err(|e| AppError::Internal(e.to_string()))?;
            let webhooks: Vec<String> = serde_json::from_str(&webhooks_json).unwrap_or_default();
            let events: Vec<String> = serde_json::from_str(&events_json).unwrap_or_default();
            result.push(dbward_domain::policies::NotificationPolicy {
                id,
                database,
                environment,
                webhooks,
                events,
            });
        }
        Ok(result)
    }

    fn update_notification_policy(
        &self,
        policy: &dbward_domain::policies::NotificationPolicy,
    ) -> Result<bool, AppError> {
        let conn = self.conn.lock().unwrap();
        let webhooks_json = serde_json::to_string(&policy.webhooks)
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let events_json =
            serde_json::to_string(&policy.events).map_err(|e| AppError::Internal(e.to_string()))?;
        let changed = conn
            .execute(
                "UPDATE notification_policies SET webhooks_json = ?1, events_json = ?2 WHERE id = ?3",
                params![webhooks_json, events_json, policy.id],
            )
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(changed > 0)
    }

    fn delete_notification_policy(&self, id: &str) -> Result<bool, AppError> {
        let conn = self.conn.lock().unwrap();
        let changed = conn
            .execute(
                "DELETE FROM notification_policies WHERE id = ?1",
                params![id],
            )
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(changed > 0)
    }

    fn create_role(&self, role: &RoleDefinition) -> Result<(), AppError> {
        let conn = self.conn.lock().unwrap();
        let perms_json = serde_json::to_string(
            &role
                .permissions
                .iter()
                .map(|p| p.as_str())
                .collect::<Vec<_>>(),
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;
        let dbs_json = serde_json::to_string(
            &role
                .databases
                .iter()
                .map(|d| d.as_str())
                .collect::<Vec<_>>(),
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;
        let envs_json = serde_json::to_string(
            &role
                .environments
                .iter()
                .map(|e| e.as_str())
                .collect::<Vec<_>>(),
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;
        conn.execute(
            "INSERT INTO roles (name, permissions_json, databases_json, environments_json, built_in)
             VALUES (?1, ?2, ?3, ?4, 0)",
            params![role.name, perms_json, dbs_json, envs_json],
        ).map_err(|e| {
            if e.to_string().contains("UNIQUE constraint failed") {
                AppError::Conflict("already exists".into())
            } else {
                AppError::Internal(e.to_string())
            }
        })?;
        Ok(())
    }

    fn list_roles(&self) -> Result<Vec<RoleDefinition>, AppError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT name, permissions_json, databases_json, environments_json FROM roles")
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let rows = stmt
            .query_map([], row_to_role)
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let mut results = Vec::new();
        for row in rows {
            let r = row.map_err(|e| AppError::Internal(e.to_string()))?;
            results.push(r.map_err(|e| AppError::Internal(e.to_string()))?);
        }
        Ok(results)
    }

    fn get_roles_by_names(&self, names: &[String]) -> Result<Vec<RoleDefinition>, AppError> {
        if names.is_empty() {
            return Ok(Vec::new());
        }
        let conn = self.conn.lock().unwrap();
        let placeholders = std::iter::repeat_n("?", names.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT name, permissions_json, databases_json, environments_json FROM roles WHERE name IN ({})",
            placeholders
        );
        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let params: Vec<&dyn rusqlite::types::ToSql> = names
            .iter()
            .map(|n| n as &dyn rusqlite::types::ToSql)
            .collect();
        let rows = stmt
            .query_map(params.as_slice(), row_to_role)
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let mut results = Vec::new();
        for row in rows {
            let r = row.map_err(|e| AppError::Internal(e.to_string()))?;
            results.push(r.map_err(|e| AppError::Internal(e.to_string()))?);
        }
        Ok(results)
    }

    fn delete_role(&self, name: &str) -> Result<bool, AppError> {
        let conn = self.conn.lock().unwrap();
        let changed = conn
            .execute(
                "DELETE FROM roles WHERE name = ?1 AND built_in = 0",
                params![name],
            )
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(changed > 0)
    }

    fn count_roles(&self) -> Result<u32, AppError> {
        let conn = self.conn.lock().unwrap();
        let count: u32 = conn
            .query_row("SELECT COUNT(*) FROM roles", [], |row| row.get(0))
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(count)
    }
}

// --- SqlitePolicyEvaluator ---

pub struct SqlitePolicyEvaluator {
    conn: DbConn,
}

impl SqlitePolicyEvaluator {
    pub fn new(conn: DbConn) -> Self {
        Self { conn }
    }
}

impl PolicyEvaluator for SqlitePolicyEvaluator {
    fn evaluate_workflow(
        &self,
        db: &DatabaseName,
        env: &Environment,
        op: Operation,
    ) -> Result<Option<Workflow>, AppError> {
        let workflows = {
            let conn = self.conn.lock().unwrap();
            let mut stmt = conn.prepare(
                "SELECT id, database_name, environment, operations_json, steps_json, skip_approval_for_json, require_reason, allow_self_approve, allow_same_approver_across_steps, pending_ttl_secs, approval_ttl_secs, statement_timeout_secs FROM workflows",
            ).map_err(|e| AppError::Internal(e.to_string()))?;
            let rows = stmt
                .query_map([], row_to_workflow)
                .map_err(|e| AppError::Internal(e.to_string()))?;
            let mut wfs = Vec::new();
            for row in rows {
                let r = row.map_err(|e| AppError::Internal(e.to_string()))?;
                wfs.push(r.map_err(|e| AppError::Internal(e.to_string()))?);
            }
            wfs
        };
        let matched = dbward_domain::services::workflow_matcher::find_matching_workflow(
            &workflows, db, env, op,
        );
        Ok(matched.cloned())
    }

    fn get_execution_policy(&self, db: &DatabaseName, env: &Environment) -> ExecutionPolicy {
        let policies = {
            let conn = self.conn.lock().unwrap();
            let mut stmt = match conn.prepare(
                "SELECT id, database_name, environment, max_executions, execution_window_secs, retry_on_failure, statement_timeout_secs, max_statement_timeout_secs, max_rows FROM execution_policies",
            ) {
                Ok(s) => s,
                Err(_) => return ExecutionPolicy::default(),
            };
            let rows = match stmt.query_map([], row_to_execution_policy) {
                Ok(r) => r,
                Err(_) => return ExecutionPolicy::default(),
            };
            let mut eps = Vec::new();
            for row in rows {
                if let Ok(Ok(ep)) = row {
                    eps.push(ep);
                }
            }
            eps
        };

        // 4-level lookup: exact > (*, env) > (db, *) > (*, *)
        let mut best: Option<&ExecutionPolicy> = None;
        let mut best_score: u8 = 0;
        for ep in &policies {
            if !scope_matches_db(&ep.database, db) || !scope_matches_env(&ep.environment, env) {
                continue;
            }
            let score = specificity_score_ep(&ep.database, &ep.environment, db, env);
            if score > best_score || best.is_none() {
                best = Some(ep);
                best_score = score;
            }
        }
        best.cloned().unwrap_or_default()
    }
}

fn scope_matches_db(policy_db: &DatabaseName, request_db: &DatabaseName) -> bool {
    policy_db.is_wildcard() || policy_db == request_db
}

fn scope_matches_env(policy_env: &Environment, request_env: &Environment) -> bool {
    policy_env.is_wildcard() || policy_env == request_env
}

fn specificity_score_ep(
    policy_db: &DatabaseName,
    policy_env: &Environment,
    db: &DatabaseName,
    env: &Environment,
) -> u8 {
    let mut score = 0u8;
    if !policy_env.is_wildcard() && policy_env == env {
        score += 2;
    }
    if !policy_db.is_wildcard() && policy_db == db {
        score += 1;
    }
    score
}

// --- Row parsers ---

fn row_to_workflow(row: &rusqlite::Row) -> rusqlite::Result<Result<Workflow, AppError>> {
    let id: String = row.get(0)?;
    let db_str: String = row.get(1)?;
    let env_str: String = row.get(2)?;
    let ops_json: String = row.get(3)?;
    let steps_json: String = row.get(4)?;
    let skip_json: String = row.get(5)?;
    let require_reason: bool = row.get(6)?;
    let allow_self_approve: bool = row.get(7)?;
    let allow_same: bool = row.get(8)?;
    let pending_ttl: Option<i64> = row.get(9)?;
    let approval_ttl: Option<i64> = row.get(10)?;
    let stmt_timeout: Option<i64> = row.get(11)?;

    Ok((|| {
        let database = DatabaseName::new(db_str).map_err(|e| AppError::Internal(e.to_string()))?;
        let environment =
            Environment::new(env_str).map_err(|e| AppError::Internal(e.to_string()))?;
        let operations =
            serde_json::from_str(&ops_json).map_err(|e| AppError::Internal(e.to_string()))?;
        let steps =
            serde_json::from_str(&steps_json).map_err(|e| AppError::Internal(e.to_string()))?;
        let skip_approval_for =
            serde_json::from_str(&skip_json).map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(Workflow {
            id,
            database,
            environment,
            operations,
            steps,
            skip_approval_for,
            require_reason,
            allow_self_approve,
            allow_same_approver_across_steps: allow_same,
            pending_ttl_secs: pending_ttl.map(|v| v as u64),
            statement_timeout_secs: stmt_timeout.map(|v| v as u64),
            approval_ttl_secs: approval_ttl.map(|v| v as u64),
            created_at: None,
            updated_at: None,
        })
    })())
}

fn row_to_execution_policy(
    row: &rusqlite::Row,
) -> rusqlite::Result<Result<ExecutionPolicy, AppError>> {
    let id: String = row.get(0)?;
    let db_str: String = row.get(1)?;
    let env_str: String = row.get(2)?;
    let max_executions: u32 = row.get(3)?;
    let window: i64 = row.get(4)?;
    let retry: bool = row.get(5)?;
    let timeout: u32 = row.get(6)?;
    let max_timeout: u32 = row.get(7)?;
    let max_rows: Option<u32> = row.get::<_, Option<u32>>(8).unwrap_or(None);

    Ok((|| {
        let database = DatabaseName::new(db_str).map_err(|e| AppError::Internal(e.to_string()))?;
        let environment =
            Environment::new(env_str).map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(ExecutionPolicy {
            id,
            database,
            environment,
            max_executions,
            execution_window_secs: window as u64,
            retry_on_failure: retry,
            statement_timeout_secs: timeout,
            max_statement_timeout_secs: max_timeout,
            max_rows,
            created_at: None,
            updated_at: None,
        })
    })())
}

fn row_to_role(row: &rusqlite::Row) -> rusqlite::Result<Result<RoleDefinition, AppError>> {
    let name: String = row.get(0)?;
    let perms_json: String = row.get(1)?;
    let dbs_json: String = row.get(2)?;
    let envs_json: String = row.get(3)?;

    Ok((|| {
        let perm_strs: Vec<String> =
            serde_json::from_str(&perms_json).map_err(|e| AppError::Internal(e.to_string()))?;
        let permissions: Vec<Permission> = perm_strs
            .iter()
            .map(|s| s.parse::<Permission>().map_err(AppError::Internal))
            .collect::<Result<_, _>>()?;
        let db_strs: Vec<String> =
            serde_json::from_str(&dbs_json).map_err(|e| AppError::Internal(e.to_string()))?;
        let databases: Vec<DatabaseName> = db_strs
            .into_iter()
            .map(|s| DatabaseName::new(s).map_err(|e| AppError::Internal(e.to_string())))
            .collect::<Result<_, _>>()?;
        let env_strs: Vec<String> =
            serde_json::from_str(&envs_json).map_err(|e| AppError::Internal(e.to_string()))?;
        let environments: Vec<Environment> = env_strs
            .into_iter()
            .map(|s| Environment::new(s).map_err(|e| AppError::Internal(e.to_string())))
            .collect::<Result<_, _>>()?;
        Ok(RoleDefinition {
            name,
            permissions,
            databases,
            environments,
        })
    })())
}
