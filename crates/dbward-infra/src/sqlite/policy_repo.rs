use rusqlite::{params, OptionalExtension};

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
        let conn = self.conn.blocking_lock();
        let operations_json = serde_json::to_string(&wf.operations).map_err(|e| AppError::Internal(e.to_string()))?;
        let steps_json = serde_json::to_string(&wf.steps).map_err(|e| AppError::Internal(e.to_string()))?;
        let skip_json = serde_json::to_string(&wf.skip_approval_for).map_err(|e| AppError::Internal(e.to_string()))?;
        conn.execute(
            "INSERT INTO workflows (id, database_name, environment, operations_json, steps_json, skip_approval_for_json, require_reason, allow_self_approve, allow_same_approver_across_steps, pending_ttl_secs, approval_ttl_secs)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
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
            ],
        ).map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(())
    }

    fn get_workflow(&self, id: &str) -> Result<Option<Workflow>, AppError> {
        let conn = self.conn.blocking_lock();
        conn.query_row(
            "SELECT id, database_name, environment, operations_json, steps_json, skip_approval_for_json, require_reason, allow_self_approve, allow_same_approver_across_steps, pending_ttl_secs, approval_ttl_secs
             FROM workflows WHERE id = ?1",
            params![id],
            row_to_workflow,
        )
        .optional()
        .map_err(|e| AppError::Internal(e.to_string()))?
        .map(|r| r)
        .transpose()
    }

    fn list_workflows(&self) -> Result<Vec<Workflow>, AppError> {
        let conn = self.conn.blocking_lock();
        let mut stmt = conn.prepare(
            "SELECT id, database_name, environment, operations_json, steps_json, skip_approval_for_json, require_reason, allow_self_approve, allow_same_approver_across_steps, pending_ttl_secs, approval_ttl_secs FROM workflows",
        ).map_err(|e| AppError::Internal(e.to_string()))?;
        let rows = stmt.query_map([], row_to_workflow).map_err(|e| AppError::Internal(e.to_string()))?;
        let mut results = Vec::new();
        for row in rows {
            let r = row.map_err(|e| AppError::Internal(e.to_string()))?;
            results.push(r.map_err(|e| AppError::Internal(e.to_string()))?);
        }
        Ok(results)
    }

    fn delete_workflow(&self, id: &str) -> Result<bool, AppError> {
        let conn = self.conn.blocking_lock();
        let changed = conn.execute("DELETE FROM workflows WHERE id = ?1", params![id])
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(changed > 0)
    }

    fn count_workflows(&self) -> Result<u32, AppError> {
        let conn = self.conn.blocking_lock();
        let count: u32 = conn.query_row("SELECT COUNT(*) FROM workflows", [], |row| row.get(0))
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(count)
    }

    fn create_execution_policy(&self, ep: &ExecutionPolicy) -> Result<(), AppError> {
        let conn = self.conn.blocking_lock();
        conn.execute(
            "INSERT INTO execution_policies (id, database_name, environment, max_executions, execution_window_secs, retry_on_failure, statement_timeout_secs, max_statement_timeout_secs)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                ep.id,
                ep.database.as_str(),
                ep.environment.as_str(),
                ep.max_executions,
                ep.execution_window_secs as i64,
                ep.retry_on_failure,
                ep.statement_timeout_secs,
                ep.max_statement_timeout_secs,
            ],
        ).map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(())
    }

    fn get_execution_policy(&self, id: &str) -> Result<Option<ExecutionPolicy>, AppError> {
        let conn = self.conn.blocking_lock();
        conn.query_row(
            "SELECT id, database_name, environment, max_executions, execution_window_secs, retry_on_failure, statement_timeout_secs, max_statement_timeout_secs
             FROM execution_policies WHERE id = ?1",
            params![id],
            row_to_execution_policy,
        )
        .optional()
        .map_err(|e| AppError::Internal(e.to_string()))?
        .map(|r| r)
        .transpose()
    }

    fn list_execution_policies(&self) -> Result<Vec<ExecutionPolicy>, AppError> {
        let conn = self.conn.blocking_lock();
        let mut stmt = conn.prepare(
            "SELECT id, database_name, environment, max_executions, execution_window_secs, retry_on_failure, statement_timeout_secs, max_statement_timeout_secs FROM execution_policies",
        ).map_err(|e| AppError::Internal(e.to_string()))?;
        let rows = stmt.query_map([], row_to_execution_policy).map_err(|e| AppError::Internal(e.to_string()))?;
        let mut results = Vec::new();
        for row in rows {
            let r = row.map_err(|e| AppError::Internal(e.to_string()))?;
            results.push(r.map_err(|e| AppError::Internal(e.to_string()))?);
        }
        Ok(results)
    }

    fn delete_execution_policy(&self, id: &str) -> Result<bool, AppError> {
        let conn = self.conn.blocking_lock();
        let changed = conn.execute("DELETE FROM execution_policies WHERE id = ?1", params![id])
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(changed > 0)
    }

    fn create_role(&self, role: &RoleDefinition) -> Result<(), AppError> {
        let conn = self.conn.blocking_lock();
        let perms_json = serde_json::to_string(
            &role.permissions.iter().map(|p| p.as_str()).collect::<Vec<_>>()
        ).map_err(|e| AppError::Internal(e.to_string()))?;
        let dbs_json = serde_json::to_string(
            &role.databases.iter().map(|d| d.as_str()).collect::<Vec<_>>()
        ).map_err(|e| AppError::Internal(e.to_string()))?;
        let envs_json = serde_json::to_string(
            &role.environments.iter().map(|e| e.as_str()).collect::<Vec<_>>()
        ).map_err(|e| AppError::Internal(e.to_string()))?;
        conn.execute(
            "INSERT INTO roles (name, permissions_json, databases_json, environments_json, built_in)
             VALUES (?1, ?2, ?3, ?4, 0)",
            params![role.name, perms_json, dbs_json, envs_json],
        ).map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(())
    }

    fn list_roles(&self) -> Result<Vec<RoleDefinition>, AppError> {
        let conn = self.conn.blocking_lock();
        let mut stmt = conn.prepare(
            "SELECT name, permissions_json, databases_json, environments_json FROM roles",
        ).map_err(|e| AppError::Internal(e.to_string()))?;
        let rows = stmt.query_map([], row_to_role).map_err(|e| AppError::Internal(e.to_string()))?;
        let mut results = Vec::new();
        for row in rows {
            let r = row.map_err(|e| AppError::Internal(e.to_string()))?;
            results.push(r.map_err(|e| AppError::Internal(e.to_string()))?);
        }
        Ok(results)
    }

    fn delete_role(&self, name: &str) -> Result<bool, AppError> {
        let conn = self.conn.blocking_lock();
        let changed = conn.execute("DELETE FROM roles WHERE name = ?1 AND built_in = 0", params![name])
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(changed > 0)
    }

    fn count_roles(&self) -> Result<u32, AppError> {
        let conn = self.conn.blocking_lock();
        let count: u32 = conn.query_row("SELECT COUNT(*) FROM roles", [], |row| row.get(0))
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
            let conn = self.conn.blocking_lock();
            let mut stmt = conn.prepare(
                "SELECT id, database_name, environment, operations_json, steps_json, skip_approval_for_json, require_reason, allow_self_approve, allow_same_approver_across_steps, pending_ttl_secs, approval_ttl_secs FROM workflows",
            ).map_err(|e| AppError::Internal(e.to_string()))?;
            let rows = stmt.query_map([], row_to_workflow).map_err(|e| AppError::Internal(e.to_string()))?;
            let mut wfs = Vec::new();
            for row in rows {
                let r = row.map_err(|e| AppError::Internal(e.to_string()))?;
                wfs.push(r.map_err(|e| AppError::Internal(e.to_string()))?);
            }
            wfs
        };
        let matched = dbward_domain::services::workflow_matcher::find_matching_workflow(&workflows, db, env, op);
        Ok(matched.cloned())
    }

    fn get_execution_policy(&self, db: &DatabaseName, env: &Environment) -> ExecutionPolicy {
        let policies = {
            let conn = self.conn.blocking_lock();
            let mut stmt = match conn.prepare(
                "SELECT id, database_name, environment, max_executions, execution_window_secs, retry_on_failure, statement_timeout_secs, max_statement_timeout_secs FROM execution_policies",
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
                if let Ok(Ok(ep)) = row.map(|r| r) {
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

fn specificity_score_ep(policy_db: &DatabaseName, policy_env: &Environment, db: &DatabaseName, env: &Environment) -> u8 {
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

    Ok((|| {
        let database = DatabaseName::new(db_str).map_err(|e| AppError::Internal(e.to_string()))?;
        let environment = Environment::new(env_str).map_err(|e| AppError::Internal(e.to_string()))?;
        let operations = serde_json::from_str(&ops_json).map_err(|e| AppError::Internal(e.to_string()))?;
        let steps = serde_json::from_str(&steps_json).map_err(|e| AppError::Internal(e.to_string()))?;
        let skip_approval_for = serde_json::from_str(&skip_json).map_err(|e| AppError::Internal(e.to_string()))?;
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
            approval_ttl_secs: approval_ttl.map(|v| v as u64),
        })
    })())
}

fn row_to_execution_policy(row: &rusqlite::Row) -> rusqlite::Result<Result<ExecutionPolicy, AppError>> {
    let id: String = row.get(0)?;
    let db_str: String = row.get(1)?;
    let env_str: String = row.get(2)?;
    let max_executions: u32 = row.get(3)?;
    let window: i64 = row.get(4)?;
    let retry: bool = row.get(5)?;
    let timeout: u32 = row.get(6)?;
    let max_timeout: u32 = row.get(7)?;

    Ok((|| {
        let database = DatabaseName::new(db_str).map_err(|e| AppError::Internal(e.to_string()))?;
        let environment = Environment::new(env_str).map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(ExecutionPolicy {
            id,
            database,
            environment,
            max_executions,
            execution_window_secs: window as u64,
            retry_on_failure: retry,
            statement_timeout_secs: timeout,
            max_statement_timeout_secs: max_timeout,
        })
    })())
}

fn row_to_role(row: &rusqlite::Row) -> rusqlite::Result<Result<RoleDefinition, AppError>> {
    let name: String = row.get(0)?;
    let perms_json: String = row.get(1)?;
    let dbs_json: String = row.get(2)?;
    let envs_json: String = row.get(3)?;

    Ok((|| {
        let perm_strs: Vec<String> = serde_json::from_str(&perms_json).map_err(|e| AppError::Internal(e.to_string()))?;
        let permissions: Vec<Permission> = perm_strs.iter()
            .map(|s| s.parse::<Permission>().map_err(|e| AppError::Internal(e)))
            .collect::<Result<_, _>>()?;
        let db_strs: Vec<String> = serde_json::from_str(&dbs_json).map_err(|e| AppError::Internal(e.to_string()))?;
        let databases: Vec<DatabaseName> = db_strs.into_iter()
            .map(|s| DatabaseName::new(s).map_err(|e| AppError::Internal(e.to_string())))
            .collect::<Result<_, _>>()?;
        let env_strs: Vec<String> = serde_json::from_str(&envs_json).map_err(|e| AppError::Internal(e.to_string()))?;
        let environments: Vec<Environment> = env_strs.into_iter()
            .map(|s| Environment::new(s).map_err(|e| AppError::Internal(e.to_string())))
            .collect::<Result<_, _>>()?;
        Ok(RoleDefinition { name, permissions, databases, environments })
    })())
}
