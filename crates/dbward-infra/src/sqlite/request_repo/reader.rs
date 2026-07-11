use std::collections::HashMap;

use rusqlite::params;

use dbward_app::error::AppError;
use dbward_app::ports::RequestReader;
use dbward_domain::entities::Request;

use super::{SqliteRequestRepo, build_selectors, row_to_request};
use crate::sqlite::error::db_err;

impl RequestReader for SqliteRequestRepo {
    fn get(&self, id: &str) -> Result<Option<Request>, AppError> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT * FROM requests WHERE id = ?1")
            .map_err(db_err("request: get"))?;
        let mut rows = stmt
            .query_and_then(params![id], row_to_request)
            .map_err(db_err("request: get"))?;
        match rows.next() {
            Some(r) => Ok(Some(r.map_err(db_err("request: get"))?)),
            None => Ok(None),
        }
    }
    fn list(
        &self,
        limit: u32,
        offset: u32,
        status: Option<&str>,
        user: Option<&str>,
    ) -> Result<(Vec<Request>, u32), AppError> {
        let conn = self.conn.lock();

        let mut conditions = Vec::new();
        let mut count_params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(s) = status {
            conditions.push("status = ?".to_string());
            count_params.push(Box::new(s.to_string()));
        }
        if let Some(u) = user {
            conditions.push("requester = ?".to_string());
            count_params.push(Box::new(u.to_string()));
        }

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", conditions.join(" AND "))
        };

        let count_sql = format!("SELECT COUNT(*) FROM requests{}", where_clause);
        let total: u32 = conn
            .query_row(
                &count_sql,
                rusqlite::params_from_iter(count_params.iter().map(|p| p.as_ref())),
                |r| r.get(0),
            )
            .map_err(db_err("request: list"))?;

        // NOTE: SELECT * includes decision_trace_json which is unused in list responses.
        // Acceptable for now (SQLite reads full row regardless), but could be optimised
        // with an explicit column list if the column grows large.
        let query_sql = format!(
            "SELECT * FROM requests{} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            where_clause
        );
        let mut query_params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        if let Some(s) = status {
            query_params.push(Box::new(s.to_string()));
        }
        if let Some(u) = user {
            query_params.push(Box::new(u.to_string()));
        }
        query_params.push(Box::new(limit));
        query_params.push(Box::new(offset));

        let mut stmt = conn.prepare(&query_sql).map_err(db_err("request: list"))?;
        let rows = stmt
            .query_and_then(
                rusqlite::params_from_iter(query_params.iter().map(|p| p.as_ref())),
                row_to_request,
            )
            .map_err(db_err("request: list"))?;
        let items = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err("request: list"))?;
        Ok((items, total))
    }
    fn find_by_idempotency_key(
        &self,
        requester: &str,
        key: &str,
    ) -> Result<Option<Request>, AppError> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT * FROM requests WHERE idempotency_key = ?1 AND requester = ?2")
            .map_err(db_err("request: find_by_idempotency_key"))?;
        let mut rows = stmt
            .query_and_then(params![key, requester], row_to_request)
            .map_err(db_err("request: find_by_idempotency_key"))?;
        match rows.next() {
            Some(r) => Ok(Some(r.map_err(db_err("request: find_by_idempotency_key"))?)),
            None => Ok(None),
        }
    }
    fn list_visible_to_user(
        &self,
        user_id: &str,
        groups: &[String],
        roles: &[String],
        status: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> Result<(Vec<Request>, u32), AppError> {
        let conn = self.conn.lock();

        let mut selectors = vec![format!("user:{user_id}")];
        for g in groups {
            selectors.push(format!("group:{g}"));
        }
        for r in roles {
            selectors.push(format!("role:{r}"));
        }
        let placeholders: String = selectors
            .iter()
            .enumerate()
            .map(|(i, _)| format!("?{}", i + 1))
            .collect::<Vec<_>>()
            .join(",");

        let uid_idx = selectors.len() + 1;

        let status_clause = if status.is_some() {
            format!(" AND r.status = ?{}", uid_idx + 1)
        } else {
            String::new()
        };

        let sql = format!(
            "SELECT COUNT(DISTINCT r.id) FROM requests r
             LEFT JOIN request_pending_approvers rpa ON r.id = rpa.request_id
             LEFT JOIN approvals a ON r.id = a.request_id AND a.actor_id = ?{uid_idx}
             WHERE (r.requester = ?{uid_idx} OR (r.status = 'pending' AND rpa.selector IN ({placeholders})) OR a.actor_id IS NOT NULL){status_clause}"
        );
        let query_sql = format!(
            "SELECT DISTINCT r.* FROM requests r
             LEFT JOIN request_pending_approvers rpa ON r.id = rpa.request_id
             LEFT JOIN approvals a ON r.id = a.request_id AND a.actor_id = ?{uid_idx}
             WHERE (r.requester = ?{uid_idx} OR (r.status = 'pending' AND rpa.selector IN ({placeholders})) OR a.actor_id IS NOT NULL){status_clause}
             ORDER BY r.created_at DESC LIMIT ?{} OFFSET ?{}",
            uid_idx + if status.is_some() { 2 } else { 1 },
            uid_idx + if status.is_some() { 3 } else { 2 },
        );

        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = selectors
            .into_iter()
            .map(|s| Box::new(s) as Box<dyn rusqlite::types::ToSql>)
            .collect();
        params.push(Box::new(user_id.to_string()));
        if let Some(s) = status {
            params.push(Box::new(s.to_string()));
        }

        let count_refs: Vec<&dyn rusqlite::types::ToSql> =
            params.iter().map(|p| p.as_ref()).collect();
        let total: u32 = conn
            .query_row(&sql, count_refs.as_slice(), |row| row.get(0))
            .map_err(db_err("request: list_visible_to_user"))?;

        params.push(Box::new(limit));
        params.push(Box::new(offset));
        let query_refs: Vec<&dyn rusqlite::types::ToSql> =
            params.iter().map(|p| p.as_ref()).collect();

        let mut stmt = conn
            .prepare(&query_sql)
            .map_err(db_err("request: list_visible_to_user"))?;
        let rows = stmt
            .query_and_then(query_refs.as_slice(), row_to_request)
            .map_err(db_err("request: list_visible_to_user"))?;
        let requests: Vec<Request> = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err("request: list_visible_to_user"))?;
        Ok((requests, total))
    }
    fn list_pending_for_user(
        &self,
        user_id: &str,
        groups: &[String],
        roles: &[String],
        limit: u32,
        offset: u32,
    ) -> Result<(Vec<Request>, u32), AppError> {
        let conn = self.conn.lock();
        let selectors = build_selectors(user_id, groups, roles);
        let placeholders: String = selectors
            .iter()
            .enumerate()
            .map(|(i, _)| format!("?{}", i + 1))
            .collect::<Vec<_>>()
            .join(",");
        let count_sql = format!(
            "SELECT COUNT(DISTINCT r.id) FROM requests r
             JOIN request_pending_approvers rpa ON r.id = rpa.request_id
             WHERE r.status = 'pending' AND rpa.selector IN ({placeholders})"
        );
        let query_sql = format!(
            "SELECT DISTINCT r.* FROM requests r
             JOIN request_pending_approvers rpa ON r.id = rpa.request_id
             WHERE r.status = 'pending' AND rpa.selector IN ({placeholders})
             ORDER BY r.created_at DESC
             LIMIT {} OFFSET {}",
            limit, offset
        );
        let params: Vec<Box<dyn rusqlite::types::ToSql>> = selectors
            .into_iter()
            .map(|s| Box::new(s) as Box<dyn rusqlite::types::ToSql>)
            .collect();
        let param_refs: Vec<&dyn rusqlite::types::ToSql> =
            params.iter().map(|p| p.as_ref()).collect();

        let total: u32 = conn
            .query_row(&count_sql, param_refs.as_slice(), |row| row.get(0))
            .map_err(db_err("request: list_pending_for_user"))?;

        let mut stmt = conn
            .prepare(&query_sql)
            .map_err(db_err("request: list_pending_for_user"))?;
        let rows = stmt
            .query_and_then(param_refs.as_slice(), row_to_request)
            .map_err(db_err("request: list_pending_for_user"))?;
        let requests: Vec<Request> = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err("request: list_pending_for_user"))?;
        Ok((requests, total))
    }
    fn is_pending_approver(
        &self,
        request_id: &str,
        user_id: &str,
        groups: &[String],
        roles: &[String],
    ) -> Result<bool, AppError> {
        let conn = self.conn.lock();
        let selectors = build_selectors(user_id, groups, roles);
        let sel_placeholders: String = selectors
            .iter()
            .enumerate()
            .map(|(i, _)| format!("?{}", i + 2))
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT 1 FROM request_pending_approvers rpa
             JOIN requests r ON r.id = rpa.request_id
             WHERE rpa.request_id = ?1 AND r.status = 'pending'
               AND rpa.selector IN ({sel_placeholders})
             LIMIT 1"
        );
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> =
            vec![Box::new(request_id.to_string())];
        for s in selectors {
            params.push(Box::new(s));
        }
        let param_refs: Vec<&dyn rusqlite::types::ToSql> =
            params.iter().map(|p| p.as_ref()).collect();
        let exists: bool = conn
            .query_row(&sql, param_refs.as_slice(), |_| Ok(true))
            .unwrap_or(false);
        Ok(exists)
    }
    fn count_executions(&self, request_id: &str) -> Result<u32, AppError> {
        let conn = self.conn.lock();
        let count: u32 = conn
            .query_row(
                "SELECT COUNT(*) FROM executions WHERE request_id = ?1",
                params![request_id],
                |row| row.get(0),
            )
            .map_err(db_err("request: count_executions"))?;
        Ok(count)
    }

    fn count_completed_executions(&self, request_id: &str) -> Result<u32, AppError> {
        let conn = self.conn.lock();
        let count: u32 = conn
            .query_row(
                "SELECT COUNT(DISTINCT e.id) FROM executions e
                 INNER JOIN results r ON r.execution_id = e.id
                 WHERE e.request_id = ?1",
                params![request_id],
                |row| row.get(0),
            )
            .map_err(db_err("request: count_completed_executions"))?;
        Ok(count)
    }

    fn find_stored_execution_ids(&self, request_id: &str) -> Result<Vec<String>, AppError> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare(
                "SELECT DISTINCT execution_id FROM results WHERE request_id = ?1 AND status = 'stored'",
            )
            .map_err(db_err("request: find_stored_execution_ids"))?;
        let rows = stmt
            .query_map(params![request_id], |row| row.get(0))
            .map_err(db_err("request: find_stored_execution_ids"))?;
        let mut ids = Vec::new();
        for row in rows {
            ids.push(row.map_err(db_err("request: find_stored_execution_ids"))?);
        }
        Ok(ids)
    }

    fn list_results_for_user(
        &self,
        user_id: &str,
        groups: &[String],
        roles: &[String],
        limit: u32,
    ) -> Result<Vec<dbward_app::ports::repos::StoredResultEntry>, AppError> {
        let conn = self.conn.lock();
        let mut conditions = vec![
            "req.requester = ?1".to_string(),
            "(ra.selector_type = 'user' AND ra.selector_value = ?1)".to_string(),
        ];
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> =
            vec![Box::new(user_id.to_string()), Box::new(limit)];
        let mut idx = 3;
        for g in groups {
            conditions.push(format!(
                "(ra.selector_type = 'group' AND ra.selector_value = ?{idx})"
            ));
            params.push(Box::new(g.clone()));
            idx += 1;
        }
        for r in roles {
            conditions.push(format!(
                "(ra.selector_type = 'role' AND ra.selector_value = ?{idx})"
            ));
            params.push(Box::new(r.clone()));
            idx += 1;
        }
        let where_clause = conditions.join(" OR ");
        let sql = format!(
            "SELECT r.request_id, db.name, db.environment, req.operation,
                    r.stored_at, r.content_length
             FROM results r
             JOIN requests req ON req.id = r.request_id
             JOIN databases db ON db.id = req.database_id
             LEFT JOIN result_access ra ON ra.result_id = r.id
             WHERE {where_clause}
             GROUP BY r.id
             ORDER BY r.stored_at DESC
             LIMIT ?2"
        );
        let mut stmt = conn
            .prepare(&sql)
            .map_err(db_err("request: list_results_for_user"))?;
        let param_refs: Vec<&dyn rusqlite::types::ToSql> =
            params.iter().map(|p| p.as_ref()).collect();
        let rows = stmt
            .query_map(param_refs.as_slice(), |row| {
                Ok(dbward_app::ports::repos::StoredResultEntry {
                    request_id: row.get(0)?,
                    database: row.get(1)?,
                    environment: row.get(2)?,
                    operation: row.get(3)?,
                    stored_at: row.get(4)?,
                    content_length: row.get(5)?,
                })
            })
            .map_err(db_err("request: list_results_for_user"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(db_err("request: list_results_for_user"))
    }
    fn count_by_status(&self, status: &str) -> Result<u32, AppError> {
        let conn = self.conn.lock();
        let count: u32 = conn
            .query_row(
                "SELECT COUNT(*) FROM requests WHERE status = ?1",
                params![status],
                |row| row.get(0),
            )
            .map_err(db_err("request: count_by_status"))?;
        Ok(count)
    }
    fn get_pending_approvers_for_requests(
        &self,
        request_ids: &[&str],
    ) -> Result<HashMap<String, (u32, Vec<String>)>, AppError> {
        if request_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let conn = self.conn.lock();
        let placeholders = request_ids
            .iter()
            .map(|_| "?")
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT request_id, step_index, selector FROM request_pending_approvers WHERE request_id IN ({})",
            placeholders
        );
        let mut stmt = conn
            .prepare(&sql)
            .map_err(db_err("request: get_pending_approvers_for_requests"))?;
        let params: Vec<&dyn rusqlite::types::ToSql> = request_ids
            .iter()
            .map(|id| id as &dyn rusqlite::types::ToSql)
            .collect();
        let rows = stmt
            .query_map(params.as_slice(), |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, u32>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(db_err("request: get_pending_approvers_for_requests"))?;
        let mut result: HashMap<String, (u32, Vec<String>)> = HashMap::new();
        for row in rows {
            let (req_id, step_idx, selector) =
                row.map_err(db_err("request: get_pending_approvers_for_requests"))?;
            result
                .entry(req_id)
                .or_insert_with(|| (step_idx, Vec::new()))
                .1
                .push(selector);
        }
        Ok(result)
    }
}
