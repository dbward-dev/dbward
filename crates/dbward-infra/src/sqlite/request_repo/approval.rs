use chrono::{DateTime, Utc};
use rusqlite::params;

use dbward_app::error::AppError;
use dbward_app::ports::ApprovalRepo;
use dbward_domain::entities::Approval;

use super::{
    SqliteRequestRepo, approval_action_str, map_err, parse_approval_action, parse_ts,
    populate_pending_approvers,
};

impl ApprovalRepo for SqliteRequestRepo {
    fn insert_approval(&self, approval: &Approval) -> Result<(), AppError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO approvals (id, request_id, action, actor_id, matched_selector, step_index, comment, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                approval.id,
                approval.request_id,
                approval_action_str(&approval.action),
                approval.actor_id,
                approval.matched_selector,
                approval.step_index,
                approval.comment,
                approval.created_at.to_rfc3339(),
            ],
        ).map_err(map_err)?;
        // Update pending_approvers to next step
        let snapshot: Option<String> = conn
            .query_row(
                "SELECT workflow_snapshot_json FROM requests WHERE id = ?1",
                params![approval.request_id],
                |row| row.get(0),
            )
            .ok()
            .flatten();
        populate_pending_approvers(
            &conn,
            &approval.request_id,
            &snapshot,
            approval.step_index + 1,
        )?;
        Ok(())
    }
    fn get_approvals(&self, request_id: &str) -> Result<Vec<Approval>, AppError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT * FROM approvals WHERE request_id = ?1 ORDER BY created_at ASC")
            .map_err(map_err)?;
        let rows = stmt
            .query_map(params![request_id], |row| {
                let action_str: String = row.get("action")?;
                let action = parse_approval_action(&action_str).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?;
                let created_at_str: String = row.get("created_at")?;
                let created_at = parse_ts(&created_at_str).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?;
                Ok(Approval {
                    id: row.get("id")?,
                    request_id: row.get("request_id")?,
                    action,
                    actor_id: row.get("actor_id")?,
                    matched_selector: row.get("matched_selector")?,
                    step_index: row.get("step_index")?,
                    comment: row.get("comment")?,
                    created_at,
                })
            })
            .map_err(map_err)?;

        rows.collect::<Result<Vec<_>, _>>().map_err(map_err)
    }
    fn approve_and_mark_approved(
        &self,
        approval: &Approval,
        request_id: &str,
        now: DateTime<Utc>,
    ) -> Result<bool, AppError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(map_err)?;

        tx.execute(
            "INSERT INTO approvals (id, request_id, action, actor_id, matched_selector, step_index, comment, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                approval.id,
                approval.request_id,
                approval_action_str(&approval.action),
                approval.actor_id,
                approval.matched_selector,
                approval.step_index,
                approval.comment,
                approval.created_at.to_rfc3339(),
            ],
        ).map_err(map_err)?;

        let now_str = now.to_rfc3339();
        let affected = tx.execute(
            "UPDATE requests SET status = 'approved', updated_at = ?2, resolved_at = ?2 WHERE id = ?1 AND status = 'pending' AND (expires_at IS NULL OR expires_at > ?2)",
            params![request_id, now_str],
        ).map_err(map_err)?;

        if affected == 0 {
            drop(tx);
            return Ok(false);
        }

        tx.execute(
            "DELETE FROM request_pending_approvers WHERE request_id = ?1",
            params![request_id],
        )
        .map_err(map_err)?;

        tx.commit().map_err(map_err)?;
        Ok(true)
    }
    fn reject_and_record(
        &self,
        request_id: &str,
        approval: &Approval,
        now: DateTime<Utc>,
    ) -> Result<bool, AppError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(map_err)?;

        let now_str = now.to_rfc3339();
        let affected = tx.execute(
            "UPDATE requests SET status = 'rejected', updated_at = ?2, resolved_at = ?2 WHERE id = ?1 AND status = 'pending' AND (expires_at IS NULL OR expires_at > ?2)",
            params![request_id, now_str],
        ).map_err(map_err)?;

        if affected == 0 {
            drop(tx);
            return Ok(false);
        }

        tx.execute(
            "INSERT INTO approvals (id, request_id, action, actor_id, matched_selector, step_index, comment, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                approval.id,
                approval.request_id,
                approval_action_str(&approval.action),
                approval.actor_id,
                approval.matched_selector,
                approval.step_index,
                approval.comment,
                approval.created_at.to_rfc3339(),
            ],
        ).map_err(map_err)?;

        tx.commit().map_err(map_err)?;
        Ok(true)
    }
}
