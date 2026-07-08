use chrono::{DateTime, Utc};
use rusqlite::params;

use dbward_app::error::AppError;
use dbward_app::ports::onboarding::{
    ClaimResult, CreateOnboardingInput, ExpiredOnboardingNotification, OnboardingRequest,
    OnboardingRequestRepo,
};

use super::DbConn;
use super::error::{db_err, json_err};

pub struct SqliteOnboardingRequestRepo {
    conn: DbConn,
}

impl SqliteOnboardingRequestRepo {
    pub fn new(conn: DbConn) -> Self {
        Self { conn }
    }
}

impl OnboardingRequestRepo for SqliteOnboardingRequestRepo {
    fn has_pending(&self, slack_user_id: &str) -> Result<bool, AppError> {
        let conn = self.conn.lock();
        let count: u32 = conn
            .query_row(
                "SELECT COUNT(*) FROM onboarding_requests WHERE slack_user_id = ?1 AND status = 'pending'",
                params![slack_user_id],
                |row| row.get(0),
            )
            .map_err(db_err("has_pending"))?;
        Ok(count > 0)
    }

    fn create(&self, input: &CreateOnboardingInput) -> Result<(), AppError> {
        let conn = self.conn.lock();
        let roles_json =
            serde_json::to_string(&input.requested_roles).map_err(json_err("create: roles"))?;
        let groups_json =
            serde_json::to_string(&input.requested_groups).map_err(json_err("create: groups"))?;
        conn.execute(
            "INSERT INTO onboarding_requests \
             (id, slack_user_id, display_name, requested_roles_json, requested_groups_json, reason, status, created_at, expires_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', ?7, ?8)",
            params![
                input.id,
                input.slack_user_id,
                input.display_name,
                roles_json,
                groups_json,
                input.reason,
                input.created_at.to_rfc3339(),
                input.expires_at.to_rfc3339(),
            ],
        )
        .map_err(db_err("create onboarding request"))?;
        Ok(())
    }

    fn set_message_ts(&self, request_id: &str, message_ts: &str) -> Result<(), AppError> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE onboarding_requests SET message_ts = ?1 WHERE id = ?2",
            params![message_ts, request_id],
        )
        .map_err(db_err("set_message_ts"))?;
        Ok(())
    }

    fn get_pending(&self, request_id: &str) -> Result<Option<OnboardingRequest>, AppError> {
        let conn = self.conn.lock();
        let result = conn.query_row(
            "SELECT id, slack_user_id, display_name, requested_roles_json, requested_groups_json, \
             reason, status, message_ts, created_at, expires_at \
             FROM onboarding_requests WHERE id = ?1 AND status = 'pending'",
            params![request_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                ))
            },
        );
        match result {
            Ok((
                id,
                slack_user_id,
                display_name,
                roles_json,
                groups_json,
                reason,
                status,
                message_ts,
                created_at_str,
                expires_at_str,
            )) => {
                let requested_roles: Vec<String> =
                    serde_json::from_str(&roles_json).map_err(json_err("get_pending: roles"))?;
                let requested_groups: Vec<String> =
                    serde_json::from_str(&groups_json).map_err(json_err("get_pending: groups"))?;
                let created_at = super::parse_datetime(&created_at_str)
                    .map_err(db_err("get_pending: created_at"))?;
                let expires_at = super::parse_datetime(&expires_at_str)
                    .map_err(db_err("get_pending: expires_at"))?;
                Ok(Some(OnboardingRequest {
                    id,
                    slack_user_id,
                    display_name,
                    requested_roles,
                    requested_groups,
                    reason,
                    status,
                    message_ts,
                    created_at,
                    expires_at,
                }))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(db_err("get_pending")(e)),
        }
    }

    fn claim_rejected(
        &self,
        request_id: &str,
        decided_by: &str,
        decided_at: DateTime<Utc>,
        decision_comment: Option<&str>,
    ) -> Result<ClaimResult, AppError> {
        let conn = self.conn.lock();
        let affected = conn
            .execute(
                "UPDATE onboarding_requests SET status = 'rejected', decided_by = ?1, decided_at = ?2, \
                 decision_comment = ?3 WHERE id = ?4 AND status = 'pending'",
                params![
                    decided_by,
                    decided_at.to_rfc3339(),
                    decision_comment,
                    request_id,
                ],
            )
            .map_err(db_err("claim_rejected"))?;
        Ok(ClaimResult {
            claimed: affected > 0,
        })
    }

    fn expire_pending(
        &self,
        now: DateTime<Utc>,
    ) -> Result<Vec<ExpiredOnboardingNotification>, AppError> {
        let conn = self.conn.lock();
        let now_str = now.to_rfc3339();

        // Atomic: UPDATE + SELECT in explicit transaction
        let tx = conn
            .unchecked_transaction()
            .map_err(db_err("expire_pending: begin"))?;

        tx.execute(
            "UPDATE onboarding_requests SET status = 'expired', decided_at = ?1 \
             WHERE status = 'pending' AND expires_at <= ?1",
            params![now_str],
        )
        .map_err(db_err("expire_pending: update"))?;

        let results: Vec<ExpiredOnboardingNotification> = {
            let mut stmt = tx
                .prepare(
                    "SELECT slack_user_id, message_ts FROM onboarding_requests \
                     WHERE status = 'expired' AND decided_at = ?1",
                )
                .map_err(db_err("expire_pending: prepare"))?;

            stmt.query_map(params![now_str], |r| {
                Ok(ExpiredOnboardingNotification {
                    slack_user_id: r.get(0)?,
                    message_ts: r.get(1)?,
                })
            })
            .map_err(db_err("expire_pending: query"))?
            .filter_map(|r| r.ok())
            .collect()
        };

        tx.commit().map_err(db_err("expire_pending: commit"))?;
        Ok(results)
    }
}
