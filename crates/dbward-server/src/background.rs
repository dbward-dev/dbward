use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use chrono::Duration;
use tokio::task::JoinSet;
use tokio::time::{Duration as TokioDuration, Instant, interval, interval_at};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use dbward_app::ports::WebhookEvent;
use dbward_domain::entities::{ActorType, AuditEvent, EventCategory, EventOutcome};

use crate::config::RetentionConfig;
use crate::state::AppState;

// --- Constants ---

const LEASE_RECLAIM_INTERVAL: TokioDuration = TokioDuration::from_secs(60);
const TTL_EXPIRY_INTERVAL: TokioDuration = TokioDuration::from_secs(60);
const DISPATCH_TIMEOUT_INTERVAL: TokioDuration = TokioDuration::from_secs(60);
const RECORD_PURGE_INTERVAL: TokioDuration = TokioDuration::from_secs(3600);
const WAL_CHECKPOINT_INTERVAL: TokioDuration = TokioDuration::from_secs(3600);
const DISPATCH_TIMEOUT_SECS: i64 = 300;

// --- TickResult ---

#[derive(Default, Debug)]
pub(crate) struct TickResult {
    pub processed: u32,
    pub failed: u32,
}

// --- Public entry point ---

pub fn spawn_background_tasks(
    state: AppState,
    draining: Arc<AtomicBool>,
    retention: RetentionConfig,
) -> (CancellationToken, JoinSet<()>) {
    let shutdown = CancellationToken::new();
    let mut set = JoinSet::new();

    set.spawn(lease_reclaim_loop(state.clone(), shutdown.clone()));
    set.spawn(ttl_expiry_loop(state.clone(), shutdown.clone()));
    set.spawn(dispatch_timeout_loop(state.clone(), shutdown.clone()));
    set.spawn(record_purge_loop(
        state.clone(),
        shutdown.clone(),
        retention,
    ));
    set.spawn(wal_checkpoint_loop(state.clone(), shutdown.clone()));

    // Bridge: when draining is set externally, also cancel background tasks
    let shutdown_bridge = shutdown.clone();
    let draining_bridge = draining;
    set.spawn(async move {
        loop {
            tokio::time::sleep(TokioDuration::from_millis(500)).await;
            if draining_bridge.load(Ordering::SeqCst) {
                shutdown_bridge.cancel();
                break;
            }
        }
    });

    (shutdown, set)
}

// --- Lease Reclaim ---

async fn lease_reclaim_loop(state: AppState, shutdown: CancellationToken) {
    let mut ticker = interval(LEASE_RECLAIM_INTERVAL);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let r = run_lease_reclaim_once(&state).await;
                if r.processed > 0 || r.failed > 0 {
                    info!(task = "lease_reclaim", processed = r.processed, failed = r.failed, "tick completed");
                }
            }
            _ = shutdown.cancelled() => break,
        }
    }
}

pub(crate) async fn run_lease_reclaim_once(state: &AppState) -> TickResult {
    let mut result = TickResult::default();
    let now_str = state.clock.now().to_rfc3339();

    let expired = match state.agent_repo.find_expired_leases(&now_str) {
        Ok(v) => v,
        Err(e) => {
            error!(task = "lease_reclaim", error = %e, "db query failed");
            result.failed += 1;
            return result;
        }
    };

    for (exec_id, req_id) in expired {
        let audit = make_audit_event("execution_lost", EventCategory::Agent, &req_id, state);
        match state
            .agent_repo
            .mark_execution_lost_and_record(&exec_id, &req_id, &audit, &now_str)
        {
            Ok(true) => {
                result.processed += 1;
                emit_webhook(state, "execution_lost", &req_id);
            }
            Ok(false) => {} // already processed
            Err(e) => {
                result.failed += 1;
                error!(task = "lease_reclaim", execution_id = %exec_id, error = %e, "failed to mark execution_lost");
            }
        }
    }
    result
}

// --- TTL Expiry ---

async fn ttl_expiry_loop(state: AppState, shutdown: CancellationToken) {
    let mut ticker = interval(TTL_EXPIRY_INTERVAL);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let r = run_ttl_expiry_once(&state).await;
                if r.processed > 0 || r.failed > 0 {
                    info!(task = "ttl_expiry", processed = r.processed, failed = r.failed, "tick completed");
                }
            }
            _ = shutdown.cancelled() => break,
        }
    }
}

pub(crate) async fn run_ttl_expiry_once(state: &AppState) -> TickResult {
    let mut result = TickResult::default();
    let now_str = state.clock.now().to_rfc3339();

    // Approval TTL
    match state.request_repo.find_expired_approved(&now_str) {
        Ok(ids) => {
            for id in ids {
                let audit =
                    make_audit_event("request_expired", EventCategory::Approval, &id, state);
                match state
                    .request_repo
                    .mark_expired_and_record(&id, &audit, &now_str)
                {
                    Ok(true) => {
                        result.processed += 1;
                        emit_webhook(state, "request_expired", &id);
                    }
                    Ok(false) => {}
                    Err(e) => {
                        result.failed += 1;
                        error!(task = "ttl_expiry", request_id = %id, error = %e, "failed to expire approved request");
                    }
                }
            }
        }
        Err(e) => {
            error!(task = "ttl_expiry", error = %e, "find_expired_approved failed");
            result.failed += 1;
        }
    }

    // Pending TTL
    match state.request_repo.find_expired_pending(&now_str) {
        Ok(ids) => {
            for id in ids {
                let audit =
                    make_audit_event("request_expired", EventCategory::Approval, &id, state);
                match state
                    .request_repo
                    .mark_expired_and_record(&id, &audit, &now_str)
                {
                    Ok(true) => {
                        result.processed += 1;
                        emit_webhook(state, "request_expired", &id);
                    }
                    Ok(false) => {}
                    Err(e) => {
                        result.failed += 1;
                        error!(task = "ttl_expiry", request_id = %id, error = %e, "failed to expire pending request");
                    }
                }
            }
        }
        Err(e) => {
            error!(task = "ttl_expiry", error = %e, "find_expired_pending failed");
            result.failed += 1;
        }
    }

    result
}

// --- Dispatch Timeout ---

async fn dispatch_timeout_loop(state: AppState, shutdown: CancellationToken) {
    let mut ticker = interval(DISPATCH_TIMEOUT_INTERVAL);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let r = run_dispatch_timeout_once(&state).await;
                if r.processed > 0 || r.failed > 0 {
                    info!(task = "dispatch_timeout", processed = r.processed, failed = r.failed, "tick completed");
                }
            }
            _ = shutdown.cancelled() => break,
        }
    }
}

pub(crate) async fn run_dispatch_timeout_once(state: &AppState) -> TickResult {
    let mut result = TickResult::default();
    let now = state.clock.now();
    let cutoff = (now - Duration::seconds(DISPATCH_TIMEOUT_SECS)).to_rfc3339();
    let now_str = now.to_rfc3339();

    let ids = match state.request_repo.find_dispatched_older_than(&cutoff) {
        Ok(v) => v,
        Err(e) => {
            error!(task = "dispatch_timeout", error = %e, "db query failed");
            result.failed += 1;
            return result;
        }
    };

    for id in ids {
        match state
            .request_repo
            .mark_approved_from_dispatched(&id, &now_str)
        {
            Ok(true) => {
                result.processed += 1;
                emit_audit(state, "dispatch_timeout", EventCategory::Approval, &id);
            }
            Ok(false) => {}
            Err(e) => {
                result.failed += 1;
                error!(task = "dispatch_timeout", request_id = %id, error = %e, "failed to revert to approved");
            }
        }
    }
    result
}

// --- Record Purge ---

async fn record_purge_loop(
    state: AppState,
    shutdown: CancellationToken,
    retention: RetentionConfig,
) {
    // Delay first execution by one interval
    let start = Instant::now() + RECORD_PURGE_INTERVAL;
    let mut ticker = interval_at(start, RECORD_PURGE_INTERVAL);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let r = run_record_purge_once(&state, &retention).await;
                info!(task = "record_purge", processed = r.processed, failed = r.failed, "tick completed");
            }
            _ = shutdown.cancelled() => break,
        }
    }
}

pub(crate) async fn run_record_purge_once(
    state: &AppState,
    retention: &RetentionConfig,
) -> TickResult {
    let mut result = TickResult::default();
    let now = state.clock.now();
    let request_cutoff = (now - Duration::days(retention.request_ttl_days as i64)).to_rfc3339();
    let audit_cutoff = (now - Duration::days(retention.audit_ttl_days as i64)).to_rfc3339();

    // Revoked tokens
    match state.token_repo.purge_revoked(&request_cutoff) {
        Ok(n) => {
            if n > 0 {
                result.processed += n;
                info!(task = "record_purge", count = n, "purged revoked tokens");
            }
        }
        Err(e) => {
            result.failed += 1;
            error!(task = "record_purge", error = %e, "purge_revoked failed");
        }
    }

    // Old audit events
    match state.audit_repo.purge_old(&audit_cutoff) {
        Ok(n) => {
            if n > 0 {
                result.processed += n;
                info!(task = "record_purge", count = n, "purged old audit events");
            }
        }
        Err(e) => {
            result.failed += 1;
            error!(task = "record_purge", error = %e, "purge_old audit failed");
        }
    }

    // Old requests
    match state.request_repo.purge_old_requests(&request_cutoff) {
        Ok(n) => {
            if n > 0 {
                result.processed += n;
                info!(task = "record_purge", count = n, "purged old requests");
            }
        }
        Err(e) => {
            result.failed += 1;
            error!(task = "record_purge", error = %e, "purge_old_requests failed");
        }
    }

    // Expired results (storage delete → DB delete)
    let now_str = now.to_rfc3339();
    match state.agent_repo.find_expired_results(&now_str) {
        Ok(expired) => {
            for (result_id, storage_key) in expired {
                match state.result_store.delete(&storage_key).await {
                    Ok(()) => {
                        // Storage deleted successfully → safe to remove DB record
                        if let Err(e) = state.agent_repo.delete_result(&result_id) {
                            error!(task = "record_purge", result_id = %result_id, error = %e, "db delete failed after storage delete");
                            result.failed += 1;
                        } else {
                            result.processed += 1;
                        }
                    }
                    Err(e) => {
                        // Storage delete failed → keep DB record for retry next cycle
                        warn!(task = "record_purge", result_id = %result_id, error = %e, "storage delete failed, will retry");
                        result.failed += 1;
                    }
                }
            }
        }
        Err(e) => {
            result.failed += 1;
            error!(task = "record_purge", error = %e, "find_expired_results failed");
        }
    }

    result
}

// --- WAL Checkpoint ---

async fn wal_checkpoint_loop(state: AppState, shutdown: CancellationToken) {
    let start = Instant::now() + WAL_CHECKPOINT_INTERVAL;
    let mut ticker = interval_at(start, WAL_CHECKPOINT_INTERVAL);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                run_wal_checkpoint_once(&state);
            }
            _ = shutdown.cancelled() => break,
        }
    }
}

pub(crate) fn run_wal_checkpoint_once(state: &AppState) {
    if let Err(e) = state.request_repo.wal_checkpoint() {
        error!(task = "wal_checkpoint", error = %e, "WAL checkpoint failed");
    } else {
        info!(task = "wal_checkpoint", "checkpoint completed");
    }
}

// --- Helpers ---

fn emit_audit(state: &AppState, event_type: &str, category: EventCategory, request_id: &str) {
    let mut event = AuditEvent::simple(event_type, "approval", "system", Some(request_id), state.clock.now());
    event.actor_type = ActorType::System;
    event.request_id = Some(request_id.to_string());
    event.outcome = EventOutcome::Success;
    event.event_category = category;
    if let Err(e) = state.audit_logger.record(&event) {
        error!(task = "background", request_id = %request_id, error = %e, "audit record failed");
    }
}

fn make_audit_event(
    event_type: &str,
    category: EventCategory,
    request_id: &str,
    state: &AppState,
) -> AuditEvent {
    let mut event = AuditEvent::simple(event_type, "approval", "system", Some(request_id), state.clock.now());
    event.actor_type = ActorType::System;
    event.request_id = Some(request_id.to_string());
    event.outcome = EventOutcome::Success;
    event.event_category = category;
    match state.request_repo.get(request_id) {
        Ok(Some(req)) => {
            event.database_name = Some(req.database.to_string());
            event.environment = Some(req.environment.to_string());
            event.operation = Some(req.operation.as_str().to_string());
        }
        Ok(None) => {
            tracing::warn!(
                request_id,
                "audit event: request not found, db/env/op will be empty"
            );
        }
        Err(e) => {
            tracing::warn!(request_id, error = %e, "audit event: failed to lookup request");
        }
    }
    event
}

fn emit_webhook(state: &AppState, event_type: &str, request_id: &str) {
    state.notifier.dispatch(WebhookEvent {
        event_type: event_type.to_string(),
        request_id: Some(request_id.to_string()),
        database: None,
        environment: None,
        actor: Some("system".to_string()),
        detail: None,
        requester: None,
        reason: None,
        redacted_detail: None,
        error_summary: None,
        approval_hint: None,
        operation: None,
    });
}
