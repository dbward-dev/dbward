use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use chrono::Duration;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{Duration as TokioDuration, Instant, interval, interval_at};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use dbward_app::ports::WebhookEvent;
use dbward_domain::entities::{ActorType, AuditContext, AuditEvent, EventCategory, EventOutcome};

use crate::config::RetentionConfig;
use crate::state::AppState;

// --- Constants ---

const LEASE_RECLAIM_INTERVAL: TokioDuration = TokioDuration::from_secs(60);
const TTL_EXPIRY_INTERVAL: TokioDuration = TokioDuration::from_secs(60);
const DISPATCH_TIMEOUT_INTERVAL: TokioDuration = TokioDuration::from_secs(60);
const RECORD_PURGE_INTERVAL: TokioDuration = TokioDuration::from_secs(3600);
const DISPATCH_TIMEOUT_SECS: i64 = 300;
const WEBHOOK_RETRY_INTERVAL: TokioDuration = TokioDuration::from_secs(30);
const WEBHOOK_STALE_CLAIM_SECS: i64 = 300;

// --- Supervisor constants ---

const MAX_RESTARTS: usize = 5;
const RESTART_WINDOW: TokioDuration = TokioDuration::from_secs(3600);
const RESTART_DELAY: TokioDuration = TokioDuration::from_secs(1);

// --- TickResult ---

#[derive(Default, Debug)]
pub(crate) struct TickResult {
    pub processed: u32,
    pub failed: u32,
}

// --- Task definitions ---

/// Each supervised task returns (index, panicked) via catch_unwind wrapper.
#[allow(clippy::type_complexity)]
struct TaskDef {
    name: &'static str,
    spawn_fn: Box<
        dyn Fn(
                AppState,
                CancellationToken,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
            + Send
            + Sync,
    >,
}

fn build_task_defs(retention: Arc<RetentionConfig>) -> Vec<TaskDef> {
    let mut defs = vec![
        TaskDef {
            name: "lease_reclaim",
            spawn_fn: Box::new(|state, shutdown| Box::pin(lease_reclaim_loop(state, shutdown))),
        },
        TaskDef {
            name: "ttl_expiry",
            spawn_fn: Box::new(|state, shutdown| Box::pin(ttl_expiry_loop(state, shutdown))),
        },
        TaskDef {
            name: "dispatch_timeout",
            spawn_fn: Box::new(|state, shutdown| Box::pin(dispatch_timeout_loop(state, shutdown))),
        },
        TaskDef {
            name: "record_purge",
            spawn_fn: Box::new(move |state, shutdown| {
                let r = retention.clone();
                Box::pin(async move { record_purge_loop(state, shutdown, &r).await })
            }),
        },
        TaskDef {
            name: "webhook_retry",
            spawn_fn: Box::new(|state, shutdown| Box::pin(webhook_retry_loop(state, shutdown))),
        },
        TaskDef {
            name: "dry_run_reclaim",
            spawn_fn: Box::new(|state, shutdown| Box::pin(dry_run_reclaim_loop(state, shutdown))),
        },
        TaskDef {
            name: "context_timeout",
            spawn_fn: Box::new(|state, shutdown| Box::pin(context_timeout_loop(state, shutdown))),
        },
        TaskDef {
            name: "license_expiry",
            spawn_fn: Box::new(|state, shutdown| Box::pin(license_expiry_loop(state, shutdown))),
        },
    ];

    // Panic injection for E2E testing (only when env var is set)
    if std::env::var("DBWARD_PANIC_INJECT_DELAY_SECS").is_ok() {
        defs.push(TaskDef {
            name: "panic_inject",
            spawn_fn: Box::new(|_state, _shutdown| {
                Box::pin(async {
                    let delay: u64 = std::env::var("DBWARD_PANIC_INJECT_DELAY_SECS")
                        .unwrap_or_else(|_| "5".into())
                        .parse()
                        .unwrap_or(5);
                    tokio::time::sleep(TokioDuration::from_secs(delay)).await;
                    panic!("panic injection triggered for E2E testing");
                })
            }),
        });
    }

    defs
}

// --- Public entry point ---

pub fn spawn_background_tasks(
    state: AppState,
    draining: Arc<AtomicBool>,
    retention: RetentionConfig,
) -> (CancellationToken, JoinHandle<()>) {
    let shutdown = CancellationToken::new();
    let handle = tokio::spawn(supervisor_loop(
        state,
        shutdown.clone(),
        draining,
        Arc::new(retention),
    ));
    (shutdown, handle)
}

/// Supervisor that restarts panicked background tasks with a sliding-window rate limit.
/// Each task future is wrapped to return its index, enabling identification on panic.
async fn supervisor_loop(
    state: AppState,
    shutdown: CancellationToken,
    draining: Arc<AtomicBool>,
    retention: Arc<RetentionConfig>,
) {
    let tasks = build_task_defs(retention);
    run_supervisor(tasks, &state, shutdown, draining).await;
}

async fn run_supervisor(
    tasks: Vec<TaskDef>,
    state: &AppState,
    shutdown: CancellationToken,
    draining: Arc<AtomicBool>,
) {
    let task_count = tasks.len();
    // JoinSet<usize>: each future returns its own task index
    let mut set: JoinSet<usize> = JoinSet::new();
    // Single sliding window for all restarts (global budget)
    let mut restart_timestamps: VecDeque<Instant> = VecDeque::new();

    // Initial spawn — wrap each task future to return its index
    for i in 0..task_count {
        spawn_task(&tasks, i, state, &shutdown, &mut set);
    }

    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            _ = drain_check(&draining) => {
                shutdown.cancel();
                break;
            }
            result = set.join_next() => {
                let Some(result) = result else { break };
                match result {
                    Ok(_idx) => {
                        // Normal exit (task loop ended due to shutdown)
                    }
                    Err(e) if e.is_panic() => {
                        error!("background task panicked: {e}");
                        state.metrics.background_panics_total.fetch_add(1, Ordering::Relaxed);

                        // Sliding window rate limit (global budget)
                        let now = Instant::now();
                        restart_timestamps.retain(|t| now.duration_since(*t) < RESTART_WINDOW);

                        if restart_timestamps.len() >= MAX_RESTARTS {
                            error!(
                                "background tasks exceeded max restart limit ({} in {}s), initiating shutdown",
                                MAX_RESTARTS, RESTART_WINDOW.as_secs()
                            );
                            draining.store(true, Ordering::SeqCst);
                            shutdown.cancel();
                            break;
                        }

                        restart_timestamps.push_back(now);

                        set.abort_all();
                        while set.join_next().await.is_some() {}

                        if shutdown.is_cancelled() {
                            break;
                        }

                        tokio::time::sleep(RESTART_DELAY).await;

                        // Re-spawn all tasks
                        for i in 0..task_count {
                            info!(task = tasks[i].name, "respawning background task");
                            spawn_task(&tasks, i, state, &shutdown, &mut set);
                        }
                        info!("background tasks restarted after panic");
                    }
                    Err(e) => {
                        error!(error = %e, "background task cancelled unexpectedly");
                    }
                }
            }
        }
    }
    set.abort_all();
}

fn spawn_task(
    tasks: &[TaskDef],
    idx: usize,
    state: &AppState,
    shutdown: &CancellationToken,
    set: &mut JoinSet<usize>,
) {
    let fut = (tasks[idx].spawn_fn)(state.clone(), shutdown.clone());
    set.spawn(async move {
        fut.await;
        idx
    });
}

async fn drain_check(draining: &Arc<AtomicBool>) {
    loop {
        tokio::time::sleep(TokioDuration::from_millis(500)).await;
        if draining.load(Ordering::SeqCst) {
            return;
        }
    }
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
    let bg = state.background();
    let now_str = bg.clock().now().to_rfc3339();

    let expired = match bg.agent_repo().find_expired_leases(&now_str) {
        Ok(v) => v,
        Err(e) => {
            error!(task = "lease_reclaim", error = %e, "db query failed");
            result.failed += 1;
            return result;
        }
    };

    for (exec_id, req_id) in expired {
        let audit = make_audit_event("execution_lost", EventCategory::Agent, &req_id, state);
        match bg
            .agent_repo()
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
    let bg = state.background();
    let now_str = bg.clock().now().to_rfc3339();

    // Approval TTL
    match bg.background_task_repo().find_expired_approved(&now_str) {
        Ok(ids) => {
            for id in ids {
                let audit =
                    make_audit_event("request_expired", EventCategory::Approval, &id, state);
                match bg
                    .background_task_repo()
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
    match bg.background_task_repo().find_expired_pending(&now_str) {
        Ok(ids) => {
            for id in ids {
                let audit =
                    make_audit_event("request_expired", EventCategory::Approval, &id, state);
                match bg
                    .background_task_repo()
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
    let bg = state.background();
    let now = bg.clock().now();
    let cutoff = (now - Duration::seconds(DISPATCH_TIMEOUT_SECS)).to_rfc3339();
    let now_str = now.to_rfc3339();

    let ids = match bg
        .background_task_repo()
        .find_dispatched_older_than(&cutoff)
    {
        Ok(v) => v,
        Err(e) => {
            error!(task = "dispatch_timeout", error = %e, "db query failed");
            result.failed += 1;
            return result;
        }
    };

    for id in ids {
        let mut audit_event = AuditEvent::simple(
            "dispatch_timeout",
            "approval",
            "system",
            Some(&id),
            now,
            &AuditContext::System,
        );
        audit_event.request_id = Some(id.clone());
        match bg
            .request_writer()
            .mark_approved_from_dispatched_and_record(&id, &audit_event, &now_str)
        {
            Ok(true) => {
                result.processed += 1;
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
    retention: &RetentionConfig,
) {
    // Delay first execution by one interval
    let start = Instant::now() + RECORD_PURGE_INTERVAL;
    let mut ticker = interval_at(start, RECORD_PURGE_INTERVAL);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let r = run_record_purge_once(&state, retention).await;
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
    let now = state.background().clock().now();
    let request_cutoff = (now - Duration::days(retention.request_ttl_days as i64)).to_rfc3339();
    let audit_cutoff = (now - Duration::days(retention.audit_ttl_days as i64)).to_rfc3339();

    // Revoked tokens
    match state
        .background()
        .token_repo()
        .purge_revoked(&request_cutoff)
    {
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
    match state.background().audit_repo().purge_old(&audit_cutoff) {
        Ok(n) => {
            if n > 0 {
                result.processed += n;
                info!(task = "record_purge", count = n, "purged old audit events");
                // A8: Record the purge action itself
                let _ = state
                    .background()
                    .audit_logger()
                    .record(&AuditEvent::simple(
                        "audit_purged",
                        "policy",
                        "system",
                        None,
                        state.background().clock().now(),
                        &AuditContext::System,
                    ));
            }
        }
        Err(e) => {
            result.failed += 1;
            error!(task = "record_purge", error = %e, "purge_old audit failed");
        }
    }

    // Old requests
    match state
        .background()
        .background_task_repo()
        .purge_old_requests(&request_cutoff)
    {
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
    match state
        .background()
        .agent_repo()
        .find_expired_results(&now_str)
    {
        Ok(expired) => {
            for (result_id, storage_key) in expired {
                match state.background().result_store().delete(&storage_key).await {
                    Ok(()) => {
                        // Storage deleted successfully → safe to remove DB record
                        if let Err(e) = state.background().agent_repo().delete_result(&result_id) {
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

fn make_audit_event(
    event_type: &str,
    category: EventCategory,
    request_id: &str,
    state: &AppState,
) -> AuditEvent {
    let bg = state.background();
    let mut event = AuditEvent::simple(
        event_type,
        "approval",
        "system",
        Some(request_id),
        bg.clock().now(),
        &dbward_domain::entities::AuditContext::System,
    );
    event.actor_type = ActorType::System;
    event.request_id = Some(request_id.to_string());
    event.outcome = EventOutcome::Success;
    event.event_category = category;
    match bg.request_reader().get(request_id) {
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
    let bg = state.background();
    let (database, environment, requester, operation) = match bg.request_reader().get(request_id) {
        Ok(Some(req)) => (
            Some(req.database.as_str().to_string()),
            Some(req.environment.as_str().to_string()),
            Some(req.requester.clone()),
            Some(req.operation.as_str().to_string()),
        ),
        _ => (None, None, None, None),
    };

    let event = WebhookEvent {
        event_type: event_type.to_string(),
        request_id: Some(request_id.to_string()),
        database,
        environment,
        actor: Some("system".to_string()),
        detail: None,
        requester,
        reason: None,
        redacted_detail: None,
        error_summary: None,
        approval_hint: None,
        operation,
        step_index: None,
        total_steps: None,
        expires_at: None,
        approvers: None,
    };

    bg.notifier().dispatch(event.clone());

    if let Some(rn) = bg.request_notifier() {
        rn.dispatch(event);
    }
}

// --- Webhook DLQ Retry ---

async fn webhook_retry_loop(state: AppState, shutdown: CancellationToken) {
    let start = Instant::now() + WEBHOOK_RETRY_INTERVAL;
    let mut ticker = interval_at(start, WEBHOOK_RETRY_INTERVAL);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let r = run_webhook_retry_once(&state).await;
                if r.processed > 0 || r.failed > 0 {
                    info!(task = "webhook_retry", processed = r.processed, failed = r.failed, "tick completed");
                }
            }
            _ = shutdown.cancelled() => break,
        }
    }
}

pub(crate) async fn run_webhook_retry_once(state: &AppState) -> TickResult {
    let mut result = TickResult::default();
    let now = state.background().clock().now();

    // Reclaim stale in_progress deliveries (crashed workers)
    let stale_cutoff = (now - Duration::seconds(WEBHOOK_STALE_CLAIM_SECS)).to_rfc3339();
    if let Some(repo) = state.background().webhook_delivery_repo() {
        match repo.reclaim_stale(&stale_cutoff) {
            Ok(n) if n > 0 => info!(
                task = "webhook_retry",
                count = n,
                "reclaimed stale deliveries"
            ),
            Err(e) => error!(task = "webhook_retry", error = %e, "reclaim_stale failed"),
            _ => {}
        }

        // Claim retryable deliveries
        let now_str = now.to_rfc3339();
        match repo.claim_for_retry(&now_str, 5) {
            Ok(deliveries) => {
                for delivery in deliveries {
                    let send_result = state
                        .background()
                        .webhook_sender()
                        .send_one(&delivery.webhook_id, &delivery.payload, None)
                        .await;
                    match send_result {
                        Ok(()) => {
                            let _ = repo.mark_delivered(&delivery.id, &now_str);
                            result.processed += 1;
                        }
                        Err(e) => {
                            let attempts = delivery.attempts + 1;
                            if attempts >= delivery.max_attempts {
                                let _ = repo.mark_dead(&delivery.id);
                                warn!(task = "webhook_retry", id = %delivery.id, "delivery marked dead");
                            } else {
                                let backoff = (attempts as i64).pow(2) * 60;
                                let next = now + Duration::seconds(backoff);
                                let _ = repo.mark_failed(
                                    &delivery.id,
                                    &e,
                                    &next.to_rfc3339(),
                                    attempts,
                                );
                            }
                            result.failed += 1;
                        }
                    }
                }
            }
            Err(e) => {
                error!(task = "webhook_retry", error = %e, "claim_for_retry failed");
                result.failed += 1;
            }
        }

        // Purge old delivered/dead entries (7 days)
        let purge_cutoff = (now - Duration::days(7)).to_rfc3339();
        match repo.purge_old(&purge_cutoff) {
            Ok(n) if n > 0 => info!(task = "webhook_retry", count = n, "purged old deliveries"),
            Err(e) => error!(task = "webhook_retry", error = %e, "purge_old failed"),
            _ => {}
        }
    }

    result
}

async fn dry_run_reclaim_loop(state: AppState, shutdown: CancellationToken) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = interval.tick() => {
                let cutoff = (state.background().clock().now() - chrono::Duration::seconds(60)).to_rfc3339();
                match state.background().dry_run_repo().reclaim_stale(&cutoff) {
                    Ok(n) if n > 0 => {
                        tracing::info!(task = "dry_run_reclaim", reclaimed = n, "reclaimed stale dry-run jobs");
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::error!(task = "dry_run_reclaim", error = %e, "reclaim_stale failed");
                    }
                }
            }
        }
    }
}

async fn context_timeout_loop(state: AppState, shutdown: CancellationToken) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = interval.tick() => {
                let now = state.background().clock().now();
                let cutoff = (now - chrono::Duration::seconds(300)).to_rfc3339();
                let now_str = now.to_rfc3339();
                match state.background().context_repo().timeout_collecting(&cutoff, &now_str) {
                    Ok(n) if n > 0 => {
                        tracing::info!(task = "context_timeout", timed_out = n, "marked collecting contexts as unavailable");
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::error!(task = "context_timeout", error = %e, "timeout_collecting failed");
                    }
                }
            }
        }
    }
}

const LICENSE_CHECK_INTERVAL: TokioDuration = TokioDuration::from_secs(3600);

async fn license_expiry_loop(state: AppState, shutdown: CancellationToken) {
    let start = Instant::now() + LICENSE_CHECK_INTERVAL;
    let mut ticker = interval_at(start, LICENSE_CHECK_INTERVAL);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                state.background().license_checker().check_expiry(state.background().clock().now());
            }
            _ = shutdown.cancelled() => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restart_window_constants_are_reasonable() {
        assert_eq!(MAX_RESTARTS, 5);
        assert_eq!(RESTART_WINDOW, TokioDuration::from_secs(3600));
        assert_eq!(RESTART_DELAY, TokioDuration::from_secs(1));
    }

    /// Standalone supervisor loop for testing (no AppState dependency).
    /// Mirrors the real `run_supervisor` logic but takes generic futures.
    #[allow(clippy::type_complexity, clippy::needless_range_loop)]
    async fn test_supervisor(
        task_fns: Vec<
            Box<
                dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
                    + Send
                    + Sync,
            >,
        >,
        shutdown: CancellationToken,
        draining: Arc<AtomicBool>,
        max_restarts: usize,
    ) -> u32 {
        let task_count = task_fns.len();
        let mut set: JoinSet<usize> = JoinSet::new();
        let mut restart_timestamps: VecDeque<Instant> = VecDeque::new();
        let mut restart_count: u32 = 0;
        let window = TokioDuration::from_secs(3600);
        let delay = TokioDuration::from_millis(10); // fast for tests

        for i in 0..task_count {
            let fut = (task_fns[i])();
            set.spawn(async move {
                fut.await;
                i
            });
        }

        loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => break,
                result = set.join_next() => {
                    let Some(result) = result else { break };
                    match result {
                        Ok(_) => {}
                        Err(e) if e.is_panic() => {
                            let now = Instant::now();
                            restart_timestamps.retain(|t| now.duration_since(*t) < window);
                            if restart_timestamps.len() >= max_restarts {
                                draining.store(true, Ordering::SeqCst);
                                shutdown.cancel();
                                break;
                            }
                            restart_timestamps.push_back(now);
                            restart_count += 1;
                            set.abort_all();
                            while set.join_next().await.is_some() {}
                            if shutdown.is_cancelled() { break; }
                            tokio::time::sleep(delay).await;
                            for i in 0..task_count {
                                let fut = (task_fns[i])();
                                set.spawn(async move { fut.await; i });
                            }
                        }
                        Err(_) => {}
                    }
                }
            }
        }
        restart_count
    }

    #[tokio::test]
    #[allow(clippy::type_complexity)]
    async fn supervisor_restarts_panicked_task() {
        let panic_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let pc = panic_count.clone();

        let shutdown = CancellationToken::new();
        let shutdown2 = shutdown.clone();
        let draining = Arc::new(AtomicBool::new(false));

        let tasks: Vec<
            Box<
                dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
                    + Send
                    + Sync,
            >,
        > = vec![
            // Task that panics once then behaves
            Box::new(move || {
                let pc = pc.clone();
                let s = shutdown2.clone();
                Box::pin(async move {
                    let count = pc.fetch_add(1, Ordering::SeqCst);
                    if count == 0 {
                        panic!("test panic");
                    }
                    // After first restart, just wait for shutdown
                    s.cancelled().await;
                })
            }),
        ];

        let draining2 = draining.clone();
        let shutdown3 = shutdown.clone();
        // Stop the test after a short time
        tokio::spawn(async move {
            tokio::time::sleep(TokioDuration::from_millis(100)).await;
            shutdown3.cancel();
        });

        let restarts = test_supervisor(tasks, shutdown, draining2, 5).await;
        assert_eq!(restarts, 1);
        assert_eq!(panic_count.load(Ordering::SeqCst), 2); // panicked once, ran again once
        assert!(!draining.load(Ordering::SeqCst)); // did not exceed limit
    }

    #[tokio::test]
    #[allow(clippy::type_complexity)]
    async fn supervisor_shuts_down_after_max_restarts() {
        let shutdown = CancellationToken::new();
        let draining = Arc::new(AtomicBool::new(false));

        let tasks: Vec<
            Box<
                dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
                    + Send
                    + Sync,
            >,
        > = vec![
            // Task that always panics
            Box::new(|| Box::pin(async { panic!("always panic") })),
        ];

        let restarts = test_supervisor(tasks, shutdown.clone(), draining.clone(), 3).await;
        assert_eq!(restarts, 3);
        assert!(draining.load(Ordering::SeqCst)); // exceeded limit → draining
        assert!(shutdown.is_cancelled());
    }
}
