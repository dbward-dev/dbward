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

pub(super) const LEASE_RECLAIM_INTERVAL: TokioDuration = TokioDuration::from_secs(60);
pub(super) const TTL_EXPIRY_INTERVAL: TokioDuration = TokioDuration::from_secs(60);
pub(super) const DISPATCH_TIMEOUT_INTERVAL: TokioDuration = TokioDuration::from_secs(60);
pub(super) const RECORD_PURGE_INTERVAL: TokioDuration = TokioDuration::from_secs(3600);
pub(super) const DISPATCH_TIMEOUT_SECS: i64 = 300;
pub(super) const WEBHOOK_RETRY_INTERVAL: TokioDuration = TokioDuration::from_secs(30);
pub(super) const WEBHOOK_STALE_CLAIM_SECS: i64 = 300;

// --- Supervisor constants ---

pub(super) const MAX_RESTARTS: usize = 5;
pub(super) const RESTART_WINDOW: TokioDuration = TokioDuration::from_secs(3600);
pub(super) const RESTART_DELAY: TokioDuration = TokioDuration::from_secs(1);

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
            spawn_fn: Box::new(|state, shutdown| {
                Box::pin(lease::lease_reclaim_loop(state, shutdown))
            }),
        },
        TaskDef {
            name: "ttl_expiry",
            spawn_fn: Box::new(|state, shutdown| {
                Box::pin(expiry::ttl_expiry_loop(state, shutdown))
            }),
        },
        TaskDef {
            name: "dispatch_timeout",
            spawn_fn: Box::new(|state, shutdown| {
                Box::pin(dispatch::dispatch_timeout_loop(state, shutdown))
            }),
        },
        TaskDef {
            name: "record_purge",
            spawn_fn: Box::new(move |state, shutdown| {
                let r = retention.clone();
                Box::pin(async move { cleanup::record_purge_loop(state, shutdown, &r).await })
            }),
        },
        TaskDef {
            name: "webhook_retry",
            spawn_fn: Box::new(|state, shutdown| {
                Box::pin(webhook::webhook_retry_loop(state, shutdown))
            }),
        },
        TaskDef {
            name: "dry_run_reclaim",
            spawn_fn: Box::new(|state, shutdown| {
                Box::pin(dry_run::dry_run_reclaim_loop(state, shutdown))
            }),
        },
        TaskDef {
            name: "context_timeout",
            spawn_fn: Box::new(|state, shutdown| {
                Box::pin(context::context_timeout_loop(state, shutdown))
            }),
        },
        TaskDef {
            name: "license_expiry",
            spawn_fn: Box::new(|state, shutdown| {
                Box::pin(license::license_expiry_loop(state, shutdown))
            }),
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

mod cleanup;
mod context;
mod dispatch;
mod dry_run;
mod expiry;
mod lease;
mod license;
mod webhook;

pub(super) fn make_audit_event(
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

pub(super) fn emit_webhook(state: &AppState, event_type: &str, request_id: &str) {
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
        matched_selector: None,
    };

    bg.notifier().dispatch(event);
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
