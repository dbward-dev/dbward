# PRE-1: Preflight — AI Safety Oracle

## Status: Design Review (Round 2)

## Summary

`POST /api/preflight` + CLI `dbward preflight` + MCP `dbward_preflight_sql` を追加。
SQL を実行せずに 5 層分析（分類 / 静的レビュー / リスク / ポリシーシミュレーション / EXPLAIN）を行い、
`requestable | blocked | warning` のステータスと AI 向け修正指示を返す。

Request を作らないので、承認待ちキューを汚さず AI が安全な SQL に収束するまで何度でも試行可能。

---

## EXPLAIN Strategy

### Problem

既存の EXPLAIN は非同期（request 作成後に DryRunJob → agent poll → 実行 → submit back）。
Preflight では request を作らないため、既存パスがそのまま使えない。

さらに、既存 `DryRunJobRecord` は `request_id` が non-optional であり、claim/submit フローも
request context に依存している。DryRunJob にオーバーロードすると互換性の問題が発生する。

### Decision: Dedicated PreflightJob table + tokio::sync::watch notification

1. **Dedicated `preflight_jobs` テーブル**を新設（`dry_run_jobs` とは別）
2. Agent の poll レスポンスに `preflight_jobs` フィールドを追加（既存 `dry_run_jobs` と並列）
3. **Poll が atomically に claim** — poll handler 内で `UPDATE ... SET status='claimed', claimed_by=? WHERE status='pending' AND (db, env) IN (?) RETURNING *` を実行。Agent は claimed 状態の job のみ受け取る。複数 agent の重複実行は発生しない。
4. Agent は受け取った job の EXPLAIN を実行 → `POST /api/agent/preflight-result` で結果 submit
5. Server は **tokio watch channel** で完了通知を受け、HTTP handler が待機（polling loop ではない）
6. タイムアウト時は `impact.status = "timeout"` を返し、job に `expired` フラグを立てる

### Why dedicated table

- `dry_run_jobs.request_id` は non-optional → NULL にすると既存 claim/submit/aggregation が壊れる
- preflight job は lifecycle が異なる（TTL 短い、cleanup aggressive、request context 不要）
- テーブル分離で既存フローへの影響ゼロ

### PreflightJob lifecycle

```
created (TTL: explain_timeout + 5s buffer)
  → poll handler atomically claims for agent (UPDATE RETURNING)
  → agent receives already-claimed job in poll response
  → agent executes EXPLAIN
  → agent submits result → status = completed
  → OR TTL expires → status = expired (background cleanup → physical DELETE)
  → OR server timeout → HTTP returns, job eventually cleaned up
```

**No separate claim endpoint needed** — poll atomically claims. This eliminates the race condition
where two agents could both receive and execute the same job.

### Agent changes

Agent に以下を追加:
- Poll レスポンスの `preflight_jobs` フィールドをパース
- EXPLAIN 実行（既存 `driver.explain()` を再利用）
- `POST /api/agent/preflight-result` で結果送信

これは新しいコードだが、既存の dry-run パスと同じパターン。

---

## Authorization

### Permission Design

| Permission | Role | Scope | Description |
|---|---|---|---|
| `request.preflight` | developer, admin | DB + env | 静的分析のみ (include_explain=false) |
| `request.preflight_explain` | developer, admin | DB + env | EXPLAIN 付き preflight |

**readonly ロールには付与しない**。理由:
- EXPLAIN は production DB にクエリを送るため、passive read を超える
- plan/schema metadata が漏れるセキュリティリスク
- DB に measurable load がかかる可能性

### Authorization flow

```rust
// 1. Always check base permission
authorizer.authorize_scoped(user, Permission::RequestPreflight, db, env, &ResourceContext::Global)?;

// 2. If include_explain=true, check EXPLAIN permission. If denied, downgrade gracefully.
let effective_include_explain = if input.include_explain {
    authorizer.authorize_scoped(user, Permission::RequestPreflightExplain, db, env, &ResourceContext::Global).is_ok()
} else {
    false
};
// Note: does NOT return 403 for EXPLAIN permission lack — silently degrades to static-only.
// The response's impact.status will be "skipped" so the caller knows EXPLAIN was not run.
```

---

## Abuse Controls

### Rate Limiting

| Control | Value | Configurable |
|---|---|---|
| Max `explain_timeout_ms` (server-side cap) | 10,000ms | `[preflight] max_explain_timeout_ms` |
| Per-user concurrent preflight jobs | 3 | `[preflight] max_concurrent_per_user` |
| Per-user preflight rate | 30/min | `[preflight] rate_limit_per_minute` |
| SQL size limit | Reuse existing `max_sql_length` | Yes |
| Reject EXPLAIN if no eligible agent | Immediate `impact.status = "not_available"` | — |

### Implementation

- Rate limit: in-memory sliding window (existing `RateLimiter` pattern if available, else new)
- Concurrent limit: `Arc<DashMap<UserId, AtomicU32>>` で tracking + **ConcurrencyGuard (RAII)**

```rust
/// RAII guard that decrements the concurrent counter on drop.
/// Prevents quota leak on error, timeout, or client disconnect.
pub struct ConcurrencyGuard {
    counters: Arc<DashMap<String, AtomicU32>>,
    user_id: String,
}

impl Drop for ConcurrencyGuard {
    fn drop(&mut self) {
        if let Some(counter) = self.counters.get(&self.user_id) {
            counter.fetch_sub(1, Ordering::Relaxed);
        }
    }
}
```

- Concurrent limit: **DB-based enforcement (atomic)** — Use `INSERT ... SELECT` pattern to atomically check count + reserve slot in one transaction:
  ```sql
  INSERT INTO preflight_jobs (id, user_id, ...)
  SELECT ?, ?, ...
  WHERE (SELECT COUNT(*) FROM preflight_jobs WHERE user_id = ? AND status IN ('pending', 'claimed')) < ?
  ```
  If 0 rows inserted → limit exceeded → return 429. This eliminates the TOCTOU race between COUNT and INSERT.
  The in-memory `ConcurrencyGuard` is kept for fast-path rejection but DB insert is the authoritative gate.
- Agent capacity: Preflight jobs count against the agent's `max_concurrent` budget (shared pool). Implementation:
  - Agent adds `in_flight_preflight: u32` to `AgentStatusReport` (api-types, new field with `#[serde(default)]`)
  - Agent tracks preflight jobs in JobTracker (unified pool with type tag)
  - Server poll handler uses a **single shared budget** within one poll cycle:
    ```
    total_available = max_concurrent - in_flight - in_flight_preflight
    // 1. Allocate normal jobs first (up to total_available)
    normal_jobs = find_dispatched_jobs(..., limit = total_available)
    remaining = total_available - normal_jobs.len()
    // 2. Allocate preflight jobs from remainder only
    preflight_jobs = claim_for_agent(..., limit = remaining)
    ```
    This prevents double-spending the same capacity slots across job types.
  - If total_available ≤ 0: return neither normal jobs nor preflight jobs
  - Agent-side: both job types share one concurrency pool for drain/shutdown
  - Changed files: `crates/dbward-api-types/src/agent.rs` (add field), agent runner (tracking), server poll handler (shared budget calc)
- Agent availability check: `AgentRepo.list()` → filter by `databases` containing (db, env) + `derived_status == Healthy` + `status != Draining` → empty = reject explain

---

## API Design

### `POST /api/preflight`

#### Request

```json
{
  "database": "primary",
  "environment": "production",
  "sql": "UPDATE users SET status = 'inactive' WHERE last_login_at < '2025-01-01'",
  "operation": "execute_dml",
  "include_explain": true,
  "explain_timeout_ms": 5000
}
```

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| database | string | ✅ | — | Target database |
| environment | string | ✅ | — | Target environment |
| sql | string | ✅ | — | SQL to analyze (max: `max_sql_length`) |
| operation | string | ❌ | auto-detect | Override operation (rejected if it disagrees with classification) |
| include_explain | bool | ❌ | true | Whether to run EXPLAIN via agent |
| explain_timeout_ms | u64 | ❌ | 5000 | Max wait (clamped to server max) |

#### Response

```json
{
  "status": "blocked",
  "risk": "critical",
  "classification": {
    "statement_type": "UPDATE",
    "operation": "execute_dml",
    "mutating": true,
    "ddl": false,
    "multi_statement": false,
    "statement_count": 1
  },
  "review": {
    "findings": [
      {
        "code": "no_where_update",
        "action": "block",
        "message": "UPDATE statement has no WHERE clause.",
        "statement_index": 0
      }
    ],
    "blocked": true
  },
  "risk_assessment": {
    "level": "critical",
    "factors": ["LargeTable", "DropOperation"]
  },
  "policy": {
    "sql_valid": false,
    "caller_can_submit": true,
    "would_auto_approve": false,
    "requires_approval": true,
    "approvers": [{"selector": "role:dba-team", "min": 1}],
    "break_glass_allowed": true,
    "workflow_id": "wf:primary:production:abc123",
    "require_reason": true
  },
  "impact": {
    "status": "completed",
    "explain_plan": [{"sql": "UPDATE ...", "plan": {...}}],
    "estimated_rows": 12430221,
    "estimated_cost": 234567.89,
    "index_used": false
  },
  "fix_hints": [
    "Add a WHERE clause using an indexed column",
    "Limit the operation to a primary-key range or date range",
    "For production writes, include --reason with expected impact"
  ],
  "retryable": true,
  "next_actions": [
    "Run preflight again with a narrower WHERE clause",
    "Consider batching into smaller transactions"
  ]
}
```

#### Status values

| Status | Meaning |
|--------|---------|
| `requestable` | SQL is safe to submit as a request |
| `blocked` | SQL violates policy rules (fix required) |
| `warning` | SQL has warnings but can be requested |

#### Impact status values

| Status | Meaning |
|--------|---------|
| `completed` | EXPLAIN result available |
| `timeout` | Agent did not respond within timeout |
| `skipped` | include_explain=false |
| `not_available` | No eligible agent for this scope |
| `disabled_by_policy` | workflow.explain=false for this scope |
| `error` | EXPLAIN execution failed (driver error) |

---

## Architecture

### Layer Responsibilities

| Layer | Component | Responsibility |
|-------|-----------|---------------|
| Domain | `Permission::RequestPreflight`, `RequestPreflightExplain` | 権限バリアント |
| Domain | `services/fix_hints.rs` | review findings → fix hints 変換 (pure) |
| App | `PreflightUseCase` | オーケストレーション |
| App | `PreflightResult` (output DTO) | use case の戻り値型 |
| App | `PreflightJobRepo` (port trait) | preflight explain job CRUD |
| Infra | `sqlite/preflight_job_repo.rs` | SQLite 実装 + migration |
| Server | `POST /api/preflight` | HTTP handler |
| Server | `POST /api/agent/preflight-result` | Agent → Server 結果受信 |
| Server | `PreflightNotifier` | watch channel management |
| Agent | `runner/preflight.rs` | preflight job 処理 (EXPLAIN → submit) |
| CLI | `dbward preflight` | CLI コマンド |
| MCP | `dbward_preflight_sql` | MCP tool |

### PreflightUseCase Flow

```
1. Input validation (sql length, database, environment)
2. Rate limit check (per-user)
3. Authorization:
   a. authorize_scoped(user, RequestPreflight, db, env, &ResourceContext::Global) → fail = 403
   b. if include_explain: check RequestPreflightExplain permission
      → granted: effective_include_explain = true
      → denied: effective_include_explain = false (graceful degrade, not 403)
4. Database registration check — DatabaseRegistry.exists_active(db, env)
5. Dialect resolution — SchemaRepo.get_dialect(db, env)
6. SQL Classification — classify_full(sql, dialect)
   → ClassifyResult { classification: Result<Classification, ClassifyError>, parsed_statements: Option<Vec<Statement>> }
   → If Err(ClassifyError::Rejected { reason }): return blocked (e.g., transaction control)
   → If Err(ClassifyError::Empty): return Err(Validation("SQL is empty"))
   → If Ok(classification) with parsed_statements = None (DmlReason::ParseFailure):
     - Call sql_reviewer::review(raw_sql, dialect, rules) for fail-closed finding
     - Use classification.operation for workflow/permission (parse failure still classifies as execute_dml)
     - Continue with empty statements vec for table extraction (no tables found)
   → If Ok(classification) with parsed_statements = Some(stmts):
     - Normal path
   → If operation override provided AND disagrees with classified operation: reject (400)
   → Classification is authoritative for permission/workflow selection
7. Workflow lookup — PolicyEvaluator.evaluate_workflow(db, env, operation)
   → operation = classified operation (override ignored for policy/permission simulation)
   → If None: return blocked (fail-closed, no workflow = no request possible)
8. SQL Review — review_statements(stmts, dialect, policy.rules)
   → If parse_failure in findings: preserve blocking behavior
9. Table extraction + Schema lookup — tables, TableRiskInfo
10. Risk Assessment — risk_scorer::evaluate(input)
11. Policy Simulation — PolicyMapper::from_workflow(wf, approval_decision, review_blocked, caller_has_break_glass, caller_can_submit)
    - caller_can_submit: `authorizer.authorize_scoped(user, op_perm, db, env, &ResourceContext::Global).is_ok()`
      where op_perm = RequestQuery (SELECT) or RequestExecute (DML/DDL)
    - caller_has_break_glass: `authorizer.authorize_scoped(user, RequestBreakGlass, db, env, &ResourceContext::Global).is_ok()`
    - workflow.steps → approvers extraction
    - workflow.auto_approve → would_auto_approve
    - require_reason: from workflow config
12. Status determination:
    - review.blocked → "blocked"
    - workflow missing → "blocked" (fail-closed)
    - !caller_can_submit → "blocked" (permission insufficient)
    - risk >= workflow.auto_approve.max_risk_level → "warning"
    - else → "requestable" or "warning" (if findings.any(warn))
13. Fix hints generation — fix_hints::generate(findings, risk, policy)
14. EXPLAIN (if include_explain=true):
    a. Check workflow.explain setting
       → false: return impact.status = "disabled_by_policy"
    b. Check agent availability for (db, env) scope
       → None: return impact.status = "not_available"
    c. Acquire ConcurrencyGuard (increment counter, check limit)
       → Limit exceeded: return 429
       → Guard ensures decrement on any exit path (Drop)
    d. Register NotifierGuard (waiter for watch channel)
    e. Create PreflightJob (TTL = timeout + 5s)
    f. Wait on watch channel (tokio::time::timeout)
    g. DB state fallback check (handles lost-wakeup)
    h. On completion: parse explain result → impact fields
    i. On timeout: impact.status = "timeout"
    j. On driver error: impact.status = "error"
    k. Guards drop automatically → notifier entry removed + counter decremented
15. Lightweight audit — event_type: "preflight.attempted", metadata: {db, env, status, risk, blocked_codes}
    - SQL text: store fingerprint (redact_literals), NOT raw SQL
16. Return PreflightResult
```

---

## Policy Mapper

Workflow → PreflightPolicy の変換を明示的に定義:

```rust
// crates/dbward-app/src/use_cases/preflight.rs

impl PreflightPolicy {
    pub fn from_workflow(
        workflow: &Workflow,
        decision: &ApprovalDecision,
        review_blocked: bool,
        caller_has_break_glass: bool,
        caller_can_submit: bool,
    ) -> Self {
        let requires_approval = matches!(decision, ApprovalDecision::NeedsApproval);
        let would_auto_approve = matches!(decision, ApprovalDecision::AutoApproved { .. });

        // sql_valid: SQL passes review rules (no blocking findings)
        let sql_valid = !review_blocked;

        // caller_can_submit: caller has the operation-specific permission (RequestQuery/RequestExecute)
        // to actually create a request for this SQL. Checked during preflight to give accurate guidance.

        // Extract approvers from workflow steps (Selector → display string)
        let approvers: Vec<PreflightApprover> = workflow.steps.iter()
            .flat_map(|step| step.approvers.iter())
            .map(|a| PreflightApprover {
                selector: a.selector.to_string(), // Selector enum: Role(r)/User(u)/Group(g)
                min: a.min,
            })
            .collect();

        // break_glass_allowed reflects the caller's actual permission, not just theoretical availability
        let break_glass_allowed = caller_has_break_glass;

        Self {
            sql_valid,
            caller_can_submit,
            would_auto_approve,
            requires_approval,
            approvers,
            break_glass_allowed,
            workflow_id: Some(workflow.id.clone()),
            require_reason: workflow.require_reason,
        }
    }
}
```

Notes:
- `sql_valid` = `!review.blocked` (SQL passes static review)
- `caller_can_submit` = caller has operation-specific permission (`RequestQuery` for SELECT, `RequestExecute` for DML/DDL). Checked via `authorizer.authorize_scoped(user, perm, db, env, &ResourceContext::Global).is_ok()` (non-failing check)
- `break_glass_allowed` = caller has `Permission::RequestBreakGlass` for this scope
- `would_auto_approve` = what would happen if requested now (based on risk level + workflow config)
- Top-level `status` field: `requestable` only if BOTH `sql_valid` AND `caller_can_submit` are true

---

## PreflightJob Infrastructure

### Table schema

```sql
-- db/migrations/NNNN_preflight_jobs.sql
CREATE TABLE preflight_jobs (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    database_name TEXT NOT NULL,
    environment TEXT NOT NULL,
    sql_text TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',  -- pending | claimed | completed | expired | error
    claimed_by TEXT,
    claim_token TEXT,
    result_json TEXT,
    error_message TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    completed_at TEXT
);

CREATE INDEX idx_preflight_jobs_pending ON preflight_jobs(status, database_name, environment)
    WHERE status = 'pending';
CREATE INDEX idx_preflight_jobs_user_active ON preflight_jobs(user_id, status)
    WHERE status IN ('pending', 'claimed');
```

### Port trait

```rust
// crates/dbward-app/src/ports/repos.rs (append to existing file)
// Sync trait — matches existing port pattern (DryRunRepo, AgentRepo, etc. in same file).
// SQLite backend is sync (rusqlite), no need for async_trait.

pub trait PreflightJobRepo: Send + Sync {
    fn create(&self, job: &PreflightJob) -> Result<(), AppError>;
    /// Atomically check user limit + insert job. Returns Err(RateLimited) if limit exceeded.
    fn create_with_limit(&self, job: &PreflightJob, max_concurrent: u32) -> Result<(), AppError>;
    /// Atomically claim pending jobs matching agent scopes. Returns claimed jobs.
    fn claim_for_agent(&self, agent_id: &str, scopes: &[(String, String)], limit: usize) -> Result<Vec<PreflightJob>, AppError>;
    /// Complete a job. Verifies agent_id + claim_token + status='claimed'.
    /// Returns Ok(true) if updated, Ok(false) if job was already expired/completed (no-op).
    fn complete(&self, job_id: &str, agent_id: &str, claim_token: &str, result: serde_json::Value, now: &str) -> Result<bool, AppError>;
    /// Fail a job. Verifies agent_id + claim_token + status='claimed'.
    /// Returns Ok(true) if updated, Ok(false) if job was already expired/completed (no-op).
    fn fail(&self, job_id: &str, agent_id: &str, claim_token: &str, error: &str, now: &str) -> Result<bool, AppError>;
    fn get(&self, job_id: &str) -> Result<Option<PreflightJob>, AppError>;
    fn mark_expired(&self) -> Result<u64, AppError>;
    fn purge_old(&self, retention_secs: u64) -> Result<u64, AppError>;
}
```

**Note**: `create_with_limit` combines the INSERT SELECT atomic pattern (concurrency check + insert) into one method, matching the existing pattern where repo methods encapsulate complex SQL logic.

### Notification mechanism

```rust
// crates/dbward-server/src/preflight_notifier.rs (new)

pub struct PreflightNotifier {
    waiters: DashMap<String, tokio::sync::watch::Sender<bool>>,
}

impl PreflightNotifier {
    /// Register waiter BEFORE job becomes visible to agents.
    /// Returns receiver that will fire when agent submits result.
    pub fn register(&self, job_id: &str) -> tokio::sync::watch::Receiver<bool> { ... }
    pub fn notify(&self, job_id: &str) { ... }
    pub fn remove(&self, job_id: &str) { ... }
}

/// RAII guard that removes the notifier entry on drop.
/// Ensures cleanup on success, timeout, and client disconnect.
pub struct NotifierGuard<'a> {
    notifier: &'a PreflightNotifier,
    job_id: String,
}

impl Drop for NotifierGuard<'_> {
    fn drop(&mut self) {
        self.notifier.remove(&self.job_id);
    }
}
```

### Ordering guarantee (lost-wakeup prevention)

```rust
// In preflight HTTP handler:

// 1. Register waiter FIRST (before job is visible to agents)
let rx = notifier.register(&job_id);
let _guard = NotifierGuard { notifier: &notifier, job_id: job_id.clone() };

// 2. Create job in DB (sync repo, called via spawn_blocking)
let repo = repo.clone();
let job_clone = job.clone();
tokio::task::spawn_blocking(move || repo.create_with_limit(&job_clone, max_concurrent))
    .await
    .map_err(|_| AppError::Internal("task join error".into()))??;

// 3. Wait for notification OR timeout
let result = tokio::time::timeout(timeout, rx.changed()).await;

// 4. On notification OR timeout, always check DB state as fallback
//    (handles case where agent completed between create and subscribe)
let repo = repo.clone();
let jid = job_id.clone();
let job_record = tokio::task::spawn_blocking(move || repo.get(&jid))
    .await
    .map_err(|_| AppError::Internal("task join error".into()))??;

match job_record.map(|j| j.status.as_str()) {
    Some("completed") => /* use result_json */,
    Some("error") => /* return error status */,
    _ => /* timeout */,
}
```

This ensures:
- If agent completes before `rx.changed()` fires → DB state check catches it
- If agent completes during wait → notification wakes handler
- On any exit path (success, timeout, disconnect) → `NotifierGuard` drops → removes entry

---

## Agent Changes

### New in poll response

```json
{
  "jobs": [...],
  "dry_run_jobs": [...],
  "preflight_jobs": [
    {
      "id": "pf-job-123",
      "database": "primary",
      "environment": "production",
      "sql": "UPDATE users SET ...",
      "claim_token": "ct-abc"
    }
  ]
}
```

### Agent processing

```rust
// crates/dbward-agent/src/runner/preflight.rs (new)

pub async fn handle_preflight_jobs(
    jobs: Vec<PreflightJobPayload>,
    pools: &PoolManager,
    client: &ServerClient,
) {
    for job in jobs {
        let result = pools.get(&job.database, &job.environment)
            .explain(&job.sql, EXPLAIN_TIMEOUT_SECS).await;
        match result {
            Ok(plan) => client.submit_preflight_result(&job.id, &job.claim_token, plan).await,
            Err(e) => client.submit_preflight_error(&job.id, &job.claim_token, &e.to_string()).await,
        }
    }
}
```

### New API call

```
POST /api/agent/preflight-result
Body size limit: 256 KB (same as existing dry-run result endpoint)

{
  "job_id": "pf-job-123",
  "claim_token": "ct-abc",
  "result": { ... },      // EXPLAIN JSON (mutually exclusive with error). Max 256 KB.
  "error": null            // Error message. Max 4 KB.
}
```

**Security: Body size limits** — The endpoint applies `DefaultBodyLimit::max(256 * 1024)` (reusing existing limit from dry-run submit). Additionally, `result_json` is validated to be ≤ 256 KB and `error_message` ≤ 4 KB before persistence. Oversized payloads are rejected with 413.

---

## Parse Failure Handling

```rust
// In PreflightUseCase::execute()

let classify_result = sql_classifier::classify_full(&input.sql, dialect);

match &classify_result.classification {
    Err(ClassifyError::Rejected { reason }) => {
        // Outright rejection (e.g., transaction control)
        return Ok(PreflightResult::blocked_with_reason(reason));
    }
    Err(ClassifyError::Empty) => {
        return Err(AppError::Validation("SQL is empty".into()));
    }
    Ok(classification) => { /* continue */ }
}

// If parsed_statements is None (parse failure but classification succeeded via DmlReason::ParseFailure)
let (review_result, stmts) = match classify_result.parsed_statements {
    Some(stmts) => {
        let policy = self.policy_evaluator.get_sql_review_policy(&db, &env)?;
        let review = sql_reviewer::review_statements(&stmts, Some(dialect), &policy.rules);
        (review, stmts)
    }
    None => {
        // Fail-closed: treat as if parse_failure rule fired
        let policy = self.policy_evaluator.get_sql_review_policy(&db, &env)?;
        let review = sql_reviewer::review(&input.sql, Some(dialect), &policy.rules);
        (review, vec![])
    }
};
```

---

## Audit

Use existing audit model (`event_type` string + `metadata_json`):

```rust
// event_type: "preflight.attempted"
// event_category: "preflight"
// metadata_json:
{
    "database": "primary",
    "environment": "production",
    "status": "blocked",
    "risk_level": "critical",
    "blocked_codes": ["no_where_update"],
    "sql_fingerprint": "UPDATE users SET status = ? WHERE last_login_at < ?",
    "include_explain": true,
    "explain_status": "completed"
}
```

- SQL text は `redact_literals()` で fingerprint 化して保存（raw SQL は保存しない）
- 既存の `AuditWriter::record()` を使用

---

## Cleanup & Retention

### Background task

```rust
// crates/dbward-server/src/background/preflight.rs (new)
// Registered via build_task_defs() in background/mod.rs — supervisor-managed (auto-restart on panic)

pub(super) async fn preflight_cleanup_loop(state: AppState, shutdown: CancellationToken) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = interval.tick() => {
                let repo = state.background().preflight_job_repo();
                // 1. Mark expired: pending/claimed past TTL → expired
                match repo.mark_expired() {
                    Ok(n) if n > 0 => tracing::info!(task = "preflight_cleanup", expired = n),
                    Err(e) => tracing::error!(task = "preflight_cleanup", %e, "mark_expired failed"),
                    _ => {}
                }
                // 2. Physical delete: completed/expired/error older than 5min
                match repo.purge_old(300) {
                    Ok(n) if n > 0 => tracing::info!(task = "preflight_cleanup", purged = n),
                    Err(e) => tracing::error!(task = "preflight_cleanup", %e, "purge_old failed"),
                    _ => {}
                }
            }
        }
    }
}
```

### Retention policy

| Status | Retention | Action |
|--------|-----------|--------|
| pending/claimed | expires_at (TTL) | Mark as `expired` |
| completed | 5 minutes after completion | Physical DELETE |
| expired | 5 minutes after expiration | Physical DELETE |
| error | 5 minutes after creation | Physical DELETE |

- Preflight jobs contain raw SQL and EXPLAIN results — sensitive data
- Short retention because results are consumed immediately by the HTTP handler
- Audit event (with fingerprinted SQL) provides the durable record
- Agent は claim 時に `expires_at` をチェック → 期限切れなら skip

### Port methods

```rust
fn mark_expired(&self) -> Result<u64, AppError>;
fn purge_old(&self, retention_secs: u64) -> Result<u64, AppError>;
```

---

## Testing Plan

### Unit Tests

| Location | Test |
|----------|------|
| domain/services/fix_hints.rs | 全 RuleId → hint mapping |
| domain/auth/permission.rs | RequestPreflight, RequestPreflightExplain roundtrip (roundtrip_all_variants テスト更新) |

### App-layer Tests

| Location | Test |
|----------|------|
| app/use_cases/preflight.rs | Happy path: SELECT → requestable, auto_approve |
| app/use_cases/preflight.rs | Blocked: UPDATE without WHERE → blocked + hints |
| app/use_cases/preflight.rs | Warning: large_table → warning + requestable |
| app/use_cases/preflight.rs | No workflow → blocked (fail-closed) |
| app/use_cases/preflight.rs | Parse failure → fail-closed with ParseFailure finding |
| app/use_cases/preflight.rs | EXPLAIN timeout → impact.status = "timeout" |
| app/use_cases/preflight.rs | include_explain = false → impact.status = "skipped" |
| app/use_cases/preflight.rs | No eligible agent → impact.status = "not_available" |
| app/use_cases/preflight.rs | Authorization failure → 403 |
| app/use_cases/preflight.rs | Rate limit exceeded → 429 |
| app/use_cases/preflight.rs | Concurrent limit exceeded → 429 |
| app/use_cases/preflight.rs | EXPLAIN driver error → impact.status = "error" |

### Server Integration Tests

| Location | Test |
|----------|------|
| server_test.rs | POST /api/preflight 200 — basic SELECT, requestable |
| server_test.rs | POST /api/preflight 200 — blocked UPDATE |
| server_test.rs | POST /api/preflight 401 — no auth |
| server_test.rs | POST /api/preflight 403 — insufficient permission |
| server_test.rs | POST /api/preflight 422 — invalid body |
| server_test.rs | POST /api/preflight 429 — rate limit |
| server_test.rs | POST /api/agent/preflight-result — agent submits result |
| server_test.rs | POST /api/agent/preflight-result — expired job rejected |
| server_test.rs | Preflight job appears in poll response |

### E2E

| Script | Scenario |
|--------|----------|
| dev/e2e/preflight.sh | SELECT → requestable (no EXPLAIN needed) |
| dev/e2e/preflight.sh | UPDATE without WHERE → blocked with hints |
| dev/e2e/preflight.sh | UPDATE with WHERE + EXPLAIN (agent running) |
| dev/e2e/preflight.sh | include_explain=false → skipped, fast response |
| dev/e2e/preflight.sh | MCP tool `dbward_preflight_sql` via CLI |
| dev/e2e/preflight.sh | Expired job: short timeout → timeout status |

---

## Changed Files

| Crate | File | Change |
|-------|------|--------|
| dbward-domain | src/services/fix_hints.rs | **NEW** — Fix hint generator (pure) |
| dbward-domain | src/services/mod.rs | pub mod fix_hints |
| dbward-domain | src/auth/permission.rs | Add RequestPreflight, RequestPreflightExplain |
| dbward-app | src/error.rs | Add `RateLimited(String)` variant |
| dbward-app | src/use_cases/preflight.rs | **NEW** — PreflightUseCase + PreflightResult DTO |
| dbward-app | src/use_cases/mod.rs | pub mod preflight |
| dbward-app | src/ports/repos.rs | Add PreflightJobRepo trait + PreflightJob struct |
| dbward-app | src/ports/mod.rs | pub use repos::PreflightJobRepo + PreflightJob |
| dbward-infra | src/sqlite/preflight_job_repo.rs | **NEW** — SQLite impl |
| dbward-infra | src/sqlite/schema.rs | Add MIGRATION_V24 (preflight_jobs table), bump SCHEMA_VERSION |
| dbward-infra | src/sqlite/mod.rs | pub mod preflight_job_repo |
| dbward-server | src/routes/preflight.rs | **NEW** — POST /api/preflight |
| dbward-server | src/routes/agent.rs | Add preflight_jobs to poll response + preflight-result endpoint |
| dbward-server | src/routes/mod.rs | pub mod preflight + router + map_error for RateLimited→429 |
| dbward-server | src/preflight_notifier.rs | **NEW** — watch channel management |
| dbward-server | src/background/preflight.rs | **NEW** — cleanup TaskDef (mark_expired + purge_old) |
| dbward-server | src/background/mod.rs | Add `preflight_cleanup` TaskDef to build_task_defs() + `mod preflight` |
| dbward-agent | src/runner/preflight.rs | **NEW** — preflight job handler |
| dbward-agent | src/runner/mod.rs | Integrate preflight job processing in poll loop + tracking |
| dbward-api-types | src/agent.rs | Add `in_flight_preflight: u32` to AgentStatusReport |
| dbward-cli | src/commands/preflight.rs | **NEW** — CLI command |
| dbward-cli | src/commands/mod.rs | Add preflight subcommand |
| dbward-cli | src/mcp/tools/preflight.rs | **NEW** — MCP tool |
| dbward-cli | src/mcp/tools/mod.rs | Register preflight tool + remove preview_impact dispatch |
| dbward-cli | src/mcp/tools/schema.rs | Remove `handle_preview_impact` |
| dbward-cli | src/mcp/backend.rs | Remove `preview_impact` impl |
| dbward-cli | src/mcp/defs.rs | Remove preview_impact def + add preflight def |
| dbward-mcp | src/tools/request.rs | Remove `preview_impact` function |
| dbward-mcp | src/tools/mod.rs | Remove dispatch branch |
| dbward-mcp | src/ports.rs | Remove `preview_impact` method from trait |
| dbward-mcp | src/handler.rs | Remove mock impl |
| dbward-mcp | src/defs.rs | Remove tool definition |
| dev/e2e/preflight.sh | **NEW** — E2E test |
| docs/reference/api.md | Add /api/preflight + /api/agent/preflight-result |
| docs/reference/cli.md | Add preflight command |
| docs/guides/mcp-integration.md | Add dbward_preflight_sql |

---

## Implementation Plan

1. Domain: Permission::RequestPreflight, RequestPreflightExplain 追加
2. Domain: fix_hints.rs (pure function)
3. App: PreflightJobRepo port trait
4. App: PreflightResult DTO + PreflightPolicy::from_workflow mapper
5. Infra: SQLite migration + preflight_job_repo 実装
6. App: PreflightUseCase (5層分析 + parse failure handling)
7. Server: PreflightNotifier (watch channel)
8. Server: POST /api/preflight route
9. Server: POST /api/agent/preflight-result route
10. Server: Poll response に preflight_jobs 追加
11. Agent: runner/preflight.rs (job handler)
12. Agent: poll loop 統合
13. CLI: `dbward preflight` コマンド
14. MCP: `dbward_preflight_sql` tool
15. Tests: unit + integration + server_test
16. E2E: preflight.sh
17. Docs: api.md, cli.md, mcp-integration.md

---

## Open Questions (all resolved)

| Question | Decision |
|----------|----------|
| EXPLAIN mechanism | Dedicated PreflightJob table + watch channel notification |
| Claim model | Poll atomically claims (UPDATE RETURNING) — no separate claim step |
| Agent changes | Yes — new preflight job handler + submit endpoint |
| Permission model | Two-tier: preflight (static) + preflight_explain (EXPLAIN) |
| Abuse controls | Rate limit + concurrent limit + server-side timeout cap |
| Parse failure | Explicit branch, preserve fail-closed via review(raw_sql) |
| DryRunJob reuse | No — dedicated table to avoid breaking existing contract |
| Audit model | Existing event_type + metadata_json pattern, SQL fingerprinted |
| Cleanup | Background task: mark_expired + purge_old (physical DELETE after 5min) |
| DTO placement | App layer (use case output), not domain services |
| Policy semantics | can_request = !review.blocked, break_glass_allowed = caller permission |
| workflow.explain | Preflight respects workflow.explain; disabled → "disabled_by_policy" |
| SQL retention | Raw SQL in preflight_jobs physically deleted after 5min |

---

## Design Notes

### Future Refactoring: Shared Assessment Pipeline

PreflightUseCase と CreateRequest::execute() は以下のロジックを共有する:
- DB登録チェック → Dialect解決 → SQL分類 → Workflow lookup → SQL Review → Table抽出 → Risk Assessment

第1イテレーションでは独立実装（CreateRequest のロジックをコピーしない。各サービスを直接呼ぶ）。
将来的に `app::services::sql_assessment::assess()` に共通read-only部分を切り出す候補。
実装時に TODO コメントで記録する。

### Sync Trait Pattern

既存の全 port trait は同期 (`fn`, not `async fn`)。理由:
- SQLite backend (rusqlite) は同期 API
- `conn.lock()` + 同期 SQL 実行
- tokio spawn_blocking で呼び出し元が非同期に橋渡し

PreflightJobRepo もこのパターンに従う。HTTP handler / background task からは
`tokio::task::spawn_blocking(move || repo.method())` で呼び出す。

### Known Limitations (accepted)

1. **Agent capacity race across concurrent polls**: 同一 agent が複数 poll を同時発行した場合、
   `total_available` の計算に race がある。ただし agent の poll_interval で直列化されるため実用上は
   起きない。既存の normal job dispatch でも同様の特性。
2. **Rate limiter in-memory only**: プロセス再起動でカウンタリセットされる。dbward は single-instance
   (SQLite) が前提のため許容。concurrent limit は DB authoritative で保護されている。

### Removal of `dbward_preview_impact` MCP tool

既存の `dbward_preview_impact` (crates/dbward-mcp/src/tools/request.rs, crates/dbward-cli/src/mcp/tools/schema.rs):
- `EXPLAIN {sql}` を request として create_request → resume → 結果取得
- **Request を作る** (承認者に通知される可能性あり)
- EXPLAIN のみ。lint/risk/policy/fix_hints なし

Preflight はこれの完全上位互換。同じ PR で削除する。

**削除対象**:
- `crates/dbward-mcp/src/tools/request.rs` — `preview_impact` 関数 + テスト mock 削除
- `crates/dbward-mcp/src/tools/mod.rs` — dispatch 分岐削除
- `crates/dbward-mcp/src/ports.rs` — `preview_impact` メソッド削除
- `crates/dbward-mcp/src/handler.rs` — mock 実装削除
- `crates/dbward-mcp/src/defs.rs` — tool 定義削除
- `crates/dbward-cli/src/mcp/tools/mod.rs` — dispatch 分岐削除
- `crates/dbward-cli/src/mcp/tools/schema.rs` — `handle_preview_impact` 削除
- `crates/dbward-cli/src/mcp/backend.rs` — 実装削除
- `crates/dbward-cli/src/mcp/defs.rs` — tool 定義 + validation helper + テスト削除
- `crates/dbward-server/src/mcp_backend.rs` — server-side MCP backend impl 削除
- `docs/guides/mcp-integration.md` — ツール一覧から削除
- `docs/reference/mcp.md` — API リファレンスから削除
