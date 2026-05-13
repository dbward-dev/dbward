# v0.1.1 リファクタリング設計書

## 目的

クリーンアーキテクチャ違反を修正し、テスト容易性と保守性を向上させる。

## 違反一覧

### High (5件)

| # | ファイル | 内容 |
|---|---|---|
| V-1 | dbward-app/src/use_cases/token_manage.rs:114 | `Uuid::new_v4()` 直接呼び出し。IdGenerator port を使うべき |
| V-4 | dbward-domain/src/entities/audit_event.rs:106 | `AuditEvent::simple()` が `Utc::now()` 直接呼び出し |
| V-5 | dbward-server/src/routes/requests.rs:170-253 | `list` handler に認可+フィルタリングのビジネスロジック |
| V-6 | dbward-server/src/routes/requests.rs:278-370 | `get` handler に long-poll + 認可 + redaction ロジック |
| V-11 | dbward-server/src/lib.rs:283-293 | Server が `rusqlite` 直接使用。DatabaseRegistry port をバイパス |

### Medium (8件)

| # | ファイル | 内容 |
|---|---|---|
| V-3 | dbward-app/Cargo.toml | `uuid` crate が app 層に直接依存 |
| V-7 | routes/requests.rs:114-145 | create handler が repo を再読み込みして approvers 取得 |
| V-8 | routes/requests.rs:635-663 | list_results が use case 層をバイパス |
| V-12 | dbward-server/src/lib.rs:439-443 | bootstrap token 生成がハッシュロジックを重複 |
| V-13 | middleware/auth.rs:57,97 | `Utc::now()` 直接呼び出し（Clock port 未使用） |
| V-17 | routes/policies.rs:48-75 | route handler 内で Workflow ドメインオブジェクト構築 |
| V-18 | server/src/lib.rs | 500+ 行の composition + bootstrap + sync 混在 |
| V-19 | routes/requests.rs | 663 行に 8 handler + base64 encoder + ビジネスロジック |

### Low (7件 — 対応しない)

V-2 (sha2 in app), V-9/V-10 (simple read handlers), V-14/V-15 (startup/agent Utc::now), V-16 (UnitOfWork), V-20 (large repo file)

---

## 対応方針

### R-1: Clock trait 統一

**対象:** V-4, V-13, V-14 + background.rs, webhook/dispatcher.rs の AuditEvent::simple() 呼び出し全箇所

- `AuditEvent::simple()` → `AuditEvent::at(timestamp, ...)` に変更。全27箇所の呼び出し元が Clock 経由で timestamp を渡す
- middleware/auth.rs → `state.clock.now()` を使用（AppState に既に Clock あり）
- server/lib.rs sync → `state.clock.now()` を使用
- background.rs, webhook/dispatcher.rs → Clock を引数で受け取る

**注意:** AuditEvent のシグネチャ変更は infra 層テスト（integration.rs 7箇所）にも影響。一括変更で対応。

### R-2: IdGenerator trait 統一

**対象:** V-1, V-3

- `token_manage.rs` の `Uuid::new_v4()` → `format!("dbw_{}", self.id_gen.generate())` で代替
- `uuid` crate を `dbward-app/Cargo.toml` から削除

### R-3: routes 分割 + use case 抽出（3段階）

**対象:** V-5, V-6, V-7, V-8, V-11, V-12, V-17, V-18, V-19

#### R-3a: use case 追加
- `ListRequests` use case: 認可 + フィルタリング + ページネーション（ロジックはそのまま移動、DB側フィルタ変更はしない）
- `GetRequest` use case: 認可 + detail redaction
- long-poll は handler に残す（tokio 依存を use case に持ち込まない。use case は Request を返すのみ）

#### R-3b: handler 薄型化
- handler は HTTP 変換 + use case 呼び出しのみ
- base64 encoder → utility module に移動
- CreateWorkflowInput DTO 導入（policies handler から Workflow 構築を use case に移動）
- CreateRequestOutput に approvers 追加（re-read 不要に）

#### R-3c: lib.rs 分割 + DatabaseRegistry 拡張
- `bootstrap.rs`: token 生成は `TokenManage::create()` use case を呼ぶ形に変更（sha2 重複解消）
- `sync.rs`: workflow/webhook sync from config
- `DatabaseRegistry` port に `register(db, env)` 追加
- server の `rusqlite` 依存を `dev-dependencies` に移動（テスト用に残す）

---

## 実装順序

1. R-2 (IdGenerator) — 1ファイル修正。最もリスク低い
2. R-1 (Clock) — 27箇所。R-2 で手順確認後に着手
3. R-3a (use case 追加) — 既存 handler は変更しない
4. R-3b (handler 薄型化) — handler から use case を呼ぶように変更
5. R-3c (lib.rs 分割) — bootstrap + sync 抽出 + DatabaseRegistry 拡張

各ステップで 354 テストが通ることを確認。

## テスト方針

- 既存 354 テストが全て通ること
- Clock/IdGenerator の mock を使った新規テスト追加
- use case 単体テスト追加（ListRequests, GetRequest）

## 設計判断

- **long-poll は handler に残す**: tokio 依存を use case 層に持ち込まない。use case は Request データを返すのみ
- **V-8 (list_results) は Low に格下げ**: 現状は repo 呼び出し + JSON 変換のみ。将来フィルタ追加時に use case 化
- **一括変更方針**: `#[deprecated]` による段階的移行は不採用。v0.1.1 で完了させる
- **rusqlite は dev-dependencies に移動**: テストでの直接 DB 操作は許容
