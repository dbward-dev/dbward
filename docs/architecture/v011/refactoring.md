# v0.1.1 リファクタリング設計書

## 目的

クリーンアーキテクチャ違反を修正し、テスト容易性と保守性を向上させる。

## 違反一覧（現状コード反映済み）

### 解決済み（本PR）

| # | 内容 | 対応 |
|---|---|---|
| V-1 | `Uuid::new_v4()` in token_manage.rs | ✅ TokenValueGenerator port 導入 |
| V-3 | `uuid` crate in dbward-app | ✅ 削除済み |
| V-4 | `AuditEvent::simple()` が `Utc::now()` | ✅ timestamp 引数追加 |
| V-5 | `list` handler にビジネスロジック | ✅ ListRequests use case 抽出 |
| V-13 | middleware `Utc::now()` | ✅ state.clock.now() に変更 |

### 残存（R-3b/R-3c で対応）

| # | ファイル | 内容 |
|---|---|---|
| V-6 | routes/requests.rs get handler | long-poll + 認可。**認可を wait の前に実行する設計に変更** |
| V-7 | routes/requests.rs create handler | repo 再読み込みで approvers 取得 |
| V-11 | server/src/lib.rs | rusqlite 直接使用。DatabaseRegistry port 拡張で解消 |
| V-12 | server/src/lib.rs bootstrap | sha2 重複。TokenManage use case 経由に変更 |
| V-17 | routes/policies.rs | handler 内で Workflow 構築 |
| V-18 | server/src/lib.rs | sync_workflows/sync_webhooks が server 層でドメインオブジェクト構築+repo更新。**app 層の SyncConfig use case に寄せる** |
| V-19 | routes/requests.rs | base64 encoder 混在 |

---

## 設計判断（Codex レビュー反映）

- **long-poll は handler に残すが、認可は wait の前に実行する**: 未認可ユーザーへの存在確認オラクルを防ぐ
- **pending_for_me の認可**: `RequestApprove` 権限があれば `RequestView` なしでも pending_for_me は使える（承認者が一覧を見られないのは不自然）。ListRequests use case で分岐追加
- **sync_workflows/sync_webhooks**: ファイル分割だけでなく app 層の `SyncConfig` use case に寄せる（server 層でのドメインオブジェクト構築を排除）
- **V-8 (list_results) は Low に格下げ**: 現状は repo 呼び出し + JSON 変換のみ
- **一括変更方針**: `#[deprecated]` による段階的移行は不採用
- **rusqlite は register_databases 置き換え完了後に dev-dependencies 移動**

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

## 次の実装順序（R-3b/R-3c）

1. `GetRequest` の認可境界を決定: wait の前に認可実行
2. `GetRequest` use case 抽出（認可 + detail redaction）
3. `ListRequests` に `RequestApprove` ベースの pending_for_me 認可分岐追加
4. `SyncConfig` use case 作成（sync_workflows/sync_webhooks を app 層に移動）
5. `DatabaseRegistry::register()` 追加 + `register_databases` 置き換え
6. `bootstrap.rs` 分離（TokenManage::create 経由）
7. `rusqlite` を dev-dependencies に移動

## テスト方針

- 既存 354 テストが全て通ること
- Clock/IdGenerator の mock を使った新規テスト追加
- use case 単体テスト追加（ListRequests, GetRequest）

## 設計判断

- **long-poll は handler に残す**: tokio 依存を use case 層に持ち込まない。use case は Request データを返すのみ
- **V-8 (list_results) は Low に格下げ**: 現状は repo 呼び出し + JSON 変換のみ。将来フィルタ追加時に use case 化
- **一括変更方針**: `#[deprecated]` による段階的移行は不採用。v0.1.1 で完了させる
- **rusqlite は dev-dependencies に移動**: テストでの直接 DB 操作は許容

---

## PR スコープ分離

### PR #6（本PR — 完了）
- R-2: uuid 依存削除 + IdGenerator 経由
- R-1: AuditEvent timestamp 引数化 + Clock port 統一
- R-3a: ListRequests use case 抽出（ロジックそのまま移動）
- TokenValueGenerator port 導入

### PR #7（次 — R-3b/R-3c）
- GetRequest use case: 認可を wait の前に実行
- ListRequests 認可モデル修正: pending_for_me は RequestApprove で許可
- pending_for_me の絞り込み修正: populate_pending_approvers の approve role 全注入を廃止
- SyncConfig use case: sync_workflows/sync_webhooks を app 層に移動
- DatabaseRegistry::register() 追加 + register_databases 置き換え
- bootstrap.rs: TokenManage::create() 経由
- CreateRequestOutput に approvers 追加
- CreateWorkflowInput DTO 導入
- rusqlite を dev-dependencies に移動

### Codex 2回目レビュー指摘（全て PR #7 スコープ）
1. pending_for_me が RequestView 必須のまま → PR #7 で修正
2. GET /requests/{id} の認可前 long-poll → PR #7 で修正
3. populate_pending_approvers の approve role 全注入 → PR #7 で修正
4. GET /requests/{id} approver fallback が広すぎ → PR #7 で修正
5. sync/register/bootstrap 未実装 → PR #7 で実装
6. create handler の repo 再読込 → PR #7 で修正
