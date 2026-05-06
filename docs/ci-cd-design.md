# dbward CI/CD設計書

## 目的

`dbward`をCI/CDに組み込み、以下を満たす運用フローを定義する。

- `dbward.toml`はアプリのリポジトリにコミットする
- 秘密情報は`${ENV_VAR}`で展開する
- `dbward`は migration と SQL 実行のワークフローを担う
- アプリのビルド・配置・トラフィック切り替えは `dbward` の責務外とする

この設計では、`dbward` は「DB変更リクエストの作成、承認、dispatch、結果取得」を担い、GitHub Actions は「いつ実行するか」「どの順で実行するか」「アプリ deploy とどうつなぐか」を担う。

## スコープ

`dbward` が担うこと:

- migration 実行リクエストの作成
- SQL 実行リクエストの作成
- 承認フロー
- DB変更の実行
- 実行結果の取得
- 監査ログ

`dbward` が担わないこと:

- アプリの build
- アプリの deploy
- Kubernetes / ECS / VM への配置
- ヘルスチェックの実行基盤
- deploy 全体の成否判定ロジック

## 前提構成

### リポジトリ内の `dbward.toml`

`dbward.toml` はコミットし、接続先やトークンは環境変数で注入する。

```toml
default_database = "app"
migrations_dir = "db/migrations"

[server]
url = "${DBWARD_SERVER_URL}"
token = "${DBWARD_SERVER_TOKEN}"

[databases.app]
```

補足:

- `dbward` は TOML 読み込み時に `${ENV_VAR}` を展開する
- GitHub Actions では `env:` または `secrets` から注入する
- staging 用と production 用で token は分ける

### 推奨トークン分離

- `DBWARD_STAGING_TOKEN`: staging 用のCI実行トークン
- `DBWARD_PROD_REQUEST_TOKEN`: production の request 作成用トークン
- `DBWARD_PROD_EXECUTE_TOKEN`: production の dispatch / result 取得用トークン
- `DBWARD_HOTFIX_TOKEN`: hotfix / data patch 用トークン

### dbwardワークフロー方針

- `staging`: auto-approve
- `production`: DBA 承認必須
- `rollback`: DBA 承認必須
- `hotfix`:
  - 通常経路は DBA 承認必須
  - 緊急時のみ break-glass を許可

## 設計原則

### 1. staging は単一workflowでよい

`staging` は auto-approve 前提なので、承認待ちが発生しない。  
そのため 1 本の workflow の中で migration → app deploy → verify を順に実行できる。

### 2. production は request 作成と実行を分ける

`dbward` は承認後も `dbward request resume <id>` で明示 dispatch する設計である。  
production で承認待ちの間 GitHub Actions の job を待機させると、運用上扱いづらい。

そのため production は以下の 2 段階に分ける。

1. migration request を作成して終了
2. DBA 承認後、別 workflow で request を dispatch して実行

これにより「承認待ちの間CIはどうなるか」に対する答えは明確で、`CIは終了する。承認後に別workflowを起動する` となる。

### 3. migration は原則 deploy 前

原則は `migration first, deploy second` とする。  
ただし前提は「後方互換のある migration」に限る。

適する変更:

- テーブル追加
- カラム追加
- index追加
- nullable な拡張

避けるべき変更:

- 既存カラム削除
- NOT NULL 化を即時で入れる変更
- 旧アプリが読めない schema 変更

破壊的変更は expand/contract で 2 回以上の release に分割する。

### 4. app deploy 失敗時に migration down を自動実行しない

理由:

- down が常に安全とは限らない
- データ変換を伴う migration は不可逆なことがある
- app deploy 失敗の原因が DB とは限らない

したがって、app deploy 失敗時は自動 rollback ではなく:

- まずアプリ側 rollback を検討する
- DB rollback が必要な場合のみ、明示的な rollback workflow を使う

### 5. 冪等性キーを必ず使う

GitHub Actions の rerun や二重起動で同じ migration request を重複作成しないため、`--idempotency-key` を必ず付ける。

例:

```text
${repo}:${sha}:staging-migrate
${repo}:${sha}:prod-migrate
${repo}:${sha}:rollback:1
```

## フロー一覧

| フロー | 起点 | 承認 | dbward実行 | Actions構成 |
|---|---|---|---|---|
| 開発フロー | 開発者ローカル + PR | なし | 開発者がローカルで実行 | PR checks |
| Staging deploy | `main` への merge | auto-approve | workflow 内で即実行 | 単一workflow、複数job |
| Production deploy | 手動 trigger | DBA 承認あり | request 作成後、承認済み request を別workflowで実行 | 2 workflow |
| Hotfix / データパッチ | 手動 trigger | 通常承認 or break-glass | SQL 実行 | 2 workflow または 1 workflow |
| Rollback | 手動 trigger | DBA 承認あり | `migrate down` | 2 workflow |

## 1. 開発フロー

### 何が起きるか

1. 開発者が `dbward migrate create <name>` で migration を作る
2. 開発者がローカル DB で `dbward migrate up --environment development` を実行する
3. 必要なら `dbward migrate down --environment development --count 1` で可逆性を確認する
4. アプリのローカル検証を行う
5. migration ファイルとアプリ変更を含めて PR を作成する

### dbwardの役割

- migration ファイル作成
- migration 実行
- migration down の動作確認

### CIの役割

- PR 上で migration を含む変更を検知する
- テストを実行する
- 必要なら一時 DB 上で migration 適用確認を行う

### 推奨コマンド

```bash
dbward migrate create add_user_status
dbward migrate up --environment development
dbward migrate status --environment development
dbward migrate down --environment development --count 1
dbward migrate up --environment development
```

### PR checks の位置づけ

PR checks は `dbward` 本番承認フローの一部ではなく、migration ファイルの整合性確認を補助する任意の仕組みとする。  
中身はリポジトリごとに異なるため、この設計書では必須フローから外す。

## 2. Staging deploy

### 何が起きるか

1. PR merge で CI が起動する
2. `dbward migrate up --environment staging` を実行する
3. staging は auto-approve のため、そのまま migration が適用される
4. migration 成功後にアプリ deploy を行う
5. deploy 後に疎通確認を行う

### dbwardの役割

- staging migration request の作成
- auto-approve 済み request の dispatch / 結果取得
- 監査ログ保存

### CIの役割

- 実行順序制御
- app build / deploy
- verify 実行
- 失敗時の通知

### ジョブ構成

推奨は 4 job:

1. `test`
2. `migrate_staging`
3. `deploy_staging`
4. `verify_staging`

`migrate_staging` と `deploy_staging` は分ける。  
理由は「DB変更失敗で app deploy を確実に止める」ため。

### GitHub Actions例

```yaml
name: deploy-staging

on:
  push:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: make test

  migrate_staging:
    runs-on: ubuntu-latest
    needs: test
    env:
      DBWARD_SERVER_URL: ${{ secrets.DBWARD_SERVER_URL }}
      DBWARD_SERVER_TOKEN: ${{ secrets.DBWARD_STAGING_TOKEN }}
      IDEMPOTENCY_KEY: ${{ github.repository }}:${{ github.sha }}:staging-migrate
    steps:
      - uses: actions/checkout@v4

      - name: Install dbward
        run: cargo install --path crates/dbward-cli --force

      - name: Apply staging migrations
        run: |
          dbward migrate up \
            --environment staging \
            --repo "${{ github.repository }}" \
            --ticket "${{ github.sha }}" \
            --idempotency-key "$IDEMPOTENCY_KEY"

  deploy_staging:
    runs-on: ubuntu-latest
    needs: migrate_staging
    steps:
      - uses: actions/checkout@v4
      - name: Deploy app
        run: ./scripts/deploy-staging.sh

  verify_staging:
    runs-on: ubuntu-latest
    needs: deploy_staging
    steps:
      - uses: actions/checkout@v4
      - name: Verify deployment
        run: ./scripts/verify-staging.sh
```

### 失敗時の扱い

- migration 失敗: app deploy しない
- app deploy 失敗: 自動で `migrate down` しない
- verify 失敗: deploy 側の rollback を判断し、必要なら別途 rollback workflow を起動する

## 3. Production deploy

### 何が起きるか

1. staging 確認後、運用者が production deploy を手動起動する
2. CI が production migration request を作成する
3. DBA が `dbward request approve <id>` で承認する
4. 別 workflow で `dbward request resume <id>` を実行して migration を適用する
5. migration 成功後に app deploy を行う
6. deploy 後に verify を行う

### dbwardの役割

- production migration request 作成
- 承認状態の管理
- approved request の dispatch
- 実行結果の返却
- 監査ログ

### CIの役割

- request 作成
- request id の提示
- 承認済み request の dispatch
- app deploy / verify

### 承認待ちの間CIはどうなるか

推奨は `待たない`。  
request 作成 workflow は request id を出力して終了する。DBA 承認後に、別 workflow を手動で起動して execution を続行する。

これは以下より優先する:

- 1つの job を長時間 polling させる方式
- GitHub runner を承認待ちで占有する方式

### ジョブ / workflow 構成

推奨は 2 workflow:

1. `prod-migration-request.yml`
2. `prod-deploy-after-approval.yml`

### Workflow 1: request 作成

```yaml
name: prod-migration-request

on:
  workflow_dispatch:
    inputs:
      ref:
        description: "Git ref to deploy"
        required: true
        type: string

jobs:
  create_request:
    runs-on: ubuntu-latest
    env:
      DBWARD_SERVER_URL: ${{ secrets.DBWARD_SERVER_URL }}
      DBWARD_SERVER_TOKEN: ${{ secrets.DBWARD_PROD_REQUEST_TOKEN }}
      IDEMPOTENCY_KEY: ${{ github.repository }}:${{ inputs.ref }}:prod-migrate
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ inputs.ref }}

      - name: Install dbward
        run: cargo install --path crates/dbward-cli --force

      - name: Create migration request
        id: create
        shell: bash
        run: |
          set -euo pipefail

          output="$(
            dbward migrate up \
              --environment production \
              --repo "${{ github.repository }}" \
              --ticket "${{ github.sha }}" \
              --idempotency-key "$IDEMPOTENCY_KEY" \
              2>&1
          )"

          echo "$output"

          request_id="$(printf '%s\n' "$output" | sed -n 's/.*Request \([^ ]*\) requires approval\..*/\1/p' | tail -n1)"

          if [ -z "$request_id" ]; then
            echo "failed to extract request id"
            exit 1
          fi

          echo "request_id=$request_id" >> "$GITHUB_OUTPUT"

          {
            echo "## Production migration request created"
            echo
            echo "- Ref: \`${{ inputs.ref }}\`"
            echo "- Request ID: \`$request_id\`"
            echo "- Approve with: \`dbward request approve $request_id --comment \\\"approved for prod\\\"\`"
            echo "- Execute after approval with workflow: \`prod-deploy-after-approval\`"
          } >> "$GITHUB_STEP_SUMMARY"
```

補足:

- `dbward migrate up` は pending 時に request を作る
- 現状のCLIは pending 経路で request id を人向け表示するため、CIでは標準出力を parse している
- 将来的に machine-readable な pending 出力が追加されたら、その形式へ置き換える

### Workflow 2: 承認後に migration 実行 + app deploy

```yaml
name: prod-deploy-after-approval

on:
  workflow_dispatch:
    inputs:
      ref:
        description: "Git ref to deploy"
        required: true
        type: string
      request_id:
        description: "Approved dbward request id"
        required: true
        type: string

jobs:
  migrate_production:
    runs-on: ubuntu-latest
    environment: production
    env:
      DBWARD_SERVER_URL: ${{ secrets.DBWARD_SERVER_URL }}
      DBWARD_SERVER_TOKEN: ${{ secrets.DBWARD_PROD_EXECUTE_TOKEN }}
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ inputs.ref }}

      - name: Install dbward
        run: cargo install --path crates/dbward-cli --force

      - name: Ensure request is approved
        run: |
          dbward request show "${{ inputs.request_id }}" --format json | \
            jq -e '.status == "approved" or .status == "auto_approved"'

      - name: Dispatch and wait for result
        run: |
          dbward request resume "${{ inputs.request_id }}"

  deploy_production:
    runs-on: ubuntu-latest
    needs: migrate_production
    environment: production
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ inputs.ref }}

      - name: Deploy app
        run: ./scripts/deploy-production.sh

  verify_production:
    runs-on: ubuntu-latest
    needs: deploy_production
    environment: production
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ inputs.ref }}

      - name: Verify production deployment
        run: ./scripts/verify-production.sh
```

### 運用メモ

- DBA の承認操作は CI の中でやらない
- 承認者の identity を `dbward` の監査ログに残すため、DBA が自分の資格情報で `dbward request approve` する
- GitHub Environment の approval を併用してもよいが、それは `dbward` 承認の代替ではなく補助である

## 4. Hotfix / データパッチ

### 4-1. 通常承認フロー

#### 何が起きるか

1. 運用者が SQL を指定して workflow を起動する
2. `dbward execute "<SQL>" --environment production` で request を作成する
3. DBA が承認する
4. 別 workflow または再実行 workflow で `dbward request resume <id>` を実行する
5. 結果を確認する

#### dbwardの役割

- SQL request 作成
- 承認
- 実行
- 結果保存
- 監査ログ

#### CIの役割

- SQL と ticket を受け取る
- request id を提示する
- 承認後実行をトリガーする

#### request 作成workflow例

```yaml
name: prod-data-patch-request

on:
  workflow_dispatch:
    inputs:
      sql:
        description: "SQL to execute"
        required: true
        type: string
      reason:
        description: "Why this patch is needed"
        required: true
        type: string

jobs:
  create_patch_request:
    runs-on: ubuntu-latest
    env:
      DBWARD_SERVER_URL: ${{ secrets.DBWARD_SERVER_URL }}
      DBWARD_SERVER_TOKEN: ${{ secrets.DBWARD_HOTFIX_TOKEN }}
      IDEMPOTENCY_KEY: ${{ github.repository }}:${{ github.run_id }}:data-patch
    steps:
      - uses: actions/checkout@v4

      - name: Install dbward
        run: cargo install --path crates/dbward-cli --force

      - name: Create request
        id: create
        shell: bash
        run: |
          set -euo pipefail

          output="$(
            dbward execute "${{ inputs.sql }}" \
              --environment production \
              --reason "${{ inputs.reason }}" \
              --repo "${{ github.repository }}" \
              --ticket "${{ github.run_id }}" \
              --idempotency-key "$IDEMPOTENCY_KEY" \
              2>&1
          )"

          echo "$output"

          request_id="$(printf '%s\n' "$output" | sed -n 's/.*Request \([^ ]*\) requires approval\..*/\1/p' | tail -n1)"

          if [ -z "$request_id" ]; then
            echo "failed to extract request id"
            exit 1
          fi

          echo "request_id=$request_id" >> "$GITHUB_OUTPUT"
```

#### 承認後実行workflow例

```yaml
name: prod-data-patch-execute

on:
  workflow_dispatch:
    inputs:
      request_id:
        description: "Approved dbward request id"
        required: true
        type: string

jobs:
  execute_patch:
    runs-on: ubuntu-latest
    environment: production
    env:
      DBWARD_SERVER_URL: ${{ secrets.DBWARD_SERVER_URL }}
      DBWARD_SERVER_TOKEN: ${{ secrets.DBWARD_HOTFIX_TOKEN }}
    steps:
      - uses: actions/checkout@v4

      - name: Install dbward
        run: cargo install --path crates/dbward-cli --force

      - name: Execute approved request
        run: dbward request resume "${{ inputs.request_id }}"
```

### 4-2. break-glass フロー

#### 何が起きるか

1. 障害対応者が workflow を起動する
2. `dbward execute ... --emergency --reason ...` で即実行する
3. 実行結果を確認する
4. 事後レビューを行う

#### dbwardの役割

- 緊急実行
- break-glass イベント記録
- 監査ログ

#### CIの役割

- 実行理由の入力を強制する
- 実行者の記録を補助する
- 必要なら GitHub Environment で追加ゲートをかける

#### GitHub Actions例

```yaml
name: prod-break-glass

on:
  workflow_dispatch:
    inputs:
      sql:
        description: "Emergency SQL"
        required: true
        type: string
      reason:
        description: "Incident reason"
        required: true
        type: string

jobs:
  break_glass:
    runs-on: ubuntu-latest
    environment: break-glass
    env:
      DBWARD_SERVER_URL: ${{ secrets.DBWARD_SERVER_URL }}
      DBWARD_SERVER_TOKEN: ${{ secrets.DBWARD_HOTFIX_TOKEN }}
    steps:
      - uses: actions/checkout@v4

      - name: Install dbward
        run: cargo install --path crates/dbward-cli --force

      - name: Execute emergency SQL
        run: |
          dbward execute "${{ inputs.sql }}" \
            --environment production \
            --emergency \
            --reason "${{ inputs.reason }}"
```

## 5. ロールバック

### 何が起きるか

1. 運用者が rollback workflow を起動する
2. `dbward migrate down --environment production --count N` の request を作成する
3. DBA が承認する
4. 別 workflow で request を dispatch する
5. 必要ならアプリ側 rollback も別途行う

### dbwardの役割

- rollback request 作成
- 承認
- rollback 実行
- 結果取得

### CIの役割

- rollback 対象 revision / count の明示
- request id の提示
- 承認後の実行
- アプリ rollback との順序制御

### 注意点

- `migrate down` は「安全な rollback が定義されている migration」に限定する
- 本番障害時でも自動 `down` はしない
- rollback 後にアプリも旧 schema と整合する必要がある

### request 作成workflow例

```yaml
name: prod-rollback-request

on:
  workflow_dispatch:
    inputs:
      ref:
        description: "Git ref to roll back to"
        required: true
        type: string
      count:
        description: "How many migrations to roll back"
        required: true
        type: number

jobs:
  create_rollback_request:
    runs-on: ubuntu-latest
    env:
      DBWARD_SERVER_URL: ${{ secrets.DBWARD_SERVER_URL }}
      DBWARD_SERVER_TOKEN: ${{ secrets.DBWARD_PROD_REQUEST_TOKEN }}
      IDEMPOTENCY_KEY: ${{ github.repository }}:${{ inputs.ref }}:rollback:${{ inputs.count }}
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ inputs.ref }}

      - name: Install dbward
        run: cargo install --path crates/dbward-cli --force

      - name: Create rollback request
        shell: bash
        run: |
          set -euo pipefail

          output="$(
            dbward migrate down \
              --environment production \
              --count "${{ inputs.count }}" \
              --repo "${{ github.repository }}" \
              --ticket "rollback-${{ github.run_id }}" \
              --idempotency-key "$IDEMPOTENCY_KEY" \
              2>&1
          )"

          echo "$output"

          request_id="$(printf '%s\n' "$output" | sed -n 's/.*Request \([^ ]*\) requires approval\..*/\1/p' | tail -n1)"

          if [ -z "$request_id" ]; then
            echo "failed to extract request id"
            exit 1
          fi

          echo "request_id=$request_id" >> "$GITHUB_OUTPUT"

          {
            echo "## Production rollback request created"
            echo
            echo "- Ref: \`${{ inputs.ref }}\`"
            echo "- Count: \`${{ inputs.count }}\`"
            echo "- Request ID: \`$request_id\`"
          } >> "$GITHUB_STEP_SUMMARY"
```

### 実行workflow例

```yaml
name: prod-rollback-execute

on:
  workflow_dispatch:
    inputs:
      request_id:
        description: "Approved rollback request id"
        required: true
        type: string

jobs:
  rollback_db:
    runs-on: ubuntu-latest
    environment: production
    env:
      DBWARD_SERVER_URL: ${{ secrets.DBWARD_SERVER_URL }}
      DBWARD_SERVER_TOKEN: ${{ secrets.DBWARD_PROD_EXECUTE_TOKEN }}
    steps:
      - uses: actions/checkout@v4

      - name: Install dbward
        run: cargo install --path crates/dbward-cli --force

      - name: Execute rollback
        run: dbward request resume "${{ inputs.request_id }}"
```

## 承認待ちをどう扱うか

### 推奨

- `staging`: 承認待ちなし
- `production` / `rollback` / 通常 hotfix: request 作成 workflow を終了させる
- 承認後は別 workflow を手動起動する

### 非推奨

- CI job が数時間 polling し続ける
- 承認待ちのためだけに runner を専有する
- GitHub Actions の approval だけで DB 変更承認を代替する

## deploy と migration の順序

### 推奨順序

1. migration
2. app deploy
3. verify

この順序を採る条件:

- migration が後方互換
- 新旧アプリのどちらでも一定期間共存できる schema である

### 例外

deploy first が必要なケースは、`dbward` の問題ではなくアプリ設計の問題として扱う。  
その場合は migration を分割し、先にアプリを対応させる段階を作る。

## 失敗時のロールバック方針

### migration 失敗

- その場で pipeline を止める
- app deploy はしない
- 原因調査後に再実行する

### app deploy 失敗

- DB はそのまま残す
- まずアプリ rollback を検討する
- DB rollback が必要なら別途 `migrate down` request を起こす

### verify 失敗

- 原因が app か DB かを切り分ける
- DB rollback は自動化しない

## 監査と可観測性

最低限残すべきもの:

- GitHub Actions run URL
- git SHA
- ticket / incident ID
- `dbward` request id
- 実行者
- 承認者

推奨:

- `--ticket` に change request / incident ID を入れる
- `--repo` に `${{ github.repository }}` を入れる
- request id を `GITHUB_STEP_SUMMARY` に必ず出す

## 推奨運用まとめ

- 開発者はローカルで `migrate up/down` を確認してから PR を出す
- staging は auto-approve で migration first
- production は request 作成と実行を分離する
- DBA 承認は `dbward` 側で行い、CI は承認待ちで止めない
- app deploy 失敗時に DB rollback を自動化しない
- hotfix は通常承認経路を基本にし、break-glass は例外運用に限定する
