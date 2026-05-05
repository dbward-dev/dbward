# Dev環境での手動テスト

## 起動

```bash
docker compose --profile oidc up -d --build

# 起動待ち
until curl -sf http://localhost:8080/realms/dbward > /dev/null 2>&1; do sleep 2; done
until curl -sf http://localhost:13000/health > /dev/null 2>&1; do sleep 1; done
echo "Ready"
```

## ログイン & テスト

```bash
# aliceとしてログイン
dbward --config dev/dbward-cli-alice.toml login --device
# → ブラウザで http://localhost:8080/... を開いて alice / alice

# 確認
dbward --config dev/dbward-cli-alice.toml whoami

# エイリアス推奨
alias alice='dbward --config dev/dbward-cli-alice.toml'
alias bob='dbward --config dev/dbward-cli-bob.toml'

# bobでログイン（別セッション）
bob login --device  # bob / bob

# テスト
alice execute "SELECT 1"
alice execute "SELECT 1" --share-with "group:backend-team"
alice results
bob execute "SELECT version()" --environment production
alice list   # bobのpending requestが見える
alice approve <id>
bob resume <id>
alice cancel <id> --reason "test"
```

## ユーザー

| User | Password | Role | Groups |
|------|----------|------|--------|
| alice | alice | developer | dbward-developers, backend-team |
| bob | bob | admin | dbward-admins |
| carol | carol | readonly | dba-team |

## 停止

```bash
docker compose --profile oidc down -v
```
