#!/bin/bash
# Git リポジトリの全履歴から機密情報・個人情報を検出する監査スクリプト
# 対象: dbward OSS リポジトリ公開前チェック

set -euo pipefail

cd "$(dirname "$0")/../.."

SIZE_THRESHOLD_BYTES="${SIZE_THRESHOLD_BYTES:-1048576}"
TOP_BLOB_LIMIT="${TOP_BLOB_LIMIT:-50}"

# 履歴差分全体を毎回生成すると重いため、一時ファイルに 1 回だけ退避して再利用する。
PATCH_DUMP_FILE=""
cleanup() {
  if [ -n "${PATCH_DUMP_FILE:-}" ] && [ -f "$PATCH_DUMP_FILE" ]; then
    rm -f "$PATCH_DUMP_FILE"
  fi
}
trap cleanup EXIT

print_header() {
  echo ""
  echo "============================================================"
  echo "$1"
  echo "============================================================"
}

require_commands() {
  local missing=0
  local cmd
  for cmd in git grep sort uniq awk sed mktemp; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      echo "ERROR: required command not found: $cmd" >&2
      missing=1
    fi
  done
  if [ "$missing" -ne 0 ]; then
    exit 1
  fi
}

ensure_git_repo() {
  git rev-parse --is-inside-work-tree >/dev/null 2>&1 || {
    echo "ERROR: current directory is not a git repository" >&2
    exit 1
  }
}

prepare_patch_dump() {
  if [ -n "${PATCH_DUMP_FILE:-}" ] && [ -f "$PATCH_DUMP_FILE" ]; then
    return
  fi

  PATCH_DUMP_FILE="$(mktemp)"
  git --no-pager log \
    --all \
    -p \
    --full-history \
    --date=iso-strict \
    --format='commit=%H%nAuthor=%an <%ae>%nDate=%ad%nSubject=%s' >"$PATCH_DUMP_FILE"
}

run_history_regex_check() {
  local label="$1"
  local regex="$2"

  print_header "履歴差分チェック: $label"
  echo "# 正規表現: $regex"
  prepare_patch_dump

  if grep -nE -i --color=never "$regex" "$PATCH_DUMP_FILE"; then
    :
  else
    echo "No matches"
  fi
}

check_secret_patterns() {
  print_header "1. 機密情報パターン検出"

  run_history_regex_check "AWS Access Key ID" 'AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}'
  run_history_regex_check "AWS Secret Access Key 風文字列" 'aws(.{0,20})?(secret|access).{0,20}[=:].{0,10}[A-Za-z0-9/+=]{40}'
  run_history_regex_check "GitHub Token" 'gh[pousr]_[A-Za-z0-9_]{20,255}|github_pat_[A-Za-z0-9_]{20,255}'
  run_history_regex_check "GitLab / Slack / Discord / Stripe / SendGrid 等のトークン" 'glpat-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z\-_]{35}|SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}|sk_(live|test)_[0-9A-Za-z]{16,}|rk_(live|test)_[0-9A-Za-z]{16,}|discord(.{0,20})?[=:].{0,10}[A-Za-z0-9._-]{20,}'
  run_history_regex_check "JWT / Bearer / 汎用 API Token" 'Bearer[[:space:]]+[A-Za-z0-9._=-]{20,}|eyJ[A-Za-z0-9._-]{20,}|(api[_-]?key|access[_-]?token|refresh[_-]?token|secret[_-]?token|auth[_-]?token)[[:space:]]*[:=][[:space:]]*["'"'"']?[A-Za-z0-9._/\-+=]{12,}'
  run_history_regex_check "パスワード・シークレット代入" '(password|passwd|pwd|secret|client_secret|app_secret|private_key)[[:space:]]*[:=][[:space:]]*["'"'"']?[^"'"'"'[:space:]]{6,}'
  run_history_regex_check "秘密鍵・証明書ヘッダ" '-----BEGIN (RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED |PRIVATE|CERTIFICATE)'
  run_history_regex_check ".env 形式の値" '(^|[+/ -])(export[[:space:]]+)?(APP|DB|DATABASE|POSTGRES|MYSQL|PG|REDIS|AWS|GCP|AZURE|OPENAI|ANTHROPIC|SLACK|GITHUB|STRIPE)_[A-Z0-9_]+[[:space:]]*=[[:space:]]*[^[:space:]#]{4,}'
  run_history_regex_check "DB 接続文字列" '(postgres(ql)?|mysql|mariadb|mongodb(\+srv)?|redis|amqp|kafka|sqlserver|oracle|sqlite):\/\/[^[:space:]'"'"']+'
  run_history_regex_check "接続情報入り DSN / JDBC" '(jdbc:[^[:space:]'"'"']+|(dsn|database_url|db_url|connection_string)[[:space:]]*[:=][[:space:]]*["'"'"']?[^"'"'"'[:space:]]+)'
}

check_sensitive_file_patterns() {
  local file_regex
  file_regex='(^|/)(\.env(\.[^/]+)?|\.envrc|\.npmrc|\.pypirc|\.netrc|\.terraform\.tfstate(\..*)?|terraform\.tfvars(\.json)?|docker-compose\..*\.env|secrets?(\..*)?|credentials?(\..*)?|id_rsa(\.pub)?|id_dsa(\.pub)?|id_ecdsa(\.pub)?|id_ed25519(\.pub)?|authorized_keys|known_hosts|.*\.(pem|key|p12|pfx|jks|kdb|pkcs12|asc|gpg|kubeconfig|ovpn))$'

  print_header "2. 機密ファイル名パターン検出"
  echo "# 正規表現: $file_regex"

  echo ""
  echo "# 現在のワークツリー"
  if git ls-files | grep -nE --color=never "$file_regex"; then
    :
  else
    echo "No matches"
  fi

  echo ""
  echo "# 履歴上に登場した全パス"
  if git log --all --name-only --pretty=format: | sed '/^$/d' | sort -u | grep -nE --color=never "$file_regex"; then
    :
  else
    echo "No matches"
  fi
}

check_history_commands_reference() {
  print_header "3. 全履歴を検索するコマンド例"
  cat <<'EOF'
# 任意のパターンを全履歴差分から検索する基本形
git --no-pager log --all -p --full-history \
  --format='commit=%H%nAuthor=%an <%ae>%nDate=%ad%nSubject=%s' \
  | grep -nE -i 'YOUR_REGEX'

# 例: 秘密鍵ヘッダ
git --no-pager log --all -p --full-history \
  --format='commit=%H%nAuthor=%an <%ae>%nDate=%ad%nSubject=%s' \
  | grep -nE 'BEGIN (RSA |EC |OPENSSH |PRIVATE)'

# 例: DB 接続文字列
git --no-pager log --all -p --full-history \
  --format='commit=%H%nAuthor=%an <%ae>%nDate=%ad%nSubject=%s' \
  | grep -nE -i '(postgres|mysql|mongodb|redis):\/\/'
EOF
}

check_large_binary_files() {
  print_header "4. 大きなバイナリ / 大きな blob の検出"
  echo "# しきい値: ${SIZE_THRESHOLD_BYTES} bytes"

  git rev-list --objects --all \
    | git cat-file --batch-check='%(objecttype) %(objectname) %(objectsize) %(rest)' \
    | awk -v threshold="$SIZE_THRESHOLD_BYTES" '
        $1 == "blob" && $3 >= threshold {
          printf "%12d  %s  %s\n", $3, $2, substr($0, index($0, $4))
        }
      ' \
    | sort -nr \
    | sed -n "1,${TOP_BLOB_LIMIT}p"

  echo ""
  echo "# 補助: バイナリ拡張子らしきファイル名"
  git log --all --name-only --pretty=format: \
    | sed '/^$/d' \
    | sort -u \
    | grep -nE --color=never '\.(7z|bin|class|crt|cer|der|dll|dylib|exe|gif|gz|ico|jar|jpeg|jpg|mov|mp3|mp4|o|pdf|png|so|tar|tgz|war|webp|zip)$' || true
}

check_pii_patterns() {
  print_header "5. メールアドレス・個人情報の検出"

  run_history_regex_check "メールアドレス" '[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}'
  run_history_regex_check "電話番号らしき値" '(\+?[0-9]{1,3}[-.[:space:]]?)?(\(?[0-9]{2,4}\)?[-.[:space:]]?){2,4}[0-9]{3,4}'
  run_history_regex_check "IP アドレス" '\b(([0-9]{1,3}\.){3}[0-9]{1,3})\b'
  run_history_regex_check "個人名を含みがちなキー" '(name|full_name|first_name|last_name|real_name|display_name)[[:space:]]*[:=][[:space:]]*["'"'"'][^"'"'"']{2,}["'"'"']'
  run_history_regex_check "住所・郵便番号らしきキー" '(address|street|city|state|postal|zip|zipcode|country)[[:space:]]*[:=][[:space:]]*["'"'"']?[^"'"'"'\n]{3,}'
}

run_all_checks() {
  check_secret_patterns
  check_sensitive_file_patterns
  check_history_commands_reference
  check_large_binary_files
  check_pii_patterns
}

usage() {
  cat <<'EOF'
Usage:
  ./dev/scripts/check-git-secrets-history.sh [all|secrets|files|commands|binaries|pii]

Examples:
  ./dev/scripts/check-git-secrets-history.sh
  ./dev/scripts/check-git-secrets-history.sh all
  ./dev/scripts/check-git-secrets-history.sh secrets
EOF
}

main() {
  require_commands
  ensure_git_repo

  case "${1:-all}" in
    all)
      run_all_checks
      ;;
    secrets)
      check_secret_patterns
      ;;
    files)
      check_sensitive_file_patterns
      ;;
    commands)
      check_history_commands_reference
      ;;
    binaries)
      check_large_binary_files
      ;;
    pii)
      check_pii_patterns
      ;;
    -h|--help|help)
      usage
      ;;
    *)
      echo "ERROR: unknown check: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
}

main "$@"
