#!/bin/bash
# E2E VAL-1: Validate Subcommand Tests
# Tests `dbward-server validate` and `dbward-agent validate` commands
# Requires: binaries built (cargo build --workspace)
# Usage: ./dev/e2e/validate.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/../.."

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'
PASS=0
FAIL=0

pass() { echo -e "${GREEN}✅ PASS${NC}: $1"; PASS=$((PASS+1)); }
fail() { echo -e "${RED}❌ FAIL${NC}: $1 — $2"; FAIL=$((FAIL+1)); }
skip() { echo -e "${YELLOW}⏭ SKIP${NC}: $1"; }

# Paths
SERVER_BIN="./target/debug/dbward-server"
AGENT_BIN="./target/debug/dbward-agent"
TMP_DIR=$(mktemp -d)
trap "rm -rf $TMP_DIR" EXIT

# Ensure binaries exist
if [ ! -f "$SERVER_BIN" ] || [ ! -f "$AGENT_BIN" ]; then
  echo "Building binaries..."
  cargo build --workspace --quiet
fi

echo ""
echo "=== E2E VAL-1: Validate Subcommand Tests ==="
echo ""

# ============================================================
# Server validate tests
# ============================================================

echo "--- Server Validate Tests ---"
echo ""

# VAL-S1: Valid server config
echo "--- VAL-S1: Valid server config ---"
cat > "$TMP_DIR/server-valid.toml" << 'EOF'
state_dir = "/tmp/dbward-test"

[[databases]]
name = "app"
environments = ["dev", "prod"]

[[workflows]]
database = "*"
environment = "*"

[workflows.auto_approve]
mode = "always"
EOF

OUTPUT=$("$SERVER_BIN" validate --config "$TMP_DIR/server-valid.toml" 2>&1) || true
if echo "$OUTPUT" | grep -q "Config valid"; then
  pass "Valid server config passes validation"
else
  fail "Valid server config" "output: $OUTPUT"
fi

# VAL-S2: Invalid server config (missing workflow)
echo "--- VAL-S2: Invalid config (no workflows) ---"
cat > "$TMP_DIR/server-no-workflow.toml" << 'EOF'
state_dir = "/tmp/dbward-test"

[[databases]]
name = "app"
environments = ["dev"]
EOF

OUTPUT=$("$SERVER_BIN" validate --config "$TMP_DIR/server-no-workflow.toml" 2>&1) || true
if echo "$OUTPUT" | grep -q "workflow_refs" || echo "$OUTPUT" | grep -q "no workflows"; then
  pass "Missing workflows detected as error"
else
  fail "Missing workflows" "output: $OUTPUT"
fi

# VAL-S3: Parse error (invalid TOML)
echo "--- VAL-S3: Parse error ---"
cat > "$TMP_DIR/server-invalid.toml" << 'EOF'
state_dir = "/tmp/dbward-test"
[invalid syntax
EOF

OUTPUT=$("$SERVER_BIN" validate --config "$TMP_DIR/server-invalid.toml" 2>&1) || true
if echo "$OUTPUT" | grep -qi "error\|parse\|invalid"; then
  pass "Parse error detected"
else
  fail "Parse error" "output: $OUTPUT"
fi

# VAL-S4: Warning (workflow coverage gap)
echo "--- VAL-S4: Warning (workflow coverage gap) ---"
cat > "$TMP_DIR/server-coverage-gap.toml" << 'EOF'
state_dir = "/tmp/dbward-test"

[[databases]]
name = "app"
environments = ["dev", "prod"]

[[workflows]]
database = "app"
environment = "dev"

[workflows.auto_approve]
mode = "always"
EOF

OUTPUT=$("$SERVER_BIN" validate --config "$TMP_DIR/server-coverage-gap.toml" 2>&1) || true
if echo "$OUTPUT" | grep -qi "warn\|coverage"; then
  pass "Workflow coverage gap detected as warning"
else
  fail "Coverage gap warning" "output: $OUTPUT"
fi

# VAL-S5: SQL review safety warning
echo "--- VAL-S5: Warning (sql_review_safety) ---"
cat > "$TMP_DIR/server-sql-review.toml" << 'EOF'
state_dir = "/tmp/dbward-test"

[[databases]]
name = "app"
environments = ["production"]

[[workflows]]
database = "*"
environment = "*"

[workflows.auto_approve]
mode = "always"

[[sql_review]]
environment = "production"
drop_table = "off"
truncate = "off"
EOF

OUTPUT=$("$SERVER_BIN" validate --config "$TMP_DIR/server-sql-review.toml" 2>&1) || true
if echo "$OUTPUT" | grep -qi "warn\|sql_review_safety\|dangerous"; then
  pass "SQL review safety warning detected"
else
  fail "SQL review safety" "output: $OUTPUT"
fi

# ============================================================
# Agent validate tests
# ============================================================

echo ""
echo "--- Agent Validate Tests ---"
echo ""

# VAL-A1: Valid agent config
echo "--- VAL-A1: Valid agent config ---"
cat > "$TMP_DIR/agent-valid.toml" << 'EOF'
[server]
url = "http://localhost:13000"
agent_token = "test-token"

[databases.app.dev]
url = "postgres://localhost/app"
EOF

OUTPUT=$("$AGENT_BIN" validate --config "$TMP_DIR/agent-valid.toml" 2>&1) || true
if echo "$OUTPUT" | grep -q "Config valid"; then
  pass "Valid agent config passes validation"
else
  fail "Valid agent config" "output: $OUTPUT"
fi

# VAL-A2: Invalid server URL scheme
echo "--- VAL-A2: Invalid server URL scheme ---"
cat > "$TMP_DIR/agent-bad-url.toml" << 'EOF'
[server]
url = "localhost:13000"
agent_token = "test-token"

[databases.app.dev]
url = "postgres://localhost/app"
EOF

OUTPUT=$("$AGENT_BIN" validate --config "$TMP_DIR/agent-bad-url.toml" 2>&1) || true
if echo "$OUTPUT" | grep -qi "error\|server_url_scheme\|http"; then
  pass "Invalid server URL scheme detected"
else
  fail "Server URL scheme" "output: $OUTPUT"
fi

# VAL-A3: Invalid database URL scheme
echo "--- VAL-A3: Invalid database URL scheme ---"
cat > "$TMP_DIR/agent-bad-db.toml" << 'EOF'
[server]
url = "http://localhost:13000"
agent_token = "test-token"

[databases.app.dev]
url = "invalid://localhost/app"
EOF

OUTPUT=$("$AGENT_BIN" validate --config "$TMP_DIR/agent-bad-db.toml" 2>&1) || true
if echo "$OUTPUT" | grep -qi "error\|db_url_scheme\|unsupported"; then
  pass "Invalid database URL scheme detected"
else
  fail "Database URL scheme" "output: $OUTPUT"
fi

# VAL-A4: Empty databases
echo "--- VAL-A4: Empty databases ---"
cat > "$TMP_DIR/agent-no-db.toml" << 'EOF'
[server]
url = "http://localhost:13000"
agent_token = "test-token"

[databases]
EOF

OUTPUT=$("$AGENT_BIN" validate --config "$TMP_DIR/agent-no-db.toml" 2>&1) || true
if echo "$OUTPUT" | grep -qi "error\|databases"; then
  pass "Empty databases detected as error"
else
  fail "Empty databases" "output: $OUTPUT"
fi

# ============================================================
# Exit code tests
# ============================================================

echo ""
echo "--- Exit Code Tests ---"
echo ""

# VAL-E1: Exit 0 on valid config
echo "--- VAL-E1: Exit 0 on valid ---"
if "$SERVER_BIN" validate --config "$TMP_DIR/server-valid.toml" > /dev/null 2>&1; then
  pass "Exit 0 on valid config"
else
  fail "Exit code" "expected 0, got $?"
fi

# VAL-E2: Exit 1 on invalid config
echo "--- VAL-E2: Exit 1 on invalid ---"
if "$SERVER_BIN" validate --config "$TMP_DIR/server-no-workflow.toml" > /dev/null 2>&1; then
  fail "Exit code" "expected non-zero, got 0"
else
  pass "Exit 1 on invalid config"
fi

# ============================================================
# Summary
# ============================================================

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ $FAIL -gt 0 ]; then
  exit 1
fi
