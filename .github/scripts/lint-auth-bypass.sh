#!/bin/bash
set -euo pipefail

# Detect Permission:: direct usage in route handlers (bypassing Authorizer).
# Multi-line authorize calls are allowed (Permission:: as argument to authorize_*).
# Allowed patterns: authorize calls, use statements, tests, comments, struct field init.

FOUND=0
while IFS=: read -r file line content; do
  # Check if any of the surrounding 3 lines contain "authorize"
  CONTEXT=$(sed -n "$((line > 2 ? line - 2 : 1)),$((line + 2))p" "$file")
  if echo "$CONTEXT" | grep -q "authorize"; then
    continue
  fi
  echo "$file:$line:$content"
  FOUND=1
done < <(grep -rn "Permission::" crates/dbward-server/src/routes/ | \
  grep -v "use \|test\|//\|permission:\|permissions:" || true)

if [ "$FOUND" -eq 1 ]; then
  echo ""
  echo "ERROR: Direct Permission:: usage in route handlers without Authorizer context."
  exit 1
fi

echo "OK: No unauthorized Permission references in handlers."
