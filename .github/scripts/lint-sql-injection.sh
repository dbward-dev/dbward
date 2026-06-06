#!/bin/bash
set -euo pipefail

# Detect SQL injection patterns: format! embedding values in SQL strings
# Excludes error messages and test code
HITS=$(grep -rn "format\!.*'[{]" crates/dbward-infra/src/sqlite/ | \
  grep -v "map_err\|AppError\|error\|Error\|test\|//" || true)

if [ -n "$HITS" ]; then
  echo "ERROR: Potential SQL injection detected (format! with interpolation in SQL):"
  echo "$HITS"
  exit 1
fi

echo "OK: No SQL injection patterns found."
