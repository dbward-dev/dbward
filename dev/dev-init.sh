#!/bin/sh
set -e

echo "[dev-init] Creating API tokens..."

# alice = developer
ALICE_OUTPUT=$(dbward server token create --user alice --role developer --data /data/dbward.db 2>&1)
ALICE_TOKEN=$(echo "$ALICE_OUTPUT" | grep "Token:" | awk '{print $2}')
echo "$ALICE_TOKEN" > /tokens/alice.token
echo "[dev-init] alice (developer): $ALICE_TOKEN"

# bob = admin
BOB_OUTPUT=$(dbward server token create --user bob --role admin --data /data/dbward.db 2>&1)
BOB_TOKEN=$(echo "$BOB_OUTPUT" | grep "Token:" | awk '{print $2}')
echo "$BOB_TOKEN" > /tokens/bob.token
echo "[dev-init] bob (admin): $BOB_TOKEN"

echo "[dev-init] Done. Tokens saved to /tokens/"
