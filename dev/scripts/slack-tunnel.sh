#!/bin/bash
# Start dbward dev environment + cloudflared tunnel for Slack testing
#
# Usage:
#   export SLACK_BOT_TOKEN="xoxb-..."
#   export SLACK_SIGNING_SECRET="..."
#   ./dev/scripts/slack-tunnel.sh
#
# This will:
#   1. Start Docker Compose (server + agent + postgres)
#   2. Start cloudflared tunnel on port 3000
#   3. Print the public URL to configure in Slack App

set -euo pipefail
cd "$(dirname "$0")/../.."

# Validate env vars
if [ -z "${SLACK_BOT_TOKEN:-}" ] || [ -z "${SLACK_SIGNING_SECRET:-}" ]; then
    echo "ERROR: Set SLACK_BOT_TOKEN and SLACK_SIGNING_SECRET environment variables"
    echo ""
    echo "  export SLACK_BOT_TOKEN='xoxb-...'"
    echo "  export SLACK_SIGNING_SECRET='...'"
    echo ""
    exit 1
fi

echo "=== Starting Docker Compose ==="
docker compose -f dev/compose.yml up -d --build

echo ""
echo "=== Waiting for server to be ready ==="
for i in $(seq 1 30); do
    if curl -sf http://localhost:3000/health > /dev/null 2>&1; then
        echo "Server ready!"
        break
    fi
    sleep 1
done

echo ""
echo "=== Starting cloudflared tunnel ==="
echo "Press Ctrl+C to stop"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "After tunnel starts, configure in Slack App:"
echo ""
echo "  Slash Commands → /dbward"
echo "    Request URL: <TUNNEL_URL>/api/slack/commands"
echo ""
echo "  Interactivity & Shortcuts → Request URL:"
echo "    <TUNNEL_URL>/api/slack/interactions"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

cloudflared tunnel --url http://localhost:3000
