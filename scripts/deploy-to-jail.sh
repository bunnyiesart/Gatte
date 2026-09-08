#!/usr/bin/env sh
# Cross-compiles mcp-gateway for freebsd/arm64 and installs it into the
# mcp-gateway-test bastille jail running inside the jailmachine VM.
#
# Local test/dev only -- see deploy/freebsd-jail.md for the full setup this
# assumes (jailmachine installed and started, jail already created).
set -eu

JAIL=mcp-gateway-test
JM_STATE_ROOT="${JM_STATE_ROOT:-$HOME/.jailmachine}"
JM_SSH_KEY="$JM_STATE_ROOT/machines/jailmachine/ssh/id_ed25519"
REMOTE_TMP=/tmp/mcp-gateway
JAIL_ROOT="/usr/local/bastille/jails/$JAIL/root"
DB_PATH="${MCP_GATEWAY_JAIL_DB:-/var/db/mcp-gateway.db}"

cd "$(dirname "$0")/.."

echo "==> cross-compiling for freebsd/arm64"
GOOS=freebsd GOARCH=arm64 CGO_ENABLED=0 go build -o /tmp/mcp-gateway-freebsd ./cmd/mcp-gateway

echo "==> copying into the jailmachine VM"
scp -q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no \
	-i "$JM_SSH_KEY" -P 2222 /tmp/mcp-gateway-freebsd "root@127.0.0.1:$REMOTE_TMP"

echo "==> installing into jail $JAIL"
jm ssh -- mkdir -p "$JAIL_ROOT/usr/local/bin"
jm ssh -- cp "$REMOTE_TMP" "$JAIL_ROOT/usr/local/bin/mcp-gateway"
jm ssh -- chmod +x "$JAIL_ROOT/usr/local/bin/mcp-gateway"

echo "==> smoke test: opening the store and migrating schemas inside the jail"
jm ssh -- bastille cmd "$JAIL" /usr/local/bin/mcp-gateway -db "$DB_PATH"

echo "==> done. jail IP: 10.17.89.10 -- 'jm ssh -- bastille list' to confirm"
