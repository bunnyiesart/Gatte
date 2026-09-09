#!/usr/bin/env sh
# Puts `mcp-gateway-test` back to a classic jail at 10.17.89.10.
#
#     ./deploy/gateway-vnet-rollback.sh
#
# READ deploy/gateway-vnet.md, "Rollback", first. Rolling back restores the
# defect design/adr/0011 was written to close: in a classic jail a bind to
# 127.0.0.1 becomes a bind to 10.17.89.10, reachable from the host, from the
# other jails, and across the VPN in cleartext -- while the gateway's own
# requireLoopbackBind check reports success. This is an unblock-other-work
# button, not a supported configuration.
#
# Idempotent, and a no-op on a jail that was never converted.
set -eu

JM_STATE_ROOT="${JM_STATE_ROOT:-$HOME/.jailmachine}"
JM_SSH_KEY="$JM_STATE_ROOT/machines/jailmachine/ssh/id_ed25519"
JM_SSH_PORT="${JM_SSH_PORT:-2222}"
STAGE=/tmp/gateway-vnet-stage

cd "$(dirname "$0")/.."

echo "==> staging the rollback script into the VM"
jm ssh -- mkdir -p "$STAGE"
scp -q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no \
	-i "$JM_SSH_KEY" -P "$JM_SSH_PORT" deploy/vm/gateway-vnet-rollback.sh "root@127.0.0.1:$STAGE/gateway-vnet-rollback.sh"
jm ssh -- chmod 0755 "$STAGE/gateway-vnet-rollback.sh"

jm ssh -- "$STAGE/gateway-vnet-rollback.sh"

echo
echo "==> rolled back. VPN clients should reconnect: 10.17.90.0/24 is no"
echo "    longer pushed, and the gateway is back at 10.17.89.10."
