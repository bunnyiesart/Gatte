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

# shellcheck source=deploy/lib/remote.sh
. "$(dirname "$0")/lib/remote.sh"

STAGE=/tmp/gateway-vnet-stage

cd "$(dirname "$0")/.."

echo "==> staging the rollback script into $(remote_target)"
remote_sh mkdir -p "$STAGE"
remote_cp deploy/vm/gateway-vnet-rollback.sh "$STAGE/gateway-vnet-rollback.sh"
remote_sh chmod 0755 "$STAGE/gateway-vnet-rollback.sh"

remote_sh "$STAGE/gateway-vnet-rollback.sh"

echo
echo "==> rolled back. VPN clients should reconnect: 10.17.90.0/24 is no"
echo "    longer pushed, and the gateway is back at 10.17.89.10."
