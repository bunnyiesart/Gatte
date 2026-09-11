#!/usr/bin/env sh
# Converts the `mcp-gateway-test` jail from a classic jail to a VNET jail,
# giving it a network stack -- and therefore a 127.0.0.1 -- of its own.
#
#     ./deploy/gateway-vnet.sh
#
# Why this exists: design/adr/0011 requires the gateway to refuse any bind
# that is not loopback, and its CORREÇÃO block records that in a classic jail
# that refusal is worthless -- the kernel rewrites a 127.0.0.1 bind to the
# jail's routable address, so the socket is reachable across the VPN in
# cleartext with the check reporting success. VNET is option (1) of the three
# that block lists, and the only one that makes the check mean what it says.
#
# The jail moves from 10.17.89.10 to 10.17.90.10 in the process. See
# deploy/gateway-vnet.md, "Subnet", for why it is not allowed to stay.
#
# Idempotent, and safe to re-run after editing deploy/vm/gateway-vnet-*.sh.
# It never reconfigures the `authelia` jail.
#
# Undo: ./deploy/gateway-vnet-rollback.sh
set -eu

# shellcheck source=deploy/lib/remote.sh
. "$(dirname "$0")/lib/remote.sh"

STAGE=/tmp/gateway-vnet-stage

cd "$(dirname "$0")/.."

echo "==> staging the conversion scripts into $(remote_target)"
remote_sh mkdir -p "$STAGE"
for f in gateway-vnet-convert.sh gateway-vnet-rollback.sh gateway-vnet-verify.sh; do
	remote_cp "deploy/vm/$f" "$STAGE/$f"
	remote_sh chmod 0755 "$STAGE/$f"
done

echo "==> converting the jail"
remote_sh "$STAGE/gateway-vnet-convert.sh"

echo
echo "==> done. Verify with:"
echo "    ./deploy/gateway-vnet-verify.sh"
echo
echo "    VPN clients must reconnect to pick up the pushed route for"
echo "    10.17.90.0/24; the gateway is at 10.17.90.10 now."
