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

JM_STATE_ROOT="${JM_STATE_ROOT:-$HOME/.jailmachine}"
JM_SSH_KEY="$JM_STATE_ROOT/machines/jailmachine/ssh/id_ed25519"
JM_SSH_PORT="${JM_SSH_PORT:-2222}"
STAGE=/tmp/gateway-vnet-stage

cd "$(dirname "$0")/.."

vmcp() {
	scp -q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no \
		-i "$JM_SSH_KEY" -P "$JM_SSH_PORT" "$1" "root@127.0.0.1:$2"
}

echo "==> staging the conversion scripts into the VM"
jm ssh -- mkdir -p "$STAGE"
for f in gateway-vnet-convert.sh gateway-vnet-rollback.sh gateway-vnet-verify.sh; do
	vmcp "deploy/vm/$f" "$STAGE/$f"
	jm ssh -- chmod 0755 "$STAGE/$f"
done

echo "==> converting the jail"
jm ssh -- "$STAGE/gateway-vnet-convert.sh"

echo
echo "==> done. Verify with:"
echo "    ./deploy/gateway-vnet-verify.sh"
echo
echo "    VPN clients must reconnect to pick up the pushed route for"
echo "    10.17.90.0/24; the gateway is at 10.17.90.10 now."
