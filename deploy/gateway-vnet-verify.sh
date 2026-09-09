#!/usr/bin/env sh
# Runs the acceptance test for the VNET conversion of `mcp-gateway-test`:
# that a listener on 127.0.0.1 inside the jail stays on 127.0.0.1 and is
# unreachable from the VM host and from the other jail.
#
#     ./deploy/gateway-vnet-verify.sh
#
# Non-zero exit means a check failed. Read-only: it starts and reaps two
# throwaway `nc` listeners in the jail and changes nothing else.
#
# See deploy/gateway-vnet.md, "The acceptance test".
set -eu

JM_STATE_ROOT="${JM_STATE_ROOT:-$HOME/.jailmachine}"
JM_SSH_KEY="$JM_STATE_ROOT/machines/jailmachine/ssh/id_ed25519"
JM_SSH_PORT="${JM_SSH_PORT:-2222}"
STAGE=/tmp/gateway-vnet-stage

cd "$(dirname "$0")/.."

echo "==> staging the verifier into the VM"
jm ssh -- mkdir -p "$STAGE"
scp -q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no \
	-i "$JM_SSH_KEY" -P "$JM_SSH_PORT" deploy/vm/gateway-vnet-verify.sh "root@127.0.0.1:$STAGE/gateway-vnet-verify.sh"
jm ssh -- chmod 0755 "$STAGE/gateway-vnet-verify.sh"

jm ssh -- "$STAGE/gateway-vnet-verify.sh"
