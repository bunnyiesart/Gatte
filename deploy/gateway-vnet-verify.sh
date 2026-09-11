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

# shellcheck source=deploy/lib/remote.sh
. "$(dirname "$0")/lib/remote.sh"

STAGE=/tmp/gateway-vnet-stage

cd "$(dirname "$0")/.."

echo "==> staging the verifier into $(remote_target)"
remote_sh mkdir -p "$STAGE"
remote_cp deploy/vm/gateway-vnet-verify.sh "$STAGE/gateway-vnet-verify.sh"
remote_sh chmod 0755 "$STAGE/gateway-vnet-verify.sh"

remote_sh "$STAGE/gateway-vnet-verify.sh"
