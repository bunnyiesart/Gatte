#!/usr/bin/env sh
# Runs on the MAC. Stages the acceptance test into the jailmachine VM and
# runs it there.
#
# It is a thin driver on purpose: everything it asserts happens on the VM,
# in deploy/vm/gateway-serve-verify.sh, because the client has to be
# somewhere that can reach 10.17.90.10 and the Mac (without the VPN up)
# cannot.
#
# Run ./deploy/gateway-serve.sh first. This one restarts the service, so it
# is safe to re-run, and it is meant to be re-run: it is the acceptance
# test, not a one-off.
set -eu

# shellcheck source=deploy/lib/remote.sh
. "$(dirname "$0")/lib/remote.sh"

GW_JAIL="${GW_JAIL:-mcp-gateway-test}"
STAGE=/tmp/mcp-gateway-deploy

cd "$(dirname "$0")/.."

remote_sh "mkdir -p $STAGE"
remote_cp deploy/vm/gateway-serve-verify.sh deploy/vm/gateway-token.sh \
	deploy/vm/gateway-upstreams.sh \
	"$STAGE/"

remote_sh "GW_JAIL=$GW_JAIL STAGE=$STAGE sh $STAGE/gateway-serve-verify.sh"
