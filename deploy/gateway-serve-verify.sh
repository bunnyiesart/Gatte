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

# The confirmation prompt lives on the far side, where there is no terminal:
# over SSH `read` gets EOF and the remote script aborts, which is the safe
# default but makes this wrapper unusable. So the wrapper is where the
# operator confirms, once, before anything is staged or stopped.
#
# GATEWAY_VERIFY_YES=1 in the environment skips it, for CI.
if [ "${GATEWAY_VERIFY_YES:-}" != "1" ]; then
	echo
	echo "!! gateway-serve-verify DESTROYS the audit trail and every tool"
	echo "   approval on jail '$GW_JAIL' at $(remote_target). It rebuilds the"
	echo "   database from scratch, because the quarantine assertions cannot"
	echo "   mean anything against yesterday's approvals. There is no backup."
	echo
	printf "   Continue? [y/N] "
	read -r reply
	case "$reply" in
		y|Y|yes|YES) ;;
		*) echo "   Aborted. Nothing was changed."; exit 1 ;;
	esac
fi

remote_sh "GW_JAIL=$GW_JAIL STAGE=$STAGE GATEWAY_VERIFY_YES=1 sh $STAGE/gateway-serve-verify.sh"
