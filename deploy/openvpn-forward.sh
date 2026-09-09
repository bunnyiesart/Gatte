#!/bin/sh
# Adds / removes / shows the gvproxy UDP forward that lets the Mac's
# 127.0.0.1:1194 reach the OpenVPN server inside the jailmachine VM.
#
#   ./deploy/openvpn-forward.sh up      # create it (idempotent)
#   ./deploy/openvpn-forward.sh down    # remove it
#   ./deploy/openvpn-forward.sh status  # list all forwards gvproxy holds
#
# The forward lives in the running gvproxy process, not on disk. It does NOT
# survive `jm stop` / `jm start` -- run `up` again after a VM restart.
set -eu

JM_STATE_ROOT="${JM_STATE_ROOT:-$HOME/.jailmachine}"
API_SOCK="$JM_STATE_ROOT/machines/jailmachine/api.sock"
LOCAL_ADDR="${LOCAL_ADDR:-127.0.0.1:1194}"
REMOTE_ADDR="${REMOTE_ADDR:-192.168.127.2:1194}"
BODY="{\"local\":\"$LOCAL_ADDR\",\"remote\":\"$REMOTE_ADDR\",\"protocol\":\"udp\"}"

api() {
	_method=$1; _path=$2; shift 2
	curl -sS --unix-socket "$API_SOCK" -X "$_method" "http://localhost$_path" "$@"
}

[ -S "$API_SOCK" ] || { echo "no gvproxy API socket at $API_SOCK -- is the VM running? (jm start)" >&2; exit 1; }

exists() {
	api GET /services/forwarder/all | grep -q "\"local\":\"$LOCAL_ADDR\""
}

case "${1:-}" in
up)
	if exists; then
		echo "==> forward $LOCAL_ADDR -> $REMOTE_ADDR (udp) already present"
	else
		echo "==> exposing $LOCAL_ADDR -> $REMOTE_ADDR (udp)"
		api POST /services/forwarder/expose -H 'Content-Type: application/json' -d "$BODY"
		exists || { echo "!! expose returned but the forward is not listed" >&2; exit 1; }
		echo "==> ok"
	fi
	;;
down)
	if exists; then
		echo "==> unexposing $LOCAL_ADDR (udp)"
		api POST /services/forwarder/unexpose -H 'Content-Type: application/json' \
			-d "{\"local\":\"$LOCAL_ADDR\",\"protocol\":\"udp\"}"
		if exists; then echo "!! still listed after unexpose" >&2; exit 1; fi
		echo "==> ok"
	else
		echo "==> no forward on $LOCAL_ADDR to remove"
	fi
	;;
status)
	api GET /services/forwarder/all
	echo
	;;
*)
	echo "usage: $0 up|down|status" >&2
	exit 2
	;;
esac
