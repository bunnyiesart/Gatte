#!/bin/sh
# Backs out everything deploy/openvpn-setup.sh did. Runs on the Mac.
#
#   ./deploy/openvpn-teardown.sh          # stop + disable the server, drop the
#                                         # forward, delete the local profile
#   KEEP_PKI=1 ./deploy/openvpn-teardown.sh   # leave the CA and certs in place
#
# Does NOT uninstall the openvpn / easy-rsa packages, and does NOT revert
# net.inet.ip.forwarding by default -- see the two flags below. Nothing here
# touches pf, because the setup never touched pf either.
set -eu

# shellcheck source=deploy/lib/remote.sh
. "$(dirname "$0")/lib/remote.sh"

PROFILE_DIR="${OVPN_PROFILE_DIR:-$HOME/.config/mcp-gateway-lab/openvpn}"
KEEP_PKI="${KEEP_PKI:-0}"
REVERT_FORWARDING="${REVERT_FORWARDING:-0}"
VPN_DIR=/usr/local/etc/openvpn

cd "$(dirname "$0")/.."

if [ "$JAILHOST_TRANSPORT" = jailmachine ]; then
	echo "==> removing the gvproxy forward"
	sh deploy/openvpn-forward.sh down || true
else
	echo "==> no gvproxy forward to remove (JAILHOST_TRANSPORT=$JAILHOST_TRANSPORT)"
fi

echo "==> stopping and disabling openvpn on $(remote_target)"
remote_sh service openvpn stop || true
remote_sh sysrc -x openvpn_enable openvpn_configfile || true

if [ "$KEEP_PKI" != "1" ]; then
	echo "==> deleting the VPN PKI, tls-crypt key and server config"
	remote_sh rm -rf "$VPN_DIR/pki" "$VPN_DIR/tls-crypt.key" "$VPN_DIR/openvpn.conf"
else
	echo "==> KEEP_PKI=1: leaving $VPN_DIR alone"
fi

if [ "$REVERT_FORWARDING" = "1" ]; then
	echo "==> reverting net.inet.ip.forwarding"
	# BUG, PRE-EXISTING, LEFT AS-IS ON PURPOSE: this does not edit
	# sysctl.conf. Both transports flatten their arguments into one string
	# for a remote shell (see deploy/lib/remote.sh, QUOTING), so the quotes
	# around the -c argument are gone by the time the far side parses it:
	# the remote runs `sh -c sed` -- sed with no arguments -- and then, past
	# the `;`, the sysctl. So the runtime sysctl is reverted and the
	# persistent line survives a reboot. It behaved exactly this way before
	# the transport refactor and is preserved verbatim rather than quietly
	# changed; the fix is the single-argument form:
	#   remote_sh "sed -i '' '/^net.inet.ip.forwarding=1/d' /etc/sysctl.conf; sysctl net.inet.ip.forwarding=0"
	remote_sh sh -c "sed -i '' '/^net.inet.ip.forwarding=1/d' /etc/sysctl.conf; sysctl net.inet.ip.forwarding=0"
else
	echo "==> leaving net.inet.ip.forwarding=1 (REVERT_FORWARDING=1 to undo it)"
fi

if [ -f "$PROFILE_DIR/mcp-gateway-lab.ovpn" ]; then
	echo "==> deleting $PROFILE_DIR/mcp-gateway-lab.ovpn"
	rm -f "$PROFILE_DIR/mcp-gateway-lab.ovpn"
	rmdir "$PROFILE_DIR" 2>/dev/null || true
fi

echo "==> done. Kill any running client with: sudo pkill -f 'openvpn --config'"
