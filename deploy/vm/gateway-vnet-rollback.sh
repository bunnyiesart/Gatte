#!/bin/sh
# Runs INSIDE the jailmachine FreeBSD VM, as root. Not meant to be run on the
# Mac -- deploy/gateway-vnet-rollback.sh copies this in and executes it.
#
# Puts `mcp-gateway-test` back the way gateway-vnet-convert.sh found it: a
# classic (shared-stack) jail at 10.17.89.10 on the bastille0 loopback clone.
#
# READ THIS BEFORE RUNNING IT. Rolling back re-creates the exact defect that
# design/adr/0011 records: in a classic jail a bind to 127.0.0.1 is rewritten
# to 10.17.89.10 and is reachable from the host, from the other jails, and
# across the VPN in cleartext. The gateway's requireLoopbackBind check will
# pass and mean nothing. Roll back to unblock other work, not to ship.
#
# Idempotent, and safe to run on a jail that was never converted (it says so
# and exits 0). It removes only what the convert script added; it does not
# touch the `authelia` jail, the SOC CA, or the OpenVPN PKI.
set -eu

JAIL="${JAIL:-mcp-gateway-test}"
EPAIR_HOST=e0a_mcpgw
BRIDGE_CLONE=bridge10
BRIDGE=socbr0

VNET_NET=10.17.90.0
VNET_CIDR=10.17.90.0/24
VNET_MASK=255.255.255.0

CLASSIC_IP=10.17.89.10

JAILS_DIR=/usr/local/bastille/jails
JAIL_DIR="$JAILS_DIR/$JAIL"
JAIL_ROOT="$JAIL_DIR/root"
JAIL_CONF="$JAIL_DIR/jail.conf"
CLASSIC_CONF="$JAIL_DIR/jail.conf.classic"

PF_CONF=/etc/pf.conf
PF_TABLE=jails
OVPN_CONF=/usr/local/etc/openvpn/openvpn.conf

say() { echo "==> $*"; }
die() { echo "!! $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must run as root inside the VM"
[ -d "$JAIL_DIR" ] || die "no jail at $JAIL_DIR"

if ! grep -q '^[[:space:]]*vnet;' "$JAIL_CONF" 2>/dev/null; then
	say "$JAIL is not a VNET jail -- nothing to roll back"
	exit 0
fi
[ -f "$CLASSIC_CONF" ] || die "no $CLASSIC_CONF to restore -- refusing to guess the old configuration"

# ------------------------------------------------------------------- 1. stop
if jls -j "$JAIL" >/dev/null 2>&1; then
	say "stopping $JAIL"
	bastille stop "$JAIL" >/dev/null 2>&1 || jail -r "$JAIL" >/dev/null 2>&1 || true
fi
jls -j "$JAIL" >/dev/null 2>&1 && die "could not stop $JAIL"

# The jail.conf poststop hook destroys the host epair; if the jail was killed
# rather than stopped, it can survive.
if ifconfig "$EPAIR_HOST" >/dev/null 2>&1; then
	say "destroying leftover $EPAIR_HOST"
	ifconfig "$EPAIR_HOST" destroy || true
fi

# -------------------------------------------------- 2. restore the jail.conf
say "restoring the classic $JAIL_CONF"
cp -p "$CLASSIC_CONF" "$JAIL_CONF"

# ------------------------------------------- 3. undo the jail's own rc.conf
#
# Harmless if left behind -- a classic jail's /etc/rc never sees these
# interfaces -- but leaving them turns the next `sysrc -a` into a puzzle.
#
# As a plain file, not `sysrc -R -x`: sysrc -R chroots, and a stopped thin
# jail has no /bin/sh of its own (its base is a nullfs mount that only exists
# while the jail runs).
say "removing the jail's VNET rc.conf entries"
JAIL_RC="$JAIL_ROOT/etc/rc.conf"
if [ -f "$JAIL_RC" ]; then
	for _v in ifconfig_e0b_mcpgw_name ifconfig_vnet0 ifconfig_vnet0_descr defaultrouter; do
		sed -i '' -E "/^${_v}=/d" "$JAIL_RC"
	done
fi

# ------------------------------------------------------------------ 4. hosts
set_hosts_entry() {
	_file="$1"; _ip="$2"; _name="$3"
	[ -f "$_file" ] || return 0
	say "pointing $_name back at $_ip in $_file"
	sed -i '' -E "/^[[:space:]]*[0-9.]+[[:space:]]+${_name}[[:space:]]*\$/d" "$_file"
	printf '%s\t%s\n' "$_ip" "$_name" >>"$_file"
}
set_hosts_entry "$JAIL_ROOT/etc/hosts" "$CLASSIC_IP" mcp.soc.internal
set_hosts_entry /etc/hosts "$CLASSIC_IP" mcp.soc.internal

# ---------------------------------------------------------------------- 5. pf
if [ -f "$PF_CONF.pre-vnet" ]; then
	say "restoring $PF_CONF from $PF_CONF.pre-vnet"
	cp -p "$PF_CONF.pre-vnet" "$PF_CONF"
	rm -f "$PF_CONF.pre-vnet"
elif grep -q "$VNET_CIDR" "$PF_CONF"; then
	say "removing $VNET_CIDR from the <$PF_TABLE> table in $PF_CONF"
	sed -i '' -E "s|^table <${PF_TABLE}> persist \{ ${VNET_CIDR} \}\$|table <${PF_TABLE}> persist|" "$PF_CONF"
fi
pfctl -n -f "$PF_CONF" || die "$PF_CONF no longer parses"
# Same reasoning as in the convert script: no `pfctl -f`, because reloading
# empties the persist table that the running classic jails depend on.
pfctl -q -t "$PF_TABLE" -T delete "$VNET_CIDR" >/dev/null 2>&1 || true

# ------------------------------------------------------------- 6. VPN route
OVPN_CHANGED=0
if [ -f "$OVPN_CONF" ] && grep -q "push \"route $VNET_NET $VNET_MASK\"" "$OVPN_CONF"; then
	say "removing the $VNET_NET push route from $OVPN_CONF"
	sed -i '' '/^# >>> mcp-gateway VNET route/,/^# <<< mcp-gateway VNET route/d' "$OVPN_CONF"
	# Belt and braces if someone hand-edited the markers away.
	sed -i '' -E "/^push \"route ${VNET_NET} ${VNET_MASK}\"\$/d" "$OVPN_CONF"
	OVPN_CHANGED=1
fi

# ------------------------------------------------------------- 7. the bridge
#
# Removed last, and only if nothing else is a member: if another stream has
# already put a jail on it, taking it out is not this script's call.
if ifconfig "$BRIDGE" >/dev/null 2>&1; then
	if ifconfig "$BRIDGE" | grep -q '^	member:'; then
		say "$BRIDGE still has members -- leaving it alone"
	else
		say "destroying $BRIDGE"
		ifconfig "$BRIDGE" destroy || true
		CLONED="$(sysrc -n cloned_interfaces 2>/dev/null || echo '')"
		NEW=""
		for _i in $CLONED; do
			[ "$_i" = "$BRIDGE_CLONE" ] || NEW="$NEW $_i"
		done
		sysrc cloned_interfaces="$(echo "$NEW" | sed 's/^ *//')" >/dev/null
		sysrc -x "ifconfig_${BRIDGE_CLONE}_name" >/dev/null 2>&1 || true
		sysrc -x "ifconfig_${BRIDGE}" >/dev/null 2>&1 || true
	fi
fi

# ------------------------------------------------------------------ 8. start
say "starting $JAIL (classic, $CLASSIC_IP)"
bastille start "$JAIL"

if [ "$OVPN_CHANGED" = "1" ]; then
	say "restarting openvpn"
	service openvpn restart >/dev/null 2>&1 || true
fi

say "rolled back. $JAIL is classic again -- and so is the defect in ADR-0011."
bastille list all
