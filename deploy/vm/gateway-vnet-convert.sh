#!/bin/sh
# Runs INSIDE the jailmachine FreeBSD VM, as root. Not meant to be run on the
# Mac -- deploy/gateway-vnet.sh copies this in and executes it.
#
# Converts the `mcp-gateway-test` jail from a classic (shared-stack) jail to a
# VNET jail, so that it has a network stack of its own and therefore a real,
# private 127.0.0.1.
#
# WHY (see design/adr/0011 and deploy/gateway-vnet.md): a classic jail has no
# loopback. A process that binds 127.0.0.1 inside one has that bind rewritten
# to the jail's routable address, so `mcp-gateway`'s requireLoopbackBind check
# passes while the socket is still reachable across the VPN in cleartext,
# bypassing the nginx TLS terminator entirely. VNET is the only fix that makes
# the check mean what it says.
#
# Idempotent. Re-running:
#   - does not re-create the bridge, the epair, or duplicate rc.conf entries
#   - does not overwrite the saved classic jail.conf (the rollback anchor)
#   - does rewrite jail.conf from the template below, so hand edits are lost
#   - restarts the jail, and restarts openvpn only if the pushed route set
#     actually changed
#
# It does NOT touch the `authelia` jail's configuration. See "The one thing
# this leaves stale" in deploy/gateway-vnet.md.
#
# Undo: deploy/vm/gateway-vnet-rollback.sh
set -eu

JAIL="${JAIL:-mcp-gateway-test}"

# Short because IFNAMSIZ is 16 and "e0a_mcp-gateway-test" is 20 characters.
# Bastille solves the same problem by falling back to e0a_bastilleN; a stable
# name is easier to recognise in ifconfig output than a counter.
EPAIR_HOST=e0a_mcpgw
EPAIR_JAIL=e0b_mcpgw

# Host-side bridge. bridge10 is the clone unit; socbr0 is the name it is
# renamed to. A high unit number keeps it clear of the bridge0/bridge1 that
# podman's CNI plugin allocates on demand.
BRIDGE_CLONE=bridge10
BRIDGE=socbr0

# The VNET subnet. Deliberately NOT 10.17.89.0/24 -- see the "Subnet" section
# of deploy/gateway-vnet.md. In short: 10.17.89.10 and .20 exist as /32 host
# routes on the bastille0 loopback clone, and a jail whose own /24 covers
# 10.17.89.20 would treat Authelia as on-link and ARP for it on a bridge
# where nothing answers.
VNET_NET=10.17.90.0
VNET_CIDR=10.17.90.0/24
VNET_MASK=255.255.255.0
HOST_IP=10.17.90.1
JAIL_IP=10.17.90.10
PREFIX=24

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

# ------------------------------------------------------------- preconditions

[ "$(id -u)" -eq 0 ] || die "must run as root inside the VM"
[ "$(sysctl -n kern.features.vimage 2>/dev/null || echo 0)" = "1" ] ||
	die "this kernel has no VIMAGE support (kern.features.vimage != 1); VNET is impossible here"
command -v bastille >/dev/null 2>&1 || die "bastille is not installed"
[ -d "$JAIL_DIR" ] || die "no jail at $JAIL_DIR"
[ -f "$JAIL_CONF" ] || die "no $JAIL_CONF"

# ------------------------------------------------- 1. keep the way back home
#
# Written once, before anything is changed, and never overwritten. This file
# is what gateway-vnet-rollback.sh restores; if a re-run clobbered it with the
# VNET version there would be no way back.
if [ ! -f "$CLASSIC_CONF" ]; then
	if grep -q '^[[:space:]]*vnet;' "$JAIL_CONF"; then
		die "$JAIL_CONF is already VNET but $CLASSIC_CONF is missing -- refusing to run without a rollback anchor"
	fi
	say "saving the classic jail.conf to $CLASSIC_CONF"
	cp -p "$JAIL_CONF" "$CLASSIC_CONF"
else
	say "classic jail.conf already saved at $CLASSIC_CONF"
fi

# ---------------------------------------------------- 2. host bridge, at boot
#
# cloned_interfaces already carries lo1 (renamed to bastille0 for the classic
# jails). Append rather than set, or Authelia loses its address on the next
# reboot.
CLONED="$(sysrc -n cloned_interfaces 2>/dev/null || echo '')"
case " $CLONED " in
*" $BRIDGE_CLONE "*)
	say "$BRIDGE_CLONE already in cloned_interfaces"
	;;
*)
	say "adding $BRIDGE_CLONE to cloned_interfaces (keeping: $CLONED)"
	sysrc cloned_interfaces="$CLONED $BRIDGE_CLONE" >/dev/null
	;;
esac
sysrc "ifconfig_${BRIDGE_CLONE}_name=$BRIDGE" >/dev/null
sysrc "ifconfig_${BRIDGE}=inet $HOST_IP/$PREFIX" >/dev/null

# ------------------------------------------------- 3. host bridge, right now
if ifconfig "$BRIDGE" >/dev/null 2>&1; then
	say "$BRIDGE already exists"
else
	say "creating $BRIDGE"
	_new="$(ifconfig bridge create)"
	ifconfig "$_new" name "$BRIDGE"
fi
if ifconfig "$BRIDGE" | grep -qw "inet $HOST_IP"; then
	say "$BRIDGE already has $HOST_IP"
else
	say "addressing $BRIDGE as $HOST_IP/$PREFIX"
	ifconfig "$BRIDGE" inet "$HOST_IP/$PREFIX"
fi
ifconfig "$BRIDGE" up

# ------------------------------------------------------------ 4. IP forwarding
#
# With classic jails this sysctl was decorative -- everything shared the host
# stack. With VNET it is load-bearing: every packet between the jail and
# anything else, Authelia included, is now routed by the host.
if ! grep -q '^net.inet.ip.forwarding=1' /etc/sysctl.conf 2>/dev/null; then
	say "enabling net.inet.ip.forwarding persistently"
	printf '\n# VNET jails are routed, not shared-stack -- see deploy/gateway-vnet.md\nnet.inet.ip.forwarding=1\n' >>/etc/sysctl.conf
fi
sysctl net.inet.ip.forwarding=1 >/dev/null

# ------------------------------------------------------------------- 5. stop
if jls -j "$JAIL" >/dev/null 2>&1; then
	say "stopping $JAIL"
	bastille stop "$JAIL" >/dev/null 2>&1 || jail -r "$JAIL" >/dev/null 2>&1 || true
else
	say "$JAIL is not running"
fi
# A jail.conf rewrite while the jail is up would leave the old poststop hooks
# unable to find the interfaces they were told to destroy.
jls -j "$JAIL" >/dev/null 2>&1 && die "could not stop $JAIL"
true

# ------------------------------------------------------------- 6. jail.conf
#
# The \$ escapes are required: jail.conf has its own variable syntax, so a
# bare $ would be expanded by jail(8) instead of by the /bin/sh that runs the
# exec.prestart line. This mirrors what bastille's own if_bridge VNET template
# emits (see generate_vnet_jail_netblock in /usr/local/share/bastille/common.sh).
say "writing VNET $JAIL_CONF"
cat >"$JAIL_CONF" <<EOF
$JAIL {
  enforce_statfs = 2;
  devfs_ruleset = 4;
  exec.clean;
  exec.consolelog = /var/log/bastille/${JAIL}_console.log;
  exec.start = '/bin/sh /etc/rc';
  exec.stop = '/bin/sh /etc/rc.shutdown';
  host.hostname = $JAIL;
  mount.devfs;
  mount.fstab = $JAIL_DIR/fstab;
  path = $JAIL_ROOT;
  securelevel = 2;
  osrelease = "15.1-RELEASE";

  vnet;
  vnet.interface = $EPAIR_JAIL;
  exec.prestart += "epair0=\\\$(ifconfig epair create) && ifconfig \\\${epair0} up name $EPAIR_HOST && ifconfig \\\${epair0%a}b up name $EPAIR_JAIL";
  exec.prestart += "ifconfig $BRIDGE addm $EPAIR_HOST";
  exec.prestart += "ifconfig $EPAIR_HOST description \\"vnet0 host interface for Bastille jail $JAIL\\"";
  exec.poststop += "ifconfig $EPAIR_HOST destroy";
}
EOF
# Note what is NOT here: the classic config's "ip4.addr" and "ip6 = disable".
# Both are IP restrictions imposed by the host on a shared stack, and jail(8)
# rejects them outright on a VNET jail --
#
#     jail: mcp-gateway-test: vnet jails cannot have IP address restrictions
#
# which is the same fact as the one this whole conversion is about, stated
# from the other side: the host no longer decides what this jail's addresses
# are, because the jail has a stack of its own. Addressing moves into the
# jail's own rc.conf, below.

# ------------------------------------------------------- 7. inside the jail
#
# A VNET jail configures its own stack: /etc/rc runs netif, which brings up
# its private lo0 (this is the whole point) and whatever it finds in rc.conf.
#
# Edited as a plain file rather than with `sysrc -R`: sysrc -R chroots, and
# this is a thin jail whose /bin is a symlink into the nullfs mount that only
# exists while the jail is running. `sysrc -R` on a stopped thin jail fails
# with "chroot: /bin/sh: No such file or directory".
set_rc() {
	_file="$1"; _key="$2"; _val="$3"
	touch "$_file"
	if grep -q "^${_key}=" "$_file"; then
		sed -i '' -E "s|^${_key}=.*\$|${_key}=\"${_val}\"|" "$_file"
	else
		printf '%s="%s"\n' "$_key" "$_val" >>"$_file"
	fi
}
say "configuring the jail's own network stack"
JAIL_RC="$JAIL_ROOT/etc/rc.conf"
set_rc "$JAIL_RC" "ifconfig_${EPAIR_JAIL}_name" "vnet0"
set_rc "$JAIL_RC" "ifconfig_vnet0" "inet $JAIL_IP/$PREFIX"
set_rc "$JAIL_RC" "ifconfig_vnet0_descr" "jail interface for $BRIDGE"
set_rc "$JAIL_RC" "defaultrouter" "$HOST_IP"

# ------------------------------------------------------------------ 8. hosts
#
# mcp.soc.internal moves with the jail. id.soc.internal does not: Authelia is
# untouched at 10.17.89.20, and the jail reaches it through the host now.
set_hosts_entry() {
	_file="$1"; _ip="$2"; _name="$3"
	[ -f "$_file" ] || return 0
	if grep -Eq "^[[:space:]]*$(echo "$_ip" | sed 's/\./\\./g')[[:space:]]+$_name\$" "$_file"; then
		say "$_file already maps $_name -> $_ip"
		return 0
	fi
	say "pointing $_name at $_ip in $_file"
	sed -i '' -E "/^[[:space:]]*[0-9.]+[[:space:]]+${_name}[[:space:]]*\$/d" "$_file"
	printf '%s\t%s\n' "$_ip" "$_name" >>"$_file"
}
set_hosts_entry "$JAIL_ROOT/etc/hosts" "$JAIL_IP" mcp.soc.internal
set_hosts_entry "$JAIL_ROOT/etc/hosts" 10.17.89.20 id.soc.internal
set_hosts_entry /etc/hosts "$JAIL_IP" mcp.soc.internal

# ---------------------------------------------------------------------- 9. pf
#
# bastille populates the <jails> NAT table from ip4.addr at jail start, and
# start.sh skips that entirely for VNET jails (`if [ "$(bastille config ...
# get vnet)" != 'enabled' ]`). So outbound NAT for this jail is now ours to
# arrange: the subnet goes into the table definition in pf.conf, so it is
# there after a reboot, and into the live table now, so it is there without
# one.
#
# Deliberately no `pfctl -f`: reloading replaces a persist table's contents
# with the file's, which would drop the 10.17.89.x entries bastille added for
# the classic jails until those jails restart. Authelia is one of them.
if grep -q "$VNET_CIDR" "$PF_CONF"; then
	say "$PF_CONF already has $VNET_CIDR in the <$PF_TABLE> table"
else
	say "adding $VNET_CIDR to the <$PF_TABLE> table in $PF_CONF"
	cp -p "$PF_CONF" "$PF_CONF.pre-vnet"
	sed -i '' -E "s|^table <${PF_TABLE}> persist\$|table <${PF_TABLE}> persist { ${VNET_CIDR} }|" "$PF_CONF"
	grep -q "$VNET_CIDR" "$PF_CONF" || die "failed to edit $PF_CONF (table <$PF_TABLE> line not found)"
	pfctl -n -f "$PF_CONF" || die "$PF_CONF no longer parses -- restore $PF_CONF.pre-vnet"
fi
pfctl -q -t "$PF_TABLE" -T add "$VNET_CIDR" 2>/dev/null || true

# ------------------------------------------------------------- 10. VPN route
#
# The OpenVPN server pushes the jail subnet to clients. A client that only
# learns 10.17.89.0/24 has no route to the gateway any more.
OVPN_CHANGED=0
if [ -f "$OVPN_CONF" ]; then
	if grep -q "push \"route $VNET_NET $VNET_MASK\"" "$OVPN_CONF"; then
		say "openvpn already pushes route $VNET_NET $VNET_MASK"
	else
		say "adding push route $VNET_NET $VNET_MASK to $OVPN_CONF"
		# Marker-delimited so the rollback script can remove exactly this
		# and nothing else.
		printf '\n# >>> mcp-gateway VNET route (deploy/vm/gateway-vnet-convert.sh) >>>\n# The mcp-gateway jail is VNET and lives on its own subnet -- see\n# deploy/gateway-vnet.md. Without this the client keeps only\n# 10.17.89.0/24 and loses the gateway.\npush "route %s %s"\n# <<< mcp-gateway VNET route <<<\n' \
			"$VNET_NET" "$VNET_MASK" >>"$OVPN_CONF"
		OVPN_CHANGED=1
	fi
else
	say "no $OVPN_CONF -- skipping the VPN push route (run deploy/openvpn-setup.sh later; its template already has it)"
fi

# ------------------------------------------------------------------ 11. start
#
# A jail that failed to start after its prestart hooks ran leaves the host
# epair behind, and the next attempt then fails on "ifconfig: e0a_mcpgw: name
# already exists".
if ifconfig "$EPAIR_HOST" >/dev/null 2>&1; then
	say "destroying leftover $EPAIR_HOST from a previous attempt"
	ifconfig "$EPAIR_HOST" destroy || true
fi
say "starting $JAIL"
bastille start "$JAIL"

# ----------------------------------------------------------------- 12. openvpn
if [ "$OVPN_CHANGED" = "1" ]; then
	say "restarting openvpn to publish the new route"
	service openvpn restart >/dev/null 2>&1 || service openvpn start >/dev/null 2>&1 || true
fi

# ------------------------------------------------------------------ 13. sanity
say "checking the routing table for conflicts"
if [ "$(netstat -rn -f inet | awk '$1=="'"$VNET_CIDR"'" {print $4}' | sort -u | wc -l | tr -d ' ')" -gt 1 ]; then
	die "$VNET_CIDR is reachable through more than one interface -- resolve before trusting anything below"
fi
netstat -rn -f inet | grep -E '^(Destination|10\.8\.0|10\.17\.)' || true

say "done. Verify with deploy/gateway-vnet-verify.sh"
