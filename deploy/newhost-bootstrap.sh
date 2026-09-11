#!/usr/bin/env sh
# Base setup for a bare-metal FreeBSD jail host, run once before any of the
# other deploy/ scripts.
#
# Deliberately covers only what does NOT depend on the machine's network
# layout: packages, forwarding, the bastille release, and the directories
# the later scripts assume. Bridges, addresses and the jails themselves are
# left to the topology-aware scripts, because guessing an interface name
# here would produce a script that appears to work and quietly configures
# the wrong thing.
#
# Idempotent: safe to re-run. Everything it does is either a no-op or a
# reinstall of the same version.
#
# Usage, from the workstation:
#   JAILHOST_TRANSPORT=ssh JAILHOST_HOST=10.0.0.5 sh deploy/newhost-bootstrap.sh
#
# See deploy/README.md for the transport variables.
set -eu

cd "$(dirname "$0")"
. ./lib/remote.sh

echo "==> target: $(remote_target)"

# --------------------------------------------------------------- packages
#
# Split by which component needs them, so removing a component later tells
# you what stops being required:
#
#   bastille          the jail manager everything else sits on
#   sops, age         Credential Vault (ADR-0005 -- the CLI, not the library)
#   nginx             TLS terminator in front of the gateway (ADR-0011)
#   openvpn, easy-rsa the access path, and its own PKI
#   authelia          the OIDC provider (ADR-0008)
#   curl              used by the verification scripts; fetch(1) cannot set
#                     headers, which the token flows need
#   git               convenience for pulling this repo onto the host
PKGS="bastille sops age nginx openvpn easy-rsa authelia curl git"

echo "==> installing packages"
# -y on both: this runs unattended. bootstrap is separate from install
# because a fresh host has no pkg(8) yet and the bootstrap prompt is not
# suppressed by install's -y.
remote_sh env ASSUME_ALWAYS_YES=YES pkg bootstrap
# Unquoted on purpose: PKGS is a list and must word-split into separate
# arguments. POSIX sh has no arrays, so this is the idiom, and the contents
# are a fixed literal above rather than anything user-supplied.
# shellcheck disable=SC2086
remote_sh pkg install -y $PKGS

# ------------------------------------------------------------- forwarding
#
# Needed the moment a VNET jail exists: its traffic is routed by the host
# rather than delivered locally. Set persistently AND live, because a value
# that only takes effect after the next reboot is the kind of thing that
# works in testing and fails at 3am.
echo "==> enabling IP forwarding"
# NOT sysrc: that writes shell variables, and `net.inet.ip.forwarding` is
# not a valid shell identifier -- sysrc rejects it with "name contains
# characters not allowed in shell". sysctl.conf is a different format that
# happens to look similar, which is exactly why the mistake is easy.
#
# Passed as ONE argument so the remote shell parses the || and the >>;
# remote_sh forwards "$@" verbatim and adds no quoting of its own (see
# deploy/lib/remote.sh). Idempotent: the grep is the guard.
remote_sh 'grep -q "^net.inet.ip.forwarding=1$" /etc/sysctl.conf || echo net.inet.ip.forwarding=1 >> /etc/sysctl.conf'
remote_sh sysctl net.inet.ip.forwarding=1

# ---------------------------------------------------------------- ntpd
#
# Not cosmetic. The Audit Trail is this project's second priority, and the
# previous lab host ran ten hours behind, which would have put every
# analyst action ten hours in the past -- evidence that actively misleads.
echo "==> enabling ntpd"
remote_sh sysrc ntpd_enable=YES ntpd_sync_on_start=YES
remote_sh service ntpd start || echo "    (ntpd already running)"

# --------------------------------------------------------------- bastille
echo "==> enabling bastille"
remote_sh sysrc bastille_enable=YES

# Bastille refuses to bootstrap when the host runs ZFS but bastille.conf
# does not say so -- deliberately, because guessing would put jails on the
# wrong storage and that is expensive to undo later.
#
# Worth having rather than merely satisfying: with ZFS each jail becomes its
# own dataset, so a jail can be snapshotted before a risky change and rolled
# back independently of every other jail. The previous VM host had no such
# thing, and the VNET conversion earlier today would have been considerably
# less nerve-wracking with it.
#
# bastille.conf IS shell-variable format, so sysrc is right here -- unlike
# sysctl.conf above, which only looks similar.
if remote_sh test -f /usr/local/etc/bastille/bastille.conf; then
	ZPOOL="${BASTILLE_ZPOOL:-zroot}"
	echo "==> pointing bastille at ZFS pool $ZPOOL"
	remote_sh sysrc -f /usr/local/etc/bastille/bastille.conf \
		bastille_zfs_enable=YES "bastille_zfs_zpool=$ZPOOL"
fi

# The release the jails are built from. Matches what the lab already ran,
# so nothing in the existing provisioning has to change.
RELEASE="${BASTILLE_RELEASE:-15.1-RELEASE}"
echo "==> bootstrapping bastille release $RELEASE (slow on first run)"
if remote_sh test -d "/usr/local/bastille/releases/$RELEASE"; then
	echo "    already present, skipping"
else
	remote_sh bastille bootstrap "$RELEASE"
fi

echo
echo "==> done. Next:"
echo "    1. create the bridge and jails (topology-specific)"
echo "    2. deploy/soc-ca-bootstrap.sh      -- internal CA"
echo "    3. deploy/authelia-jail.sh          -- OIDC provider"
echo "    4. deploy/gateway-serve.sh          -- the gateway itself"
echo "    5. deploy/gateway-serve-verify.sh   -- prove it end to end"
