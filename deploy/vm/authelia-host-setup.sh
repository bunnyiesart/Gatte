#!/bin/sh
# Runs on the jailmachine VM host (not in a jail). Driven by
# deploy/authelia-jail.sh.
#
# Creates the `authelia` jail if it does not exist, installs the packages,
# issues its TLS certificate from the SOC CA, stages the payload into the
# jail's filesystem and runs the in-jail provisioning script.
#
# Idempotent. It never touches the mcp-gateway-test jail.
set -eu

JAIL="${JAIL:-authelia}"
JAIL_IP="${JAIL_IP:-10.17.89.20}"
RELEASE="${RELEASE:-15.1-RELEASE}"
FQDN="${FQDN:-id.soc.internal}"
GATEWAY_FQDN="${GATEWAY_FQDN:-mcp.soc.internal}"
# 10.17.90.10, not 10.17.89.10: mcp-gateway-test is a VNET jail on its own
# bridge and its own subnet. See deploy/gateway-vnet.md, "Subnet".
GATEWAY_IP="${GATEWAY_IP:-10.17.90.10}"
CA_DIR=/usr/local/etc/soc-ca
STAGE="${STAGE:-/tmp/authelia-stage}"
JAIL_ROOT="/usr/local/bastille/jails/$JAIL/root"

[ "$JAIL" != "mcp-gateway-test" ] || { echo "refusing to touch mcp-gateway-test" >&2; exit 1; }

# ------------------------------------------------------------------- jail
# `bastille list jails` prints one name per line and, unlike `list all`,
# reports a stopped jail too -- a jail that exists but is Down must not be
# re-created.
if bastille list jails 2>/dev/null | grep -qx "$JAIL"; then
	echo "==> jail $JAIL already exists"
else
	echo "==> creating jail $JAIL at $JAIL_IP"
	bastille create "$JAIL" "$RELEASE" "$JAIL_IP"
fi
bastille start "$JAIL" >/dev/null 2>&1 || true

echo "==> packages"
bastille pkg "$JAIL" install -y authelia nginx curl jq >/dev/null

# ------------------------------------------------------------------- hosts
# There is no DNS in this lab. Both names have to resolve on the VM host
# (that is where the verification curl runs from) and inside the jail
# (Authelia and the verify script both dial id.soc.internal by name).
add_host() {
	_file="$1"; _ip="$2"; _name="$3"
	if grep -Eq "^[[:space:]]*$_ip[[:space:]]+.*\b$_name\b" "$_file" 2>/dev/null; then
		echo "  $_file already maps $_name"
	else
		# Drop any stale mapping for this name first, so a changed IP
		# does not leave two answers in the file.
		if [ -f "$_file" ]; then
			grep -v "[[:space:]]$_name\$" "$_file" >"$_file.tmp" || true
			mv "$_file.tmp" "$_file"
		fi
		printf '%s\t%s\n' "$_ip" "$_name" >>"$_file"
		echo "  $_file now maps $_name -> $_ip"
	fi
}

echo "==> /etc/hosts"
add_host /etc/hosts "$JAIL_IP" "$FQDN"
add_host /etc/hosts "$GATEWAY_IP" "$GATEWAY_FQDN"
add_host "$JAIL_ROOT/etc/hosts" "$JAIL_IP" "$FQDN"
add_host "$JAIL_ROOT/etc/hosts" "$GATEWAY_IP" "$GATEWAY_FQDN"

# --------------------------------------------------------------------- TLS
echo "==> TLS certificate from the SOC CA"
[ -x "$CA_DIR/issue.sh" ] || { echo "no CA -- run deploy/soc-ca-bootstrap.sh first" >&2; exit 1; }
"$CA_DIR/issue.sh" "$FQDN" "$JAIL_IP"

mkdir -p "$JAIL_ROOT/usr/local/etc/nginx/tls" "$JAIL_ROOT$CA_DIR"
install -m 0644 "$CA_DIR/$FQDN.crt" "$JAIL_ROOT/usr/local/etc/nginx/tls/$FQDN.crt"
install -m 0600 "$CA_DIR/$FQDN.key" "$JAIL_ROOT/usr/local/etc/nginx/tls/$FQDN.key"
# The CA root also goes into the jail, so curl inside it can verify the
# provider the same way a real client would rather than with --insecure.
install -m 0644 "$CA_DIR/ca.crt" "$JAIL_ROOT$CA_DIR/ca.crt"

# ------------------------------------------------------------------ stage
echo "==> staging the payload into $JAIL:/root/provision"
mkdir -p "$JAIL_ROOT/root/provision"
for f in authelia-provision.sh authelia-configuration.yml authelia-nginx.conf authelia-verify.sh; do
	install -m 0755 "$STAGE/$f" "$JAIL_ROOT/root/provision/$f"
done

echo "==> provisioning inside the jail"
bastille cmd "$JAIL" /root/provision/authelia-provision.sh /root/provision

echo "==> jail $JAIL ready at https://$FQDN ($JAIL_IP)"
