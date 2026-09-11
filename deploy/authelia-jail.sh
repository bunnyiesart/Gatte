#!/usr/bin/env sh
# Creates and provisions the `authelia` jail (10.17.89.20) inside the
# jailmachine VM: Authelia as an OpenID Connect provider for id.soc.internal,
# behind nginx doing TLS with a certificate from the SOC lab CA.
#
#     ./deploy/authelia-jail.sh
#
# Idempotent, and safe to re-run after editing deploy/vm/*. It bootstraps
# the CA first if it is not there. It never touches the mcp-gateway-test
# jail.
#
# See deploy/authelia-jail.md for what this is, what it proves, and the
# several places where it is deliberately not production-shaped.
set -eu

# shellcheck source=deploy/lib/remote.sh
. "$(dirname "$0")/lib/remote.sh"

STAGE=/tmp/authelia-stage

cd "$(dirname "$0")/.."

echo "==> ensuring the SOC CA exists"
./deploy/soc-ca-bootstrap.sh

echo "==> staging the jail payload into $(remote_target)"
remote_sh mkdir -p "$STAGE"
for f in authelia-host-setup.sh authelia-provision.sh authelia-verify.sh \
         authelia-configuration.yml authelia-nginx.conf; do
	remote_cp "deploy/vm/$f" "$STAGE/$f"
done
remote_sh chmod 0755 "$STAGE/authelia-host-setup.sh"

echo "==> running the host-side setup on the jail host"
# Every tunable has to be named here explicitly. Environment does not cross
# an SSH boundary, so a variable set on the workstation is simply absent on
# the far side and the remote default applies -- silently, and looking like
# success.
#
# That is not hypothetical: provisioning this against the new host with
# JAIL_IP=10.17.90.20 produced a certificate whose SAN said 10.17.89.20 and
# an /etc/hosts entry pointing at an address that does not exist on that
# network. The script reported "provisioned" and exited 0. OIDC discovery
# from the gateway would have failed later, a long way from the cause.
#
# Defaults live on the remote side; these lines only forward an override
# when one was given, so an unset variable still means "use the default".
remote_sh env \
	"STAGE=$STAGE" \
	${JAIL_IP:+"JAIL_IP=$JAIL_IP"} \
	${GATEWAY_IP:+"GATEWAY_IP=$GATEWAY_IP"} \
	${AUTHELIA_JAIL:+"AUTHELIA_JAIL=$AUTHELIA_JAIL"} \
	"$STAGE/authelia-host-setup.sh"

echo
echo "==> done. Verify with:"
echo "    ./deploy/authelia-verify.sh"
