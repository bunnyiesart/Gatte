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

JM_STATE_ROOT="${JM_STATE_ROOT:-$HOME/.jailmachine}"
JM_SSH_KEY="$JM_STATE_ROOT/machines/jailmachine/ssh/id_ed25519"
JM_SSH_PORT="${JM_SSH_PORT:-2222}"
STAGE=/tmp/authelia-stage

cd "$(dirname "$0")/.."

vmcp() {
	scp -q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no \
		-i "$JM_SSH_KEY" -P "$JM_SSH_PORT" "$1" "root@127.0.0.1:$2"
}

echo "==> ensuring the SOC CA exists"
./deploy/soc-ca-bootstrap.sh

echo "==> staging the jail payload into the VM"
jm ssh -- mkdir -p "$STAGE"
for f in authelia-host-setup.sh authelia-provision.sh authelia-verify.sh \
         authelia-configuration.yml authelia-nginx.conf; do
	vmcp "deploy/vm/$f" "$STAGE/$f"
done
jm ssh -- chmod 0755 "$STAGE/authelia-host-setup.sh"

echo "==> running the host-side setup in the VM"
jm ssh -- env "STAGE=$STAGE" "$STAGE/authelia-host-setup.sh"

echo
echo "==> done. Verify with:"
echo "    ./deploy/authelia-verify.sh"
