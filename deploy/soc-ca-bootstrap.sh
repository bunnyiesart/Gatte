#!/usr/bin/env sh
# Provisions the SOC lab internal CA inside the jailmachine VM.
#
#     ./deploy/soc-ca-bootstrap.sh
#
# Afterwards, and this is the contract other streams depend on:
#
#     /usr/local/etc/soc-ca/ca.crt          the root, 0644, in the VM host
#     /usr/local/etc/soc-ca/ca.key          the root key, 0600
#     /usr/local/etc/soc-ca/issue.sh NAME IP    issues NAME.crt / NAME.key
#
# Idempotent. Re-running keeps an existing, healthy root untouched -- see
# deploy/vm/soc-ca-install.sh for exactly when it decides not to.
#
# Local lab only. See deploy/authelia-jail.md for why this is not a PKI.
set -eu

JM_STATE_ROOT="${JM_STATE_ROOT:-$HOME/.jailmachine}"
JM_SSH_KEY="$JM_STATE_ROOT/machines/jailmachine/ssh/id_ed25519"
JM_SSH_PORT="${JM_SSH_PORT:-2222}"
STAGE=/tmp/soc-ca-stage

cd "$(dirname "$0")/.."

vmcp() {
	scp -q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no \
		-i "$JM_SSH_KEY" -P "$JM_SSH_PORT" "$1" "root@127.0.0.1:$2"
}

echo "==> staging the CA scripts into the VM"
jm ssh -- mkdir -p "$STAGE"
vmcp deploy/vm/soc-ca-install.sh "$STAGE/soc-ca-install.sh"
vmcp deploy/vm/soc-ca-issue.sh "$STAGE/soc-ca-issue.sh"
jm ssh -- chmod 0755 "$STAGE/soc-ca-install.sh"

echo "==> creating / verifying the CA"
jm ssh -- "$STAGE/soc-ca-install.sh" "$STAGE/soc-ca-issue.sh"

echo "==> done. Consumers copy /usr/local/etc/soc-ca/ca.crt out of the VM:"
echo "    jm ssh -- cat /usr/local/etc/soc-ca/ca.crt > soc-ca.crt"
