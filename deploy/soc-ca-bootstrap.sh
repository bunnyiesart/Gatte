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

# shellcheck source=deploy/lib/remote.sh
. "$(dirname "$0")/lib/remote.sh"

STAGE=/tmp/soc-ca-stage

cd "$(dirname "$0")/.."

echo "==> staging the CA scripts into $(remote_target)"
remote_sh mkdir -p "$STAGE"
remote_cp deploy/vm/soc-ca-install.sh "$STAGE/soc-ca-install.sh"
remote_cp deploy/vm/soc-ca-issue.sh "$STAGE/soc-ca-issue.sh"
remote_sh chmod 0755 "$STAGE/soc-ca-install.sh"

echo "==> creating / verifying the CA"
remote_sh "$STAGE/soc-ca-install.sh" "$STAGE/soc-ca-issue.sh"

echo "==> done. Consumers copy /usr/local/etc/soc-ca/ca.crt out of the VM:"
echo "    jm ssh -- cat /usr/local/etc/soc-ca/ca.crt > soc-ca.crt"
