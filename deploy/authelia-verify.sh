#!/usr/bin/env sh
# Verifies the `authelia` jail actually works as an OIDC provider for
# mcp-gateway. Runs the checks inside the jail, over TLS, against the CA
# root -- not from the Mac, which has neither the hosts entries nor the CA.
#
#     ./deploy/authelia-verify.sh            # user 'analyst'  (soc-analysts)
#     ./deploy/authelia-verify.sh dfirlead   # user 'dfirlead' (dfir-leads)
#
# Non-zero exit means a check failed; the message says which. See
# deploy/authelia-jail.md, "What is proven and what is assumed".
set -eu

JAIL="${JAIL:-authelia}"
USER_UNDER_TEST="${1:-analyst}"

cd "$(dirname "$0")/.."

jm ssh -- bastille cmd "$JAIL" \
	env "USER_UNDER_TEST=$USER_UNDER_TEST" /root/provision/authelia-verify.sh
