#!/usr/bin/env sh
# Cross-compiles mcp-gateway for freebsd/arm64 and installs it into the
# mcp-gateway-test bastille jail running inside the jailmachine VM.
#
# Local test/dev only -- see deploy/freebsd-jail.md for the full setup this
# assumes (jailmachine installed and started, jail already created).
set -eu

# shellcheck source=deploy/lib/remote.sh
. "$(dirname "$0")/../deploy/lib/remote.sh"

JAIL=mcp-gateway-test
REMOTE_TMP=/tmp/mcp-gateway
JAIL_ROOT="/usr/local/bastille/jails/$JAIL/root"

cd "$(dirname "$0")/.."

echo "==> cross-compiling for freebsd/arm64"
GOOS=freebsd GOARCH=arm64 CGO_ENABLED=0 go build -o /tmp/mcp-gateway-freebsd ./cmd/mcp-gateway

echo "==> copying into $(remote_target)"
remote_cp /tmp/mcp-gateway-freebsd "$REMOTE_TMP"

echo "==> installing into jail $JAIL"
remote_sh mkdir -p "$JAIL_ROOT/usr/local/bin"
remote_sh cp "$REMOTE_TMP" "$JAIL_ROOT/usr/local/bin/mcp-gateway"
remote_sh chmod +x "$JAIL_ROOT/usr/local/bin/mcp-gateway"

# Smoke test: `version` is the only subcommand that reads no configuration
# file. Everything else -- serve, upstream, tool, sign, audit -- loads the
# TOML first, and config.Validate requires a database path, an OIDC issuer
# and audience, and both vault files, none of which this script installs.
# So `version` is deliberately all this proves: that a freebsd/arm64 binary
# cross-compiled on darwin/arm64 actually loads and executes in the jail.
# Anything past that is a deployment, not a smoke test -- see
# deploy/freebsd-jail.md, "What this does and doesn't prove".
echo "==> smoke test: running the binary inside the jail"
remote_sh bastille cmd "$JAIL" /usr/local/bin/mcp-gateway version

# 10.17.90.10, not 10.17.89.10: the jail became a VNET jail on its own
# bridge and moved subnet (deploy/gateway-vnet.md, "Subnet"). The old
# address was left in this line for a while and is exactly the kind of
# stale fact a deploy script should not be printing with authority.
echo "==> done. jail IP: 10.17.90.10 -- 'jm ssh -- bastille list' to confirm"
echo "    This installs the binary and nothing else. For a gateway that"
echo "    actually serves -- vault, signing key, config, upstreams, rc.d --"
echo "    use ./deploy/gateway-serve.sh (deploy/gateway-serve.md)."
