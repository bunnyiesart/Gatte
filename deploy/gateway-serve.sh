#!/usr/bin/env sh
# Runs on the MAC. Cross-compiles the gateway and the four lab mocks for
# freebsd/arm64, stages them plus the deployment templates into the
# jailmachine VM, and runs deploy/vm/gateway-serve-provision.sh there.
#
# This exists for the same reason deploy/authelia-jail.sh does: a sequence
# of ad-hoc `jm ssh` commands is not reviewable and not reproducible. What
# the VM executes lives in deploy/vm/ and is staged in by scp.
#
# Idempotent. Re-running rebuilds and reinstalls the binaries and re-signs
# every registry entry; it never regenerates the age identity, the vault or
# the signing key. See deploy/gateway-serve.md.
#
#   ./deploy/gateway-serve.sh            # provision
#   ./deploy/gateway-serve-verify.sh     # start it and prove it works
set -eu

GW_JAIL="${GW_JAIL:-mcp-gateway-test}"
JM_STATE_ROOT="${JM_STATE_ROOT:-$HOME/.jailmachine}"
JM_SSH_KEY="$JM_STATE_ROOT/machines/jailmachine/ssh/id_ed25519"
STAGE=/tmp/mcp-gateway-deploy
# Not /tmp/mcp-gateway-build: an earlier stream left a plain FILE at that
# exact path, and `mkdir -p` on it fails rather than being the no-op the
# name promises.
BUILD="${BUILD:-/tmp/mcp-gateway-jail-build}"

cd "$(dirname "$0")/.."

# The build version ends up in the startup log line and in the MCP
# initialize handshake, so it is worth being a commit rather than "dev".
VERSION="${VERSION:-$(git rev-parse --short HEAD 2>/dev/null || echo dev)}"

scp_vm() {
	scp -q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no \
		-i "$JM_SSH_KEY" -P 2222 "$@"
}

echo "==> cross-compiling for freebsd/arm64 (version $VERSION)"
mkdir -p "$BUILD"
GOOS=freebsd GOARCH=arm64 CGO_ENABLED=0 \
	go build -ldflags "-s -w -X main.buildVersion=$VERSION" \
	-o "$BUILD/mcp-gateway" ./cmd/mcp-gateway
for m in casemgmt logsearch docsearch threatintel; do
	# The mocks are the four upstreams. CGO_ENABLED=0 for the same reason
	# as the gateway: a static binary that does not care what libc the jail
	# has.
	GOOS=freebsd GOARCH=arm64 CGO_ENABLED=0 \
		go build -ldflags "-s -w" -o "$BUILD/mock-$m" "./lab/servers/$m"
done
ls -l "$BUILD" | sed 's/^/    /'

echo "==> staging into the VM at $STAGE"
jm ssh -- "rm -rf $STAGE && mkdir -p $STAGE"
scp_vm "$BUILD/mcp-gateway" "$BUILD/mock-casemgmt" "$BUILD/mock-logsearch" \
	"$BUILD/mock-docsearch" "$BUILD/mock-threatintel" \
	deploy/gateway-jail/config.toml.template \
	deploy/gateway-jail/mcp_gateway \
	deploy/gateway-jail/nginx.conf \
	deploy/vm/gateway-serve-provision.sh \
	deploy/vm/gateway-serve-verify.sh \
	deploy/vm/gateway-token.sh \
	deploy/vm/gateway-upstreams.sh \
	"root@127.0.0.1:$STAGE/"

echo "==> provisioning jail $GW_JAIL"
jm ssh -- "GW_JAIL=$GW_JAIL STAGE=$STAGE sh $STAGE/gateway-serve-provision.sh"

echo
echo "==> done. Jail $GW_JAIL is at 10.17.90.10; nginx terminates TLS there and"
echo "    proxies to the gateway on the jail's own 127.0.0.1:8080."
echo "    Next: ./deploy/gateway-serve-verify.sh"
