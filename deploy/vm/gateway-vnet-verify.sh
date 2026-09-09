#!/bin/sh
# Runs INSIDE the jailmachine FreeBSD VM, as root. Not meant to be run on the
# Mac -- deploy/gateway-vnet-verify.sh copies this in and executes it.
#
# The acceptance test for the VNET conversion, and the only thing that
# entitles anyone to claim design/adr/0011's loopback property actually holds
# in this deployment.
#
# It is deliberately the SAME sequence that proved the property absent on the
# classic jail (ADR-0011, the CORREÇÃO block), run against the converted jail,
# expecting the opposite answer:
#
#     bastille cmd mcp-gateway-test sh -c "nc -l 127.0.0.1 18080 &"
#     bastille cmd mcp-gateway-test sockstat -4 -l | grep 18080
#     nc -z 10.17.90.10 18080          # from the VM host
#
# Non-zero exit means a check failed and the message says which. Nothing here
# writes anything: it is safe to run whenever, and it cleans up its listeners.
set -eu

JAIL="${JAIL:-mcp-gateway-test}"
PEER_JAIL="${PEER_JAIL:-authelia}"     # probed from, never modified
JAIL_IP="${JAIL_IP:-10.17.90.10}"
HOST_IP="${HOST_IP:-10.17.90.1}"
LOOPBACK_PORT=18080
ROUTABLE_PORT=18081
CA=/usr/local/etc/ssl/certs/soc-ca.crt
ISSUER=https://id.soc.internal

FAIL=0
ok()   { echo "  ok   -- $*"; }
bad()  { echo "  FAIL -- $*"; FAIL=1; }
head_() { echo; echo "== $*"; }

cleanup() {
	bastille cmd "$JAIL" pkill -f 'nc -l' >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM
cleanup

# ---------------------------------------------------------------- 0. shape
head_ "0. the jail is VNET"
if bastille config "$JAIL" get vnet 2>/dev/null | grep -q enabled; then
	ok "bastille reports vnet enabled"
else
	bad "bastille does not report vnet enabled -- everything below is meaningless"
	exit 1
fi
echo "--- the jail's own interfaces (note: its OWN lo0) ---"
bastille cmd "$JAIL" ifconfig | sed 's/^/  /'

# --------------------------------------------- 1. the bind stays on loopback
head_ "1. a listener on 127.0.0.1:$LOOPBACK_PORT stays on 127.0.0.1"
bastille cmd "$JAIL" sh -c "nohup nc -l 127.0.0.1 $LOOPBACK_PORT >/dev/null 2>&1 &" >/dev/null 2>&1
sleep 1
# sockstat prints the endpoint as ADDRESS:PORT, so the port is not a
# whitespace-delimited field -- grepping for " 18080 " silently matches
# nothing and makes every reachability check below vacuously pass.
SOCK="$(bastille cmd "$JAIL" sockstat -4 -l 2>/dev/null | grep ":$LOOPBACK_PORT " || true)"
echo "--- bastille cmd $JAIL sockstat -4 -l | grep $LOOPBACK_PORT ---"
echo "  ${SOCK:-<nothing listening>}"
LISTENING=1
if [ -z "$SOCK" ]; then
	bad "no listener came up at all -- the checks below would prove nothing"
	LISTENING=0
elif echo "$SOCK" | grep -q "127\.0\.0\.1:$LOOPBACK_PORT"; then
	ok "bound to 127.0.0.1:$LOOPBACK_PORT, not rewritten to the jail's address"
else
	bad "the bind was rewritten: $SOCK"
fi

# ------------------------------------------- 2. and is unreachable from out
head_ "2. that listener is unreachable from outside the jail"
if [ "$LISTENING" -eq 0 ]; then
	echo "  skip -- nothing is listening, so 'unreachable' would mean nothing"
else
	if nc -z -w 3 "$JAIL_IP" "$LOOPBACK_PORT" 2>/dev/null; then
		bad "VM host reached $JAIL_IP:$LOOPBACK_PORT -- the loopback is not private"
	else
		ok "VM host cannot reach $JAIL_IP:$LOOPBACK_PORT"
	fi
	if nc -z -w 3 "$HOST_IP" "$LOOPBACK_PORT" 2>/dev/null; then
		bad "VM host reached $HOST_IP:$LOOPBACK_PORT"
	else
		ok "VM host cannot reach $HOST_IP:$LOOPBACK_PORT (the bridge address)"
	fi
	if nc -z -w 3 127.0.0.1 "$LOOPBACK_PORT" 2>/dev/null; then
		bad "the VM host's OWN 127.0.0.1:$LOOPBACK_PORT answered -- the jail is sharing the host loopback"
	else
		ok "the VM host's own 127.0.0.1:$LOOPBACK_PORT is silent"
	fi
	if jls -j "$PEER_JAIL" >/dev/null 2>&1; then
		if bastille cmd "$PEER_JAIL" nc -z -w 3 "$JAIL_IP" "$LOOPBACK_PORT" >/dev/null 2>&1; then
			bad "the $PEER_JAIL jail reached $JAIL_IP:$LOOPBACK_PORT"
		else
			ok "the $PEER_JAIL jail cannot reach $JAIL_IP:$LOOPBACK_PORT"
		fi
	else
		echo "  skip -- $PEER_JAIL is not running"
	fi
fi

# ---------------------------------------- 3. control: the path itself works
#
# Without this, "unreachable" above could just mean "no route", and the test
# would pass on a jail with its networking broken.
head_ "3. control: a listener on the jail's ROUTABLE address IS reachable"
bastille cmd "$JAIL" sh -c "nohup nc -l $JAIL_IP $ROUTABLE_PORT >/dev/null 2>&1 &" >/dev/null 2>&1
sleep 1
if nc -z -w 3 "$JAIL_IP" "$ROUTABLE_PORT" 2>/dev/null; then
	ok "VM host reaches $JAIL_IP:$ROUTABLE_PORT -- so step 2's silence is isolation, not a dead network"
else
	bad "VM host cannot reach $JAIL_IP:$ROUTABLE_PORT either -- the jail's network is broken, step 2 proves nothing"
fi
cleanup

# ----------------------------------------------------- 4. the IdP, over TLS
#
# The gateway performs OIDC discovery at startup and refuses to come up if it
# fails (ADR-0008). Authelia is a classic jail on the other subnet, so this
# also exercises host forwarding between the two.
head_ "4. the jail still reaches the IdP over TLS, with the CA"
if ! bastille cmd "$JAIL" test -f "$CA" >/dev/null 2>&1; then
	bad "$CA is missing inside the jail"
else
	DISC="$(bastille cmd "$JAIL" fetch --ca-cert="$CA" -q -o - \
		"$ISSUER/.well-known/openid-configuration" 2>/dev/null | tr -d '\r' | grep -v '^\[' || true)"
	if echo "$DISC" | grep -q '"issuer":"https://id.soc.internal"'; then
		ok "discovery returned JSON with the expected issuer"
		echo "  $(echo "$DISC" | cut -c1-160)..."
	else
		bad "discovery did not return the expected JSON: $(echo "$DISC" | cut -c1-200)"
	fi
	if bastille cmd "$JAIL" fetch --ca-cert="$CA" -q -o /dev/null "$ISSUER/jwks.json" >/dev/null 2>&1; then
		ok "the JWKS endpoint is reachable too"
	else
		bad "the JWKS endpoint is not reachable"
	fi
fi

# --------------------------------------------------------- 5. no route mess
head_ "5. no routing conflict with the classic-jail subnet"
echo "--- netstat -rn -f inet ---"
netstat -rn -f inet | sed 's/^/  /'
DUP="$(netstat -rn -f inet | awk '{print $1}' | grep -E '^10\.17\.' | sort | uniq -d || true)"
if [ -n "$DUP" ]; then
	bad "duplicate route entries: $DUP"
else
	ok "every 10.17.x destination appears exactly once"
fi
for _r in 10.17.89.20 10.17.90.10; do
	echo "  route to $_r: $(route -n get "$_r" 2>/dev/null | awk '/interface:/ {print $2}')"
done
if [ "$(sysctl -n net.inet.ip.forwarding)" = "1" ]; then
	ok "net.inet.ip.forwarding is 1"
else
	bad "net.inet.ip.forwarding is 0 -- the VNET jail cannot reach anything"
fi

# ----------------------------------------------------- 6. Authelia untouched
head_ "6. the authelia jail is still classic and still serving"
if [ "$(bastille config "$PEER_JAIL" get vnet 2>/dev/null)" = "enabled" ]; then
	bad "$PEER_JAIL became a VNET jail -- that was not the deal"
else
	ok "$PEER_JAIL is still a classic jail"
fi
if nc -z -w 3 10.17.89.20 443 2>/dev/null; then
	ok "10.17.89.20:443 still answers from the VM host"
else
	bad "10.17.89.20:443 no longer answers"
fi

echo
if [ "$FAIL" -eq 0 ]; then
	echo "== all checks passed"
else
	echo "== SOME CHECKS FAILED -- do not report the loopback property as held"
fi
exit "$FAIL"
