#!/bin/sh
# smoke.sh -- end-to-end check of a running deploy/docker stack (ADR-0049).
#
#     cd deploy/docker && ./smoke.sh [SERVER SAFE_TOOL [SENSITIVE_TOOL [SAFE_ARGS_JSON]]]
#     e.g. ./smoke.sh petstore findPetsByStatus addPet '{"query_status":"available"}'
#
# From the host, as an analyst would: creates a throwaway person, signs in
# at Authelia with the public client's authorization-code + PKCE flow (curl
# stands in for the browser), opens an MCP session at the gateway with the access token, lists
# the tools, calls SAFE_TOOL (it must answer) and SENSITIVE_TOOL (it must be
# refused), and deletes the person. The password and the tokens stay in
# shell variables and a private temporary directory; nothing prints them.
#
# Needs on the host: docker compose, curl, jq, openssl.

set -eu
cd "$(dirname "$0")"
SERVER=${1:-}
SAFE=${2:-}
SENSITIVE=${3:-}
SAFE_ARGS=${4:-'{}'}

. ./.env
[ "${GATTE_PORT:-443}" = 443 ] && sfx= || sfx=:$GATTE_PORT
GATEWAY=https://$GATTE_DOMAIN$sfx/
ISSUER=https://auth.$GATTE_DOMAIN$sfx
AUDIENCE=$GATEWAY
CLIENT_ID=claude-code
REDIRECT_URI=http://127.0.0.1:47823/callback
U=smoke$(openssl rand -hex 3)

W=$(mktemp -d)
cleanup() {
	docker compose exec -T gatte gatte user rm "$U" >/dev/null 2>&1 || true
	rm -rf "$W"
}
trap cleanup EXIT INT TERM

ok() { printf 'ok    %s\n' "$*"; }
fail() {
	printf 'FAIL  %s\n' "$*" >&2
	exit 1
}

if [ "${GATTE_TLS:-internal}" = internal ]; then
	docker compose exec -T gatte gatte ca >"$W/ca.crt" || fail "gatte ca"
	CURL="curl -sS --cacert $W/ca.crt"
else
	CURL="curl -sS"
fi

# 1. The gateway answers anonymously only with its OAuth challenge.
c=$($CURL -o /dev/null -w '%{http_code}' -X POST "$GATEWAY" -H 'Content-Type: application/json' -d '{}')
[ "$c" = 401 ] || fail "anonymous call: http $c, want 401"
ok "anonymous call refused with 401"

# 2. A throwaway person.
docker compose exec -T gatte gatte user add "$U" -name "Smoke Test" >"$W/add" 2>&1 || fail "user add: $(cat "$W/add")"
PASSWORD=$(sed -n 's/^One-time password, shown only now: //p' "$W/add")
[ -n "$PASSWORD" ] || fail "user add printed no password"
rm -f "$W/add"
ok "created $U in soc-analysts"
sleep 2 # Authelia's watch on the users file

# 3. Sign in: first factor, authorization (with consent), code -> token.
$CURL -o "$W/disco" "$ISSUER/.well-known/openid-configuration" || fail "discovery"
AUTHZ=$(jq -r .authorization_endpoint "$W/disco")
TOKEN_EP=$(jq -r .token_endpoint "$W/disco")
VERIFIER=$(openssl rand -hex 32)
CHALLENGE=$(printf '%s' "$VERIFIER" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
STATE=$(openssl rand -hex 16)
jq -nc --arg u "$U" --arg p "$PASSWORD" --arg t "$ISSUER/" \
	'{username:$u, password:$p, keepMeLoggedIn:false, targetURL:$t}' >"$W/login.req"
PASSWORD=
$CURL -c "$W/c" -o "$W/login" -H 'Content-Type: application/json' -H "Origin: $ISSUER" \
	-X POST --data @"$W/login.req" "$ISSUER/api/firstfactor" || fail "firstfactor"
rm -f "$W/login.req"
[ "$(jq -r .status "$W/login")" = OK ] || fail "first factor refused: $(cat "$W/login")"
ok "signed in at $ISSUER"

$CURL -b "$W/c" -c "$W/c" -o /dev/null -D "$W/h" -G "$AUTHZ" \
	--data-urlencode "client_id=$CLIENT_ID" --data-urlencode "response_type=code" \
	--data-urlencode "scope=openid profile email groups offline_access" \
	--data-urlencode "redirect_uri=$REDIRECT_URI" --data-urlencode "resource=$AUDIENCE" \
	--data-urlencode "code_challenge=$CHALLENGE" --data-urlencode "code_challenge_method=S256" \
	--data-urlencode "state=$STATE" || fail "authorization request"
loc=$(awk 'tolower($1)=="location:"{print $2}' "$W/h" | tr -d '\r' | tail -n 1)
case "$loc" in
*flow_id=*)
	flow=$(printf '%s' "$loc" | sed -n 's/.*[?&]flow_id=\([^&]*\).*/\1/p')
	jq -nc --arg f "$flow" --arg c "$CLIENT_ID" '{flow_id:$f, client_id:$c, consent:true, pre_configure:true}' >"$W/consent.req"
	$CURL -b "$W/c" -c "$W/c" -o "$W/consent" -H 'Content-Type: application/json' -H "Origin: $ISSUER" \
		-X POST --data @"$W/consent.req" "$ISSUER/api/oidc/consent" || fail "consent"
	[ "$(jq -r .status "$W/consent")" = OK ] || fail "consent refused: $(cat "$W/consent")"
	$CURL -b "$W/c" -c "$W/c" -o /dev/null -D "$W/h" "$(jq -r .data.redirect_uri "$W/consent")" || fail "post-consent"
	loc=$(awk 'tolower($1)=="location:"{print $2}' "$W/h" | tr -d '\r' | tail -n 1)
	;;
esac
case "$loc" in "$REDIRECT_URI"*"state=$STATE"*) ;; *) fail "unexpected redirect: $loc" ;; esac
CODE=$(printf '%s' "$loc" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
c=$($CURL -o "$W/token" -w '%{http_code}' -X POST "$TOKEN_EP" \
	--data-urlencode "grant_type=authorization_code" --data-urlencode "code=$CODE" \
	--data-urlencode "redirect_uri=$REDIRECT_URI" --data-urlencode "client_id=$CLIENT_ID" \
	--data-urlencode "resource=$AUDIENCE" --data-urlencode "code_verifier=$VERIFIER")
[ "$c" = 200 ] || fail "token exchange: http $c"
AT=$(jq -r .access_token "$W/token")
rm -f "$W/token"
ok "access token from the public client with PKCE (no secret)"

# 4. MCP over streamable HTTP with that token.
rpc() { # ID METHOD PARAMS-JSON OUT
	jq -nc --argjson id "$1" --arg m "$2" --argjson p "$3" '{jsonrpc:"2.0", id:$id, method:$m, params:$p}' >"$W/req"
	$CURL -o "$W/$4.raw" -D "$W/$4.h" -w '%{http_code}' -X POST "$GATEWAY" \
		-H "Authorization: Bearer $AT" -H 'Content-Type: application/json' \
		-H 'Accept: application/json, text/event-stream' ${SID:+-H "Mcp-Session-Id: $SID"} \
		--data @"$W/req"
	{ sed -n 's/^data: //p' "$W/$4.raw"; grep -v '^\(data\|event\|id\):' "$W/$4.raw" || true; } |
		jq -s 'map(select(type == "object")) | last' >"$W/$4"
}
SID=
c=$(rpc 1 initialize '{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"gatte-smoke","version":"1"}}' init)
[ "$c" = 200 ] || fail "initialize: http $c"
SID=$(awk 'tolower($1)=="mcp-session-id:"{print $2}' "$W/init.h" | tr -d '\r')
jq -nc '{jsonrpc:"2.0", method:"notifications/initialized"}' >"$W/req"
$CURL -o /dev/null -X POST "$GATEWAY" -H "Authorization: Bearer $AT" -H 'Content-Type: application/json' \
	-H 'Accept: application/json, text/event-stream' ${SID:+-H "Mcp-Session-Id: $SID"} --data @"$W/req" || true
c=$(rpc 2 tools/list '{}' list)
[ "$c" = 200 ] || fail "tools/list: http $c"
ok "gateway session open; $U sees: $(jq -r '[.result.tools[].name] | join(" ")' "$W/list")"

if [ -n "$SERVER" ] && [ -n "$SAFE" ]; then
	t=$SERVER.$SAFE
	jq -e --arg t "$t" '[.result.tools[].name] | index($t)' "$W/list" >/dev/null || fail "$t is not listed for $U"
	c=$(rpc 3 tools/call "$(jq -nc --arg n "$t" --argjson a "$SAFE_ARGS" '{name:$n, arguments:$a}')" call)
	[ "$c" = 200 ] || fail "tools/call $t: http $c"
	jq -e '.result and (.result.isError | not)' "$W/call" >/dev/null || fail "tools/call $t: $(jq -c . "$W/call" | cut -c1-300)"
	ok "called $t through the gateway: $(jq -r '.result.content[0].text' "$W/call" | cut -c1-120)"
fi
if [ -n "$SERVER" ] && [ -n "$SENSITIVE" ]; then
	t=$SERVER.$SENSITIVE
	if jq -e --arg t "$t" '[.result.tools[].name] | index($t)' "$W/list" >/dev/null; then
		fail "sensitive $t is listed for $U, a read-only analyst"
	fi
	rpc 4 tools/call "$(jq -nc --arg n "$t" '{name:$n, arguments:{}}')" deny >/dev/null || true
	if jq -e '.result and (.result.isError | not)' "$W/deny" >/dev/null 2>&1; then
		fail "sensitive $t answered a read-only analyst"
	fi
	ok "sensitive $t is neither listed nor callable for $U"
fi
AT=
ok "all checks passed"
