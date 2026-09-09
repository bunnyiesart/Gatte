#!/bin/sh
# Runs on the VM HOST. Prints one Authelia access token for USERNAME on
# stdout, and nothing else on stdout -- every diagnostic goes to stderr, so
# this can be used as `TOKEN=$(gateway-token.sh analyst)`.
#
# This is the same authorization-code flow deploy/vm/authelia-verify.sh
# drives, for the same reason: Authelia has no resource-owner-password
# grant, so the only way to a token with a real subject -- and therefore
# with the `groups` claim the gateway maps to a role -- is to authenticate
# a session the way a browser would and then drive the authorization
# endpoint with that cookie. The client is registered with
# consent_mode 'implicit' precisely so this finishes without a UI.
#
# It reads the analyst's password and the client secret out of the authelia
# jail's secrets directory, read-only, from the host filesystem. It changes
# nothing in that jail -- deliberately: that jail belongs to another
# stream and its configuration is not this one's to touch. That is also
# why the requests go to $ISSUER by name rather than by address: Authelia
# derives `iss` and every discovery URL from the Host header, and an
# IP-addressed request mints tokens the gateway will refuse.
#
# The `resource` parameter (RFC 8707) is passed on BOTH the authorization
# request and the token exchange. Without it Authelia issues a perfectly
# well-formed, correctly signed JWT with an EMPTY audience, which the
# gateway rejects -- a failure that looks like a broken gateway and is not.
set -eu

USERNAME="${1:-analyst}"

CA=/usr/local/etc/soc-ca/ca.crt
SECRETS=/usr/local/bastille/jails/authelia/root/usr/local/etc/authelia/secrets
ISSUER=https://id.soc.internal
CLIENT_ID=mcp-gateway
AUDIENCE='https://mcp.soc.internal/'
REDIRECT_URI='https://mcp.soc.internal/oauth2/callback'

WORK=$(mktemp -d /tmp/gateway-token.XXXXXX)
trap 'rm -rf "$WORK"' EXIT INT TERM
CURL="curl -sS --cacert $CA"

fail() { echo "gateway-token: $*" >&2; exit 1; }

[ -r "$CA" ] || fail "no CA root at $CA"
[ -r "$SECRETS/user.$USERNAME.plain" ] || fail "no password for user '$USERNAME' in $SECRETS"

PASSWORD=$(cat "$SECRETS/user.$USERNAME.plain")
CLIENT_SECRET=$(cat "$SECRETS/oidc.client.$CLIENT_ID.plain")

$CURL -o "$WORK/disco.json" "$ISSUER/.well-known/openid-configuration" \
	|| fail "discovery failed"
AUTHZ_EP=$(jq -r '.authorization_endpoint' "$WORK/disco.json")
TOKEN_EP=$(jq -r '.token_endpoint' "$WORK/disco.json")

LOGIN=$(jq -nc --arg u "$USERNAME" --arg p "$PASSWORD" --arg t "$ISSUER/" \
	'{username:$u, password:$p, keepMeLoggedIn:false, targetURL:$t}')
$CURL -c "$WORK/cookies" -o "$WORK/login.json" \
	-H 'Content-Type: application/json' \
	-H "Origin: $ISSUER" -H "Referer: $ISSUER/" \
	-X POST --data "$LOGIN" "$ISSUER/api/firstfactor" || fail "firstfactor failed"
[ "$(jq -r '.status' "$WORK/login.json")" = OK ] \
	|| fail "firstfactor rejected user '$USERNAME'"

$CURL -b "$WORK/cookies" -c "$WORK/cookies" -o /dev/null -D "$WORK/authz.headers" \
	-G "$AUTHZ_EP" \
	--data-urlencode "client_id=$CLIENT_ID" \
	--data-urlencode "response_type=code" \
	--data-urlencode "response_mode=query" \
	--data-urlencode "scope=openid profile email groups" \
	--data-urlencode "redirect_uri=$REDIRECT_URI" \
	--data-urlencode "resource=$AUDIENCE" \
	--data-urlencode "state=$(openssl rand -hex 16)" \
	--data-urlencode "nonce=$(openssl rand -hex 16)" || fail "authorization request failed"

LOCATION=$(awk 'tolower($1)=="location:"{print $2}' "$WORK/authz.headers" | tr -d '\r' | tail -1)
[ -n "$LOCATION" ] || fail "authorization endpoint returned no redirect"
case "$LOCATION" in *error=*) fail "authorization error: $LOCATION" ;; esac
CODE=$(printf '%s' "$LOCATION" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
[ -n "$CODE" ] || fail "no authorization code in the redirect"

$CURL -o "$WORK/token.json" -X POST "$TOKEN_EP" \
	--data-urlencode "grant_type=authorization_code" \
	--data-urlencode "code=$CODE" \
	--data-urlencode "redirect_uri=$REDIRECT_URI" \
	--data-urlencode "client_id=$CLIENT_ID" \
	--data-urlencode "client_secret=$CLIENT_SECRET" \
	--data-urlencode "resource=$AUDIENCE" || fail "token exchange failed"

jq -e '.access_token' "$WORK/token.json" >/dev/null 2>&1 \
	|| fail "no access_token in the token response"
jq -r '.access_token' "$WORK/token.json"
