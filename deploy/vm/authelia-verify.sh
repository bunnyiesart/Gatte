#!/bin/sh
# Runs INSIDE the `authelia` jail. Driven by deploy/authelia-verify.sh.
#
# Proves -- not assumes -- that the provider does the four things the
# gateway depends on:
#
#   1. serves a parseable discovery document over TLS signed by the SOC CA,
#      advertising a jwks_uri;
#   2. serves a JWKS with at least one key;
#   3. issues an access token that is a JWT, not an opaque string;
#   4. that JWT carries aud == https://mcp.soc.internal/, the right iss,
#      and a groups claim.
#
# Every request goes through nginx over TLS and verifies against the CA
# root. No --insecure anywhere: a lab that skips verification is not
# testing the thing it was built to test.
#
# Exits non-zero on the first failed assertion. Read the output, do not
# read the exit code alone.
set -eu

FQDN="${FQDN:-id.soc.internal}"
ISSUER="https://$FQDN"
CA=/usr/local/etc/soc-ca/ca.crt
SECRETS=/usr/local/etc/authelia/secrets
CLIENT_ID=mcp-gateway
AUDIENCE='https://mcp.soc.internal/'
REDIRECT_URI='https://mcp.soc.internal/oauth2/callback'
USER="${USER_UNDER_TEST:-analyst}"

WORK=$(mktemp -d /tmp/authelia-verify.XXXXXX)
trap 'rm -rf "$WORK"' EXIT INT TERM
COOKIES="$WORK/cookies"

CURL="curl -sS --cacert $CA"
fail() { echo; echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "  ok: $*"; }

# base64url -> JSON. Padding is added explicitly because jq's @base64d
# rejects unpadded input on some builds and the failure looks like a
# malformed token rather than a decoder problem.
decode_segment() {
	jq -Rr '
		gsub("-";"+") | gsub("_";"/")
		| . + (["", "", "==", "="][length % 4])
		| @base64d'
}

# base64url -> raw bytes on stdout.
b64url_raw() {
	tr -- '-_' '+/' | awk '{ n = length($0) % 4
		printf "%s%s", $0, (n == 2 ? "==" : n == 3 ? "=" : "") }' \
		| openssl base64 -d -A
}

# base64url -> lowercase hex, no separators (for ASN.1 INTEGER generation).
b64url_hex() {
	b64url_raw | od -An -tx1 -v | tr -d ' \n'
}

echo "=== 1. discovery: $ISSUER/.well-known/openid-configuration"
$CURL -o "$WORK/disco.json" -w '  HTTP %{http_code}\n' \
	"$ISSUER/.well-known/openid-configuration" || fail "discovery request failed"
jq -e . "$WORK/disco.json" >/dev/null || fail "discovery document is not JSON"

DISCO_ISS=$(jq -r '.issuer' "$WORK/disco.json")
JWKS_URI=$(jq -r '.jwks_uri' "$WORK/disco.json")
AUTHZ_EP=$(jq -r '.authorization_endpoint' "$WORK/disco.json")
TOKEN_EP=$(jq -r '.token_endpoint' "$WORK/disco.json")

[ "$DISCO_ISS" = "$ISSUER" ] || fail "issuer is '$DISCO_ISS', expected '$ISSUER'"
ok "issuer  = $DISCO_ISS"
[ -n "$JWKS_URI" ] && [ "$JWKS_URI" != null ] || fail "no jwks_uri in the discovery document"
ok "jwks_uri = $JWKS_URI"
ok "authorization_endpoint = $AUTHZ_EP"
ok "token_endpoint = $TOKEN_EP"

echo
echo "=== 2. JWKS"
$CURL -o "$WORK/jwks.json" "$JWKS_URI" || fail "JWKS request failed"
NKEYS=$(jq -r '.keys | length' "$WORK/jwks.json")
[ "$NKEYS" -ge 1 ] 2>/dev/null || fail "JWKS has no keys"
ok "$NKEYS key(s)"
jq -r '.keys[] | "  kid=\(.kid) kty=\(.kty) alg=\(.alg) use=\(.use)"' "$WORK/jwks.json"

echo
echo "=== 3. access token for user '$USER' (authorization code flow)"
PASSWORD=$(cat "$SECRETS/user.$USER.plain")
CLIENT_SECRET=$(cat "$SECRETS/oidc.client.$CLIENT_ID.plain")

# 3a. First factor. Authelia has no resource-owner-password grant, so the
# only way to a token with a real subject -- and therefore with groups -- is
# to authenticate a session the way the browser would, then drive the
# authorization endpoint with that session cookie. The client is registered
# with consent_mode 'implicit' precisely so this can finish without a UI.
LOGIN=$(jq -nc --arg u "$USER" --arg p "$PASSWORD" --arg t "$ISSUER/" \
	'{username:$u, password:$p, keepMeLoggedIn:false, targetURL:$t}')
$CURL -c "$COOKIES" -o "$WORK/login.json" \
	-H 'Content-Type: application/json' \
	-H "Origin: $ISSUER" -H "Referer: $ISSUER/" \
	-X POST --data "$LOGIN" "$ISSUER/api/firstfactor" || fail "firstfactor request failed"
[ "$(jq -r '.status' "$WORK/login.json")" = "OK" ] \
	|| fail "firstfactor rejected the credentials: $(cat "$WORK/login.json")"
ok "authenticated as $USER"

# 3b. Authorization request. `resource` is RFC 8707 -- it is what makes the
# access token's audience the gateway rather than the client id.
STATE=$(openssl rand -hex 16)
NONCE=$(openssl rand -hex 16)
$CURL -b "$COOKIES" -c "$COOKIES" -o "$WORK/authz.body" -D "$WORK/authz.headers" \
	-G "$AUTHZ_EP" \
	--data-urlencode "client_id=$CLIENT_ID" \
	--data-urlencode "response_type=code" \
	--data-urlencode "response_mode=query" \
	--data-urlencode "scope=openid profile email groups" \
	--data-urlencode "redirect_uri=$REDIRECT_URI" \
	--data-urlencode "resource=$AUDIENCE" \
	--data-urlencode "state=$STATE" \
	--data-urlencode "nonce=$NONCE" || fail "authorization request failed"

LOCATION=$(awk 'tolower($1)=="location:"{print $2}' "$WORK/authz.headers" | tr -d '\r' | tail -1)
[ -n "$LOCATION" ] || fail "authorization endpoint returned no redirect:
$(cat "$WORK/authz.headers")
$(head -c 800 "$WORK/authz.body")"

case "$LOCATION" in
	*error=*) fail "authorization endpoint returned an error: $LOCATION" ;;
esac
CODE=$(printf '%s' "$LOCATION" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
[ -n "$CODE" ] || fail "no authorization code in the redirect: $LOCATION"
ok "authorization code obtained"

# 3c. Token exchange. The `resource` parameter is repeated here; Authelia
# narrows the granted audience at this step too.
$CURL -o "$WORK/token.json" -w '  HTTP %{http_code}\n' \
	-X POST "$TOKEN_EP" \
	--data-urlencode "grant_type=authorization_code" \
	--data-urlencode "code=$CODE" \
	--data-urlencode "redirect_uri=$REDIRECT_URI" \
	--data-urlencode "client_id=$CLIENT_ID" \
	--data-urlencode "client_secret=$CLIENT_SECRET" \
	--data-urlencode "resource=$AUDIENCE" || fail "token request failed"

jq -e '.access_token' "$WORK/token.json" >/dev/null \
	|| fail "no access_token in the response: $(cat "$WORK/token.json")"
ACCESS_TOKEN=$(jq -r '.access_token' "$WORK/token.json")
ok "token_type = $(jq -r '.token_type' "$WORK/token.json"), expires_in = $(jq -r '.expires_in' "$WORK/token.json")"

echo
echo "=== 4. the access token is a JWT, with the right audience and groups"
NSEG=$(printf '%s' "$ACCESS_TOKEN" | awk -F. '{print NF}')
[ "$NSEG" -eq 3 ] || fail "the access token is not a JWT -- it has $NSEG dot-separated segment(s), \
which means Authelia issued an opaque token. Check access_token_signed_response_alg on the client."
ok "three segments -- this is a JWT, not an opaque token"

printf '%s' "$ACCESS_TOKEN" | cut -d. -f1 | decode_segment | jq . >"$WORK/hdr.json"
printf '%s' "$ACCESS_TOKEN" | cut -d. -f2 | decode_segment | jq . >"$WORK/claims.json"

echo "--- access token header ---"
cat "$WORK/hdr.json"
echo "--- access token claims ---"
cat "$WORK/claims.json"

HDR_ALG=$(jq -r '.alg' "$WORK/hdr.json")
[ "$HDR_ALG" != none ] && [ "$HDR_ALG" != null ] || fail "access token alg is '$HDR_ALG'"
ok "alg = $HDR_ALG, kid = $(jq -r '.kid' "$WORK/hdr.json")"

KID=$(jq -r '.kid' "$WORK/hdr.json")
jq -e --arg k "$KID" '.keys[] | select(.kid == $k)' "$WORK/jwks.json" >/dev/null \
	|| fail "the token's kid '$KID' is not in the published JWKS"
ok "kid is present in the JWKS -- the gateway can resolve the signing key"

# Actually verify the RS256 signature with the published key, rather than
# stopping at "the kid exists". This is the step the gateway performs, and
# it is the one that would catch a JWKS serving a key that does not match
# the key the provider signs with.
JWK_N=$(jq -r --arg k "$KID" '.keys[] | select(.kid == $k) | .n' "$WORK/jwks.json")
JWK_E=$(jq -r --arg k "$KID" '.keys[] | select(.kid == $k) | .e' "$WORK/jwks.json")
cat >"$WORK/rsa.cnf" <<EOF
asn1=SEQUENCE:pubkeyinfo
[pubkeyinfo]
algorithm=SEQUENCE:rsa_alg
subjectPublicKey=BITWRAP,SEQUENCE:rsapubkey
[rsa_alg]
algorithm=OID:rsaEncryption
parameter=NULL
[rsapubkey]
n=INTEGER:0x$(printf '%s' "$JWK_N" | b64url_hex)
e=INTEGER:0x$(printf '%s' "$JWK_E" | b64url_hex)
EOF
openssl asn1parse -genconf "$WORK/rsa.cnf" -noout -out "$WORK/pub.der" \
	|| fail "could not rebuild an RSA public key from the JWKS entry"
openssl rsa -pubin -inform DER -in "$WORK/pub.der" -out "$WORK/pub.pem" 2>/dev/null \
	|| fail "the reconstructed JWKS key is not a usable RSA public key"

printf '%s.%s' "$(printf '%s' "$ACCESS_TOKEN" | cut -d. -f1)" \
	"$(printf '%s' "$ACCESS_TOKEN" | cut -d. -f2)" >"$WORK/signing_input"
printf '%s' "$ACCESS_TOKEN" | cut -d. -f3 | b64url_raw >"$WORK/sig.bin"
openssl dgst -sha256 -verify "$WORK/pub.pem" -signature "$WORK/sig.bin" \
	"$WORK/signing_input" >/dev/null \
	|| fail "the access token signature does NOT verify against the published JWKS key"
ok "RS256 signature verifies against the JWKS key"

jq -e --arg i "$ISSUER" '.iss == $i' "$WORK/claims.json" >/dev/null \
	|| fail "iss is $(jq -r '.iss' "$WORK/claims.json"), expected $ISSUER"
ok "iss = $ISSUER"

jq -e --arg a "$AUDIENCE" '
	(if (.aud | type) == "array" then .aud else [.aud] end) | index($a)
' "$WORK/claims.json" >/dev/null \
	|| fail "aud is $(jq -c '.aud' "$WORK/claims.json"), which does not contain $AUDIENCE.
The gateway enforces RFC 8707 audience validation and will reject this token."
ok "aud contains $AUDIENCE"

jq -e '(.groups | type) == "array" and (.groups | length) > 0' "$WORK/claims.json" >/dev/null \
	|| fail "no non-empty groups claim in the access token: $(jq -c '.groups' "$WORK/claims.json")"
ok "groups = $(jq -c '.groups' "$WORK/claims.json")"

echo
echo "=== 5. id_token claims (informational)"
if jq -e '.id_token' "$WORK/token.json" >/dev/null 2>&1; then
	jq -r '.id_token' "$WORK/token.json" | cut -d. -f2 | decode_segment | jq .
else
	echo "  (no id_token in the response)"
fi

echo
echo "ALL CHECKS PASSED for user '$USER'."
