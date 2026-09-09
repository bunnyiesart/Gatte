#!/bin/sh
# Runs on the VM HOST. Driven by deploy/gateway-serve-verify.sh.
#
# The acceptance test for "the gateway actually runs". Provisioning is not
# the deliverable; this is. It starts the service through rc.d -- not by
# hand, so the service path is what gets tested -- and then proves, by
# measurement rather than by reading a config file:
#
#   1. serve came up: loopback bind, require_signed on, a non-empty trust
#      anchor;
#   2. all four upstreams connected and their tools were discovered;
#   3. those tools begin QUARANTINED, and an analyst really does see an
#      empty list until an operator approves them;
#   4. the vault reached the upstream processes (variable names only);
#   5. a real Authelia token gets a real tool list through TLS -> nginx ->
#      gateway, and a real tool call gets real data back;
#   6. no token is 401, a garbage token is 401, and `analyst` can neither
#      see nor call a tool only `dfir-lead` has;
#   7. the Audit Trail recorded all of it;
#   8. no credential from the vault appears in any log.
#
# The client is the VM HOST, not the jail: the request crosses socbr0 and
# arrives at 10.17.90.10:443 the way an analyst's would over the VPN. A
# curl from inside the jail would exercise the same nginx but would prove
# nothing about reachability.
#
# Exits non-zero on the first failed assertion. Read the output; do not
# read the exit code alone.
set -eu

# NOT named JAIL, and this is not fussiness. /usr/sbin/service reads $JAIL
# from its environment -- that is where its own -j flag lands and it is
# never unset -- and re-execs itself as `jexec -l "$JAIL" service ...`. So
# a script that exports JAIL and then runs `service` INSIDE that jail makes
# service look for a nested jail of the same name, which does not exist:
#
#   jexec: jail "mcp-gateway-test" not found
#
# Only the `service` calls fail; every other jexec in the same script works,
# which makes it look like an intermittent jail bug rather than an exported
# variable. Cost an hour once. GW_JAIL is invisible to service(8).
GW_JAIL="${GW_JAIL:-mcp-gateway-test}"
STAGE="${STAGE:-/tmp/mcp-gateway-deploy}"
GW_JAIL_ROOT="/usr/local/bastille/jails/$GW_JAIL/root"

ETC=/usr/local/etc/mcp-gateway
CONFIG="$ETC/config.toml"
GW=/usr/local/bin/mcp-gateway
SVC_USER=mcpgw
LOG=/var/log/mcp-gateway/mcp-gateway.log
NGINX_ACCESS=/var/log/nginx/mcp-access.log
NGINX_ERROR=/var/log/nginx/mcp-error.log
DBDIR=/var/db/mcp-gateway
LIBEXEC=/usr/local/libexec/mcp-gateway

CA=/usr/local/etc/soc-ca/ca.crt
ENDPOINT="https://mcp.soc.internal/"

WORK=$(mktemp -d /tmp/gateway-verify.XXXXXX)
trap 'rm -rf "$WORK"' EXIT INT TERM

j()  { jexec "$GW_JAIL" /bin/sh -c "$1"; }
ju() { jexec -U "$SVC_USER" "$GW_JAIL" /bin/sh -c "$1"; }
ok()   { echo "  ok  -- $*"; }
fail() { echo; echo "FAIL: $*" >&2; exit 1; }
head2() { echo; echo "== $*"; }

# MOCKS and register_and_sign_upstreams, shared with the provisioning
# script so the registered command and -env list cannot drift between the
# thing that installs the gateway and the thing that tests it.
. "$STAGE/gateway-upstreams.sh"

# curl(1) and jq(1) are the client here, and FreeBSD's base system has
# neither. fetch(8) cannot set an Authorization header, which is the one
# thing every request below needs.
command -v curl >/dev/null 2>&1 && command -v jq >/dev/null 2>&1 \
	|| pkg install -y curl jq >/dev/null

# ---------------------------------------------------------------------------
head2 "0. re-baseline, then restart mcp_gateway through rc.d"
# The database is rebuilt from scratch on every run, and that is the only
# way step 3 below means anything: Tool Quarantine remembers approvals, so
# a second run against yesterday's database would find every tool already
# approved and the "tools begin quarantined" assertion would pass by
# accident, or fail for the wrong reason.
#
# What this destroys is worth naming rather than burying: the tool
# approvals AND the audit trail. That is defensible here because this is an
# acceptance test on a lab jail whose registry is rebuilt deterministically
# two lines further down -- and it would be indefensible on anything real,
# where the trail is the record of who called what.
j "service mcp_gateway stop >/dev/null 2>&1 || true"
j "rm -f $LOG $DBDIR/mcp-gateway.db $DBDIR/mcp-gateway.db-wal $DBDIR/mcp-gateway.db-shm"
echo "  registry rebuilt:"
register_and_sign_upstreams >/dev/null
ju "$GW upstream list -config $CONFIG" | sed -n '1,6p' | sed 's/^/    /'

# Through service(8), deliberately. Starting the binary by hand would skip
# the su(1) to the service account, the minimal PATH, the SSL_CERT_FILE and
# the pidfile arrangement -- every one of which broke the first time this
# was tried, and none of which a hand-run would have found.
j "service mcp_gateway start"
# The gateway spawns four stdio upstreams and completes OIDC discovery
# before it serves; a poll is honest about that, a fixed sleep would be a
# guess that gets copied.
i=0
while [ "$i" -lt 30 ]; do
	if j "grep -q 'mcp-gateway: serving' $LOG 2>/dev/null"; then break; fi
	sleep 1
	i=$((i + 1))
done
j "grep -q 'mcp-gateway: serving' $LOG" \
	|| fail "the gateway did not reach 'serving' in ${i}s. Its log follows:
$(j "cat $LOG" 2>&1 | tail -20)"
ok "service is up (${i}s)"

# ---------------------------------------------------------------------------
head2 "1. the startup log"
j "cat $LOG" | sed 's/^/  /'

j "grep -q 'listen=127.0.0.1:8080' $LOG" \
	|| fail "the log does not report listen=127.0.0.1:8080"
ok "listen=127.0.0.1:8080"

j "grep -q 'require_signed=true' $LOG" \
	|| fail "require_signed is not true. It is never to be turned off to make something work."
ok "require_signed=true"

TRUSTED=$(j "grep -o 'trusted_keys=[0-9]*' $LOG | head -1 | cut -d= -f2")
[ -n "$TRUSTED" ] && [ "$TRUSTED" -gt 0 ] 2>/dev/null \
	|| fail "trusted_keys is '$TRUSTED' -- with require_signed on and no trust anchor the gateway serves nothing"
ok "trusted_keys=$TRUSTED (non-zero: signatures are checked against something)"

# The socket, not the log line about the socket. This jail is a VNET jail
# with a private loopback (deploy/gateway-vnet.md); in the classic jail it
# used to be, this bind was rewritten to the routable address and the
# reassuring log line above was a lie.
j "sockstat -4 -l | grep -q '127.0.0.1:8080'" \
	|| fail "nothing is listening on 127.0.0.1:8080 inside the jail"
ok "sockstat confirms the listener is on the jail's own 127.0.0.1:8080"

# ---------------------------------------------------------------------------
head2 "2. upstreams and tools -- the startup summary"
j "grep 'mcp-gateway: serving' $LOG" | sed 's/^/  /'

CONNECTED=$(j "grep -o 'upstreams_connected=[0-9]*' $LOG | head -1 | cut -d= -f2")
FAILED=$(j "grep -o 'upstreams_failed=[0-9]*' $LOG | head -1 | cut -d= -f2")
DISCOVERED=$(j "grep -o 'tools_discovered=[0-9]*' $LOG | head -1 | cut -d= -f2")
[ "$CONNECTED" = 4 ] || fail "only $CONNECTED of 4 upstreams connected"
[ "$FAILED" = 0 ] || fail "$FAILED upstreams failed to come up"
ok "4 upstreams connected, 0 failed"
[ "$DISCOVERED" -ge 12 ] 2>/dev/null || fail "only $DISCOVERED tools discovered, expected 12"
ok "$DISCOVERED tools discovered"

echo "  the four upstream processes, as seen by the jail:"
j "ps -axo user,pid,command | grep -E 'lab-(casemgmt|logsearch|docsearch|threatintel)' | grep -v grep" \
	| sed 's/^/    /'

echo "  the registry, with signature state:"
ju "$GW upstream list -config $CONFIG" | sed 's/^/    /'

# ---------------------------------------------------------------------------
head2 "3. Tool Quarantine -- BEFORE approval"
# Quarantined-on-first-sight is the design (ADR-0007), not a fault. A tool
# an operator has never looked at is exactly the tool a poisoned upstream
# would have just added.
ju "$GW tool list -config $CONFIG" | sed 's/^/  /'
PENDING=$(ju "$GW tool list -config $CONFIG -json" | jq '[.[]|select(.usable==false)]|length')
USABLE=$(ju "$GW tool list -config $CONFIG -json" | jq '[.[]|select(.usable==true)]|length')
[ "$PENDING" -ge 12 ] || fail "expected at least 12 tools awaiting approval, found $PENDING"
[ "$USABLE" = 0 ] || fail "$USABLE tools are already usable -- this run cannot show the before/after"
ok "12 pending, 0 usable: every tool starts quarantined"

# ---------------------------------------------------------------------------
head2 "4. the Credential Vault reached the upstream processes"
# Variable NAMES only. procstat -e would print the values, which is the one
# thing this project's whole vault design exists to prevent, so the values
# are cut off before anything is printed.
#
# What this proves is narrow and worth stating: the gateway resolved each
# name through sops+age and handed it to the child. It does NOT prove the
# child received the value the operator intended -- the *_credcheck tools
# exist for that and are deliberately granted to no role, so they cannot be
# called through the gateway at all.
for m in casemgmt logsearch docsearch threatintel; do
	pid=$(j "pgrep -f /usr/local/libexec/mcp-gateway/lab-$m | head -1")
	[ -n "$pid" ] || fail "the $m mock is not running"
	names=$(j "procstat -e $pid" | tr ' ' '\n' | sed -n 's/=.*//p' | grep -v '^$' | sort | tr '\n' ' ')
	echo "    $m [$pid]: $names"
	case "$names" in
		*MOCK_SECRET*) : ;;
		*) fail "$m did not receive MOCK_SECRET" ;;
	esac
done
ok "each upstream got MOCK_SECRET plus its own per-backend credential, and PATH/HOME -- nothing else"
ok "the child environment is BUILT, not inherited: no stray variable from the gateway's own env"

# ---------------------------------------------------------------------------
head2 "5. a real token from Authelia"
TOKEN_ANALYST=$(sh "$STAGE/gateway-token.sh" analyst) || fail "could not get a token for analyst"
TOKEN_DFIR=$(sh "$STAGE/gateway-token.sh" dfirlead)  || fail "could not get a token for dfirlead"
ok "authorization-code flow completed for analyst and dfirlead"

decode() { # base64url JWT payload -> JSON on stdout
	printf '%s' "$1" | cut -d. -f2 | tr -- '-_' '+/' \
		| awk '{n=length($0)%4; printf "%s%s", $0, (n==2?"==":n==3?"=":"")}' \
		| openssl base64 -d -A
}
echo "  analyst claims:"
decode "$TOKEN_ANALYST" | jq -c '{iss,aud,groups,preferred_username}' | sed 's/^/    /'
echo "  dfirlead claims:"
decode "$TOKEN_DFIR" | jq -c '{iss,aud,groups,preferred_username}' | sed 's/^/    /'

# --------------------------------------------------------------- MCP client
# One POST per call. The gateway's MCP handler is Stateless (ADR-0008: a
# session id must never stand in for authentication), so there is no
# handshake to keep alive and every request carries its own bearer token --
# which is exactly what makes the negative tests below meaningful.
mcp() { # $1 = bearer token or "" ; $2 = JSON-RPC body -> prints HTTP status
	if [ -n "$1" ]; then
		curl -sS --cacert "$CA" -o "$WORK/resp" -D "$WORK/resp.h" -w '%{http_code}' \
			-H 'Content-Type: application/json' \
			-H 'Accept: application/json, text/event-stream' \
			-H "Authorization: Bearer $1" \
			-X POST --data "$2" "$ENDPOINT"
	else
		curl -sS --cacert "$CA" -o "$WORK/resp" -D "$WORK/resp.h" -w '%{http_code}' \
			-H 'Content-Type: application/json' \
			-H 'Accept: application/json, text/event-stream' \
			-X POST --data "$2" "$ENDPOINT"
	fi
}
# The response is server-sent events when the SDK streams and plain JSON
# when it does not; both shapes are unwrapped here so the assertions below
# do not have to care which one arrived.
mcp_body() {
	if head -c1 "$WORK/resp" | grep -q '{'; then
		cat "$WORK/resp"
	else
		sed -n 's/^data: //p' "$WORK/resp" | head -1
	fi
}

TOOLS_LIST='{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'

head2 "6. an approved-nothing gateway serves an empty tool list"
STATUS=$(mcp "$TOKEN_ANALYST" "$TOOLS_LIST")
[ "$STATUS" = 200 ] || fail "tools/list returned HTTP $STATUS, expected 200:
$(cat "$WORK/resp")"
N=$(mcp_body | jq '.result.tools | length')
[ "$N" = 0 ] || fail "analyst can already see $N tools before any approval"
ok "HTTP 200 through TLS -> nginx -> gateway, and the tool list is EMPTY"
ok "the quarantine gate is live, not just a column in a table"

# ---------------------------------------------------------------------------
head2 "7. approve the eight domain tools"
# The four *_credcheck tools are deliberately left pending. No role grants
# them (they would let a caller ask a backend to describe the credential it
# was handed), and leaving them unapproved keeps both gates visible: policy
# does not grant them AND quarantine has not released them.
for pair in "casemgmt list_cases" "casemgmt get_case" \
	"logsearch search_relative" "logsearch search_keyword" \
	"docsearch docsearch_search" "docsearch docsearch_list_indices" \
	"threatintel lookup_ip" "threatintel enrich"; do
	# shellcheck disable=SC2086
	ju "$GW tool approve -config $CONFIG $pair" >/dev/null \
		|| fail "could not approve $pair"
	echo "    approved $pair"
done

head2 "8. Tool Quarantine -- AFTER approval"
ju "$GW tool list -config $CONFIG" | sed 's/^/  /'
USABLE=$(ju "$GW tool list -config $CONFIG -json" | jq '[.[]|select(.usable==true)]|length')
STILL=$(ju "$GW tool list -config $CONFIG -json" | jq '[.[]|select(.usable==false)]|length')
[ "$USABLE" = 8 ] || fail "expected 8 usable tools after approval, found $USABLE"
ok "8 usable, $STILL still pending (the *_credcheck fixtures, on purpose)"

# ---------------------------------------------------------------------------
head2 "9. THE HEADLINE: tools/list over TLS, through nginx, with a real token"
STATUS=$(mcp "$TOKEN_ANALYST" "$TOOLS_LIST")
[ "$STATUS" = 200 ] || fail "tools/list returned HTTP $STATUS:
$(cat "$WORK/resp")"
mcp_body | jq -r '.result.tools[].name' >"$WORK/analyst.tools"
echo "  analyst sees:"
sed 's/^/    /' "$WORK/analyst.tools"
ANALYST_N=$(wc -l <"$WORK/analyst.tools" | tr -d ' ')
[ "$ANALYST_N" = 6 ] || fail "analyst sees $ANALYST_N tools, expected the 6 its role grants"
ok "HTTP 200, 6 tools -- the analyst role's exact grant"

echo "  and a real call, casemgmt.list_cases:"
STATUS=$(mcp "$TOKEN_ANALYST" \
	'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"casemgmt.list_cases","arguments":{}}}')
[ "$STATUS" = 200 ] || fail "tools/call returned HTTP $STATUS:
$(cat "$WORK/resp")"
mcp_body | jq -r '.result.content[0].text' | jq -c '.' | sed 's/^/    /'
mcp_body | jq -e '.result.content[0].text | fromjson | .cases | length > 0' >/dev/null \
	|| fail "casemgmt.list_cases returned no cases"
ok "a tool call reached the upstream process and came back with data"

# ---------------------------------------------------------------------------
head2 "10. negative: no token"
STATUS=$(mcp "" "$TOOLS_LIST")
[ "$STATUS" = 401 ] || fail "an unauthenticated request got HTTP $STATUS, expected 401"
ok "HTTP 401"
grep -i '^www-authenticate:' "$WORK/resp.h" | sed 's/^/    /' \
	|| fail "a 401 with no WWW-Authenticate sends a compliant client nowhere"
ok "WWW-Authenticate points the client at the resource metadata (RFC 9728)"

head2 "11. negative: a garbage token"
STATUS=$(mcp "not-a-jwt.at-all.nope" "$TOOLS_LIST")
[ "$STATUS" = 401 ] || fail "a garbage token got HTTP $STATUS, expected 401"
ok "HTTP 401"
echo "    body: $(head -c 200 "$WORK/resp")"

# A token that IS a well-formed JWT but signed by nobody the gateway
# trusts. Without this, "garbage is rejected" could just mean "the parser
# choked", which is a much weaker statement than "the signature is checked".
FORGED=$(printf '%s' '{"alg":"RS256","kid":"main","typ":"at+jwt"}' | openssl base64 -A | tr -d '=' | tr '+/' '-_')
FORGED="$FORGED.$(printf '%s' '{"iss":"https://id.soc.internal","aud":["https://mcp.soc.internal/"],"sub":"analyst","groups":["dfir-leads"],"exp":9999999999}' | openssl base64 -A | tr -d '=' | tr '+/' '-_').ZmFrZXNpZ25hdHVyZQ"
STATUS=$(mcp "$FORGED" "$TOOLS_LIST")
[ "$STATUS" = 401 ] || fail "a well-formed but unsigned JWT claiming dfir-leads got HTTP $STATUS, expected 401"
ok "HTTP 401 for a well-formed JWT with a bogus signature claiming dfir-leads"

# ---------------------------------------------------------------------------
head2 "12. negative: analyst must not reach a dfir-lead-only tool"
# The control first, for the same reason deploy/gateway-vnet.md's step 3
# exists: without it, "analyst cannot see threatintel.enrich" would pass just as
# happily on a gateway where threatintel.enrich does not exist at all.
STATUS=$(mcp "$TOKEN_DFIR" "$TOOLS_LIST")
[ "$STATUS" = 200 ] || fail "dfirlead tools/list returned HTTP $STATUS"
mcp_body | jq -r '.result.tools[].name' >"$WORK/dfir.tools"
echo "  dfirlead sees:"
sed 's/^/    /' "$WORK/dfir.tools"
grep -qx 'threatintel.enrich' "$WORK/dfir.tools" \
	|| fail "threatintel.enrich is not visible to dfirlead either -- the test below would be vacuous"
grep -qx 'docsearch.docsearch_list_indices' "$WORK/dfir.tools" \
	|| fail "docsearch.docsearch_list_indices is not visible to dfirlead either"
ok "control: dfirlead sees threatintel.enrich and docsearch.docsearch_list_indices"

grep -qx 'threatintel.enrich' "$WORK/analyst.tools" \
	&& fail "analyst can SEE threatintel.enrich, which only dfir-lead grants"
grep -qx 'docsearch.docsearch_list_indices' "$WORK/analyst.tools" \
	&& fail "analyst can SEE docsearch.docsearch_list_indices"
ok "analyst's list contains neither"

# Seeing is not the control; calling is. A client that never lists can
# still POST a name it guessed.
STATUS=$(mcp "$TOKEN_ANALYST" \
	'{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"threatintel.enrich","arguments":{"ip":"8.8.8.8"}}}')
echo "    HTTP $STATUS, body: $(mcp_body | head -c 300)"
if mcp_body | jq -e '.result.content[0].text | fromjson | .virustotal' >/dev/null 2>&1; then
	fail "analyst CALLED threatintel.enrich and got real data back"
fi
ok "analyst calling threatintel.enrich by name is refused, not merely hidden from the list"

# ---------------------------------------------------------------------------
head2 "13. the Audit Trail recorded it"
ju "$GW audit -config $CONFIG -limit 15" | sed 's/^/  /'
ju "$GW audit -config $CONFIG -json" >"$WORK/audit.json"
jq -e '[.[]|select(.tool=="casemgmt.list_cases" and .outcome=="allowed")]|length > 0' \
	"$WORK/audit.json" >/dev/null || fail "no allowed record for casemgmt.list_cases"
ok "an 'allowed' record exists for casemgmt.list_cases"
jq -e '[.[]|select(.tool=="threatintel.enrich" and .outcome=="denied")]|length > 0' \
	"$WORK/audit.json" >/dev/null || fail "no denied record for the analyst's threatintel.enrich attempt"
ok "a 'denied' record exists for threatintel.enrich"
echo "  the analyst identity the trail recorded:"
jq -r '[.[]|select(.tool=="threatintel.enrich")][0] | "    analyst=\(.analyst_identity) tool=\(.tool) outcome=\(.outcome) reason=\(.reason)"' \
	"$WORK/audit.json"

# ---------------------------------------------------------------------------
head2 "14. no credential from the vault appears in any log"
# Every value in the vault, searched for as a fixed string in the gateway's
# log and in both of nginx's. Only the KEY NAMES are ever printed -- a leak
# check that echoes what it is looking for has created the leak it was
# testing for.
#
# The files searched are named explicitly rather than globbed, so the
# report says what was actually covered.
echo "  files searched (inside the jail):"
echo "    $LOG"
echo "    $NGINX_ACCESS"
echo "    $NGINX_ERROR"
echo "  vault keys searched for (values never printed):"
j "SOPS_AGE_KEY_FILE=$ETC/age.key sops --decrypt --input-type json --output-type json $ETC/secrets.json" \
	>"$WORK/plain.json"
LEAKED=0
for k in $(jq -r 'keys[]' "$WORK/plain.json"); do
	v=$(jq -r --arg k "$k" '.[$k]' "$WORK/plain.json")
	# The value is passed to the jail on the command line of a grep. That
	# is visible in ps(1) for an instant on a machine where root is the
	# only user and the value is a lab fake; it is the price of grepping
	# for it at all, and it is named here rather than glossed over.
	if j "grep -F -l -e '$v' $LOG $NGINX_ACCESS $NGINX_ERROR 2>/dev/null"; then
		echo "    LEAKED: $k"
		LEAKED=1
	else
		echo "    clean:  $k"
	fi
done
[ "$LEAKED" = 0 ] || fail "a vault value appears in a log"
ok "no vault value appears in the gateway log or in either nginx log"

# The bearer token is not a vault secret, but it is a credential and it
# goes through nginx on every request, so it gets the same treatment.
if j "grep -F -q -e '$(printf '%s' "$TOKEN_ANALYST" | cut -c1-40)' $NGINX_ACCESS $LOG 2>/dev/null"; then
	fail "the analyst's bearer token appears in a log"
fi
ok "the analyst's bearer token does not appear in a log either"

echo
echo "ALL CHECKS PASSED."
