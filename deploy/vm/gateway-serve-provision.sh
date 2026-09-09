#!/bin/sh
# Runs on the VM HOST (not inside a jail, not on the Mac). Driven by
# deploy/gateway-serve.sh, which stages this file and the binaries into
# $STAGE first.
#
# Brings `mcp-gateway serve` into existence inside the mcp-gateway-test
# jail: packages, Credential Vault, signing key, configuration, the four
# lab upstreams (registered AND signed), and the rc.d service. It does not
# start the service -- deploy/gateway-serve-verify.sh does that, because
# the service coming up is the first assertion of the acceptance test
# rather than a side effect of provisioning.
#
# Idempotent, and deliberately so in the direction that matters: it never
# regenerates a key or a secret that already exists. Re-rolling the age
# identity makes the existing secrets.json undecryptable; re-rolling the
# signing key invalidates every stored signature. Both look, hours later,
# like "the gateway suddenly refuses everything". To rotate either one,
# delete that specific file and re-run -- then re-sign every entry.
#
# Everything this writes lives inside the jail. Nothing generated here is
# copied back to the Mac, and no secret value is ever echoed.
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

# Paths as seen from INSIDE the jail.
ETC=/usr/local/etc/mcp-gateway
LIBEXEC=/usr/local/libexec/mcp-gateway
CONFIG="$ETC/config.toml"
AGE_KEY="$ETC/age.key"
SECRETS="$ETC/secrets.json"
SIGN_KEY="$ETC/signing.key"
SIGN_PUB="$ETC/signing.pub"
DBDIR=/var/db/mcp-gateway
GW=/usr/local/bin/mcp-gateway

# The unprivileged account the service runs as. rc.subr honours
# ${name}_user by wrapping the command in su(1), so the name in
# deploy/gateway-jail/mcp_gateway is not decoration -- without this account
# the service does not start at all ("su: unknown login: mcpgw").
#
# It gets /bin/sh rather than nologin for exactly that reason: su(1) execs
# the target account's shell, so a nologin shell makes rc.subr's own start
# path fail.
SVC_USER=mcpgw


j() { jexec "$GW_JAIL" /bin/sh -c "$1"; }
# Same, as the service account. Every Operator Console command runs through
# this rather than as root: `upstream register`, `sign` and `tool approve`
# all write the SQLite file the *service* has to write too, and SQLite in
# WAL mode creates -wal and -shm siblings owned by whoever wrote first. Run
# half of them as root and the service is left with a database directory it
# cannot write.
ju() { jexec -U "$SVC_USER" "$GW_JAIL" /bin/sh -c "$1"; }
say() { echo "==> $*"; }

# MOCKS and register_and_sign_upstreams. Shared with the verify script so
# the two cannot drift; see the header of that file.
. "$STAGE/gateway-upstreams.sh"

[ -d "$GW_JAIL_ROOT" ] || { echo "no such jail root: $GW_JAIL_ROOT" >&2; exit 2; }
jls -N | awk 'NR>1 {print $1}' | grep -qx "$GW_JAIL" \
	|| { echo "jail $GW_JAIL is not running" >&2; exit 2; }

# ---------------------------------------------------------------- packages
# sops and age are not Go dependencies of this module and never will be:
# ADR-0005 shells out to the sops CLI precisely to keep the AWS/GCP/Azure
# KMS SDKs out of the binary. That makes them a deployment prerequisite,
# installed here rather than assumed.
#
# curl and jq the gateway does not need at all. They are here for
# deploy/gateway-serve-verify.sh, which drives the MCP endpoint from inside
# this jail as one of its two clients.
say "packages: sops age curl jq"
j "pkg install -y sops age curl jq" 2>&1 | tail -2 | sed 's/^/    /'

# Stop first if it is already running: install(1) over a running binary
# is how a redeploy turns into a mystery, and the rc.d script runs the
# gateway under `daemon -r`, which would restart the half-written file.
j "service mcp_gateway stop >/dev/null 2>&1 || true"

# ------------------------------------------------------------ service user
if j "id -u $SVC_USER >/dev/null 2>&1"; then
	say "service user: $SVC_USER already exists"
else
	say "service user: creating $SVC_USER"
	j "pw useradd -n $SVC_USER -d /nonexistent -s /bin/sh -c 'mcp-gateway service account' -w no"
fi

# ------------------------------------------------------------- directories
# $ETC is root:$SVC_USER 0750 -- the service can READ its configuration,
# its age identity and its signing key, and cannot rewrite any of them.
# That split is deliberate: the process that holds every backend credential
# should not also be able to edit the trust anchor it is checked against.
#
# $DBDIR is owned by the service account, because SQLite must create -wal
# and -shm files beside the database.
say "directories"
j "install -d -o root -g $SVC_USER -m 0750 $ETC"
j "install -d -o root -g wheel  -m 0755 $LIBEXEC"
j "install -d -o $SVC_USER -g $SVC_USER -m 0750 $DBDIR"

# ---------------------------------------------------------------- binaries
say "binaries"
install -m 0755 "$STAGE/mcp-gateway" "$GW_JAIL_ROOT$GW"
for m in $MOCKS; do
	install -m 0755 "$STAGE/mock-$m" "$GW_JAIL_ROOT$LIBEXEC/lab-$m"
done
install -m 0555 "$STAGE/mcp_gateway" "$GW_JAIL_ROOT/usr/local/etc/rc.d/mcp_gateway"
j "$GW version" | sed 's/^/    /'

# ------------------------------------------------------------ age identity
# The one knowingly-accepted plaintext-on-disk exposure in this design
# (ADR-0003). age-keygen writes 0600 itself; the chmod is belt and braces
# against an umask that made it something else.
if j "[ -f $AGE_KEY ]"; then
	say "age identity: already present, left untouched"
else
	say "age identity: generating"
	j "umask 077 && age-keygen -o $AGE_KEY >/dev/null 2>&1"
fi
j "chown $SVC_USER:$SVC_USER $AGE_KEY && chmod 600 $AGE_KEY"
AGE_RECIPIENT=$(j "age-keygen -y $AGE_KEY")
[ -n "$AGE_RECIPIENT" ] || { echo "could not read the age recipient" >&2; exit 1; }
echo "    recipient: $AGE_RECIPIENT"

# ------------------------------------------------------------------- vault
# One fake credential per backend, plus the MOCK_SECRET/MOCK_EXPECT pair
# the mocks themselves compare (lab/mockutil/credcheck.go). Values are
# generated inside the jail by openssl(1), piped straight into sops through
# /dev/stdin, and never touch the disk in cleartext, never appear in a log,
# and never leave the VM.
#
# MOCK_EXPECT is set from the same shell variable as MOCK_SECRET rather
# than from a second `openssl rand`: two random values would never be
# equal, every credcheck would report a mismatch, and that reads exactly
# like broken credential injection.
if j "[ -f $SECRETS ]"; then
	say "vault: $SECRETS already present, left untouched"
else
	say "vault: generating secrets and encrypting with sops"
	j "umask 077 && MS=lab-\$(openssl rand -hex 16) && \
		jq -n --arg ms \"\$MS\" \
			--arg casemgmt \"casemgmt-TOK-\$(openssl rand -hex 12)\" \
			--arg gl \"gl-TOK-\$(openssl rand -hex 12)\" \
			--arg os \"os-PWD-\$(openssl rand -hex 12)\" \
			--arg vt \"vt-KEY-\$(openssl rand -hex 12)\" \
			'{MOCK_SECRET:\$ms, MOCK_EXPECT:\$ms, CASEMGMT_API_TOKEN:\$casemgmt,
			  LOGSEARCH_API_TOKEN:\$gl, DOCSEARCH_PASSWORD:\$os, THREATINTEL_VT_KEY:\$vt}' \
		| sops --encrypt --age '$AGE_RECIPIENT' --input-type json --output-type json /dev/stdin \
		>$SECRETS.tmp && mv $SECRETS.tmp $SECRETS"
	j "chmod 640 $SECRETS"
fi
j "chown root:$SVC_USER $SECRETS && chmod 640 $SECRETS"
# Prove the vault round-trips before anything depends on it. Only the KEY
# names are printed -- keeping the values out of a terminal is the entire
# point of the component.
say "vault: decrypt check (key names only)"
j "SOPS_AGE_KEY_FILE=$AGE_KEY sops --decrypt --input-type json --output-type json $SECRETS | jq -r 'keys[]'" \
	| sed 's/^/    /'

# ------------------------------------------------------------- signing key
# ADR-0010: `sign -generate-key` reads no configuration file, because the
# config is invalid until it names a trusted key and there is no key until
# this runs. It prints the trusted_keys line and deliberately does not
# write it anywhere -- a command that granted itself trust would be the
# exact hole the anchor exists to close. Substituting it into the config is
# this script's job, in a file a reviewer can read.
#
# The public half is cached in $SIGN_PUB so a re-run can rebuild the config
# without regenerating the key. It is a public key: not a secret, which is
# why it can sit in a plain file at all.
if j "[ -f $SIGN_KEY ]"; then
	say "signing key: already present, left untouched"
	j "[ -f $SIGN_PUB ]" || {
		echo "  $SIGN_KEY exists but $SIGN_PUB does not." >&2
		echo "  The public half cannot be recovered here: -generate-key refuses to" >&2
		echo "  overwrite the private key, by design. Copy the base64 out of the" >&2
		echo "  trusted_keys line already in $CONFIG into $SIGN_PUB, or rotate" >&2
		echo "  deliberately -- see deploy/gateway-serve.md." >&2
		exit 1
	}
else
	say "signing key: generating (mcp-gateway sign -generate-key)"
	j "umask 077 && $GW sign -generate-key -out $SIGN_KEY" >"$STAGE/genkey.out"
	sed 's/^/    /' "$STAGE/genkey.out"
	# The pasteable line is:      "<44 chars of base64>",  # <fingerprint>
	grep -o '"[A-Za-z0-9+/]\{42,\}=\{0,2\}"' "$STAGE/genkey.out" | tr -d '"' | head -1 \
		>"$GW_JAIL_ROOT$SIGN_PUB"
	rm -f "$STAGE/genkey.out"
	j "chmod 644 $SIGN_PUB"
fi
# Owned by the service account and 0600: `mcp-gateway sign` runs as that
# account (see ju above) and LoadKey refuses a group- or world-readable
# key file outright.
j "chown $SVC_USER:$SVC_USER $SIGN_KEY && chmod 600 $SIGN_KEY"
TRUSTED_KEY=$(j "cat $SIGN_PUB")
case "$TRUSTED_KEY" in
	"" | *" "*) echo "could not read exactly one trusted key from $SIGN_PUB" >&2; exit 1 ;;
esac
echo "    trusted key: $TRUSTED_KEY"

# ----------------------------------------------------------- configuration
# The template carries every role's tool list, each name read out of
# lab/servers/*/main.go rather than guessed. Only __TRUSTED_KEY__ is
# substituted: a config generator that also invented role names would be a
# second place for the silent-empty-tool-list bug to live.
say "configuration: $CONFIG"
sed "s|__TRUSTED_KEY__|$TRUSTED_KEY|" "$STAGE/config.toml.template" >"$GW_JAIL_ROOT$CONFIG.tmp"
# Comment lines are excluded on purpose: the template's own header explains
# the __LIKE_THIS__ convention and would otherwise trip this check forever.
if grep -vE '^[[:space:]]*#' "$GW_JAIL_ROOT$CONFIG.tmp" | grep -q '__[A-Z][A-Z0-9_]*__'; then
	echo "the rendered config still contains an unsubstituted __PLACEHOLDER__" >&2
	grep -nvE '^[[:space:]]*#' "$GW_JAIL_ROOT$CONFIG.tmp" | grep '__[A-Z][A-Z0-9_]*__' >&2
	rm -f "$GW_JAIL_ROOT$CONFIG.tmp"
	exit 1
fi
mv "$GW_JAIL_ROOT$CONFIG.tmp" "$GW_JAIL_ROOT$CONFIG"
chmod 644 "$GW_JAIL_ROOT$CONFIG"

# --------------------------------------------------------------- upstreams
say "upstreams: register and sign"
# The database may predate the service account (an earlier provisioning run
# as root). Hand it over before the console writes to it as $SVC_USER.
j "chown -R $SVC_USER:$SVC_USER $DBDIR"
register_and_sign_upstreams

# ------------------------------------------------------------------- nginx
# nginx was already installed and running in this jail before this script
# existed. Its configuration is reinstalled here anyway, because the
# `proxy_set_header Host 127.0.0.1:8080` line in it is load-bearing (see
# the comment in deploy/gateway-jail/nginx.conf) and a deployment where
# that line lives only in somebody's shell history is not a deployment.
#
# Reloaded, not restarted, and only after nginx -t: a bad config that
# restarts is an outage, a bad config that fails -t is a message.
if j "[ -f /usr/local/etc/nginx/nginx.conf ]"; then
	say "nginx: installing config and reloading"
	install -m 0644 "$STAGE/nginx.conf" "$GW_JAIL_ROOT/usr/local/etc/nginx/nginx.conf"
	j "nginx -t" 2>&1 | sed 's/^/    /'
	if j "service nginx status >/dev/null 2>&1"; then
		j "service nginx reload" | sed 's/^/    /'
	else
		j "service nginx start" | sed 's/^/    /'
	fi
else
	echo "    nginx is not installed in this jail -- skipping (see deploy/gateway-serve.md)"
fi

# ----------------------------------------------------------------- service
say "service: enabling mcp_gateway in the jail's rc.conf"
j "sysrc mcp_gateway_enable=YES" | sed 's/^/    /'

say "provisioned. Start and verify with deploy/gateway-serve-verify.sh"
