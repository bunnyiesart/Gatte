# Shared by gatte-entrypoint and gatte (design/adr/0049). POSIX sh: the
# image's shell is busybox ash.
#
# Every path and URL the container uses is derived here from four .env
# values, so the entrypoint, the operator's commands, the generated
# configuration files and the compose file cannot disagree about them.

set -eu

GATTE_ETC=/etc/gatte
GATTE_SITE=$GATTE_ETC/site          # the host's deploy/docker/config/
GATTE_KEYS=$GATTE_ETC/keys
GATTE_CA=$GATTE_ETC/ca
GATTE_DATA=/var/lib/gatte
GATTE_EDGE=/etc/gatte-edge          # what Caddy reads: Caddyfile, certificate
AUTHELIA_ETC=/etc/authelia
TEMPLATES=/usr/local/share/gatte/templates

CONFIG=$GATTE_ETC/config.toml
BASE=$GATTE_ETC/base.toml
SIGNING_KEY=$GATTE_KEYS/signing.key
SIGNING_PUB=$GATTE_KEYS/signing.pub
AGE_KEY=$GATTE_ETC/age.key
VAULT=$GATTE_ETC/secrets.json
USERS_FILE=$AUTHELIA_ETC/users_database.yml
BOOTSTRAP_USER=gatte-bootstrap      # disabled; see cmd_init

RUN_DIR=/run/gatte
OPERATOR_SOCKET=$RUN_DIR/op/operator.sock
ACCOUNTS_SOCKET=$RUN_DIR/accounts/accounts.sock

SERVICE_USER=gatte
SERVICE_HOME=$GATTE_DATA

die() {
	printf 'gatte: %s\n' "$*" >&2
	exit 1
}

say() {
	printf '%s\n' "$*"
}

# derive computes every URL from GATTE_DOMAIN and GATTE_PORT. The port is
# part of every URL when it is not 443, because the issuer and the audience
# are compared as strings: a client that reached https://auth.D:8443 must be
# handed an issuer that says :8443.
derive() {
	: "${GATTE_DOMAIN:=}"
	[ -n "$GATTE_DOMAIN" ] || die "GATTE_DOMAIN is not set: copy .env.example to .env and set it"
	case "$GATTE_DOMAIN" in
	*.*) ;;
	*) die "GATTE_DOMAIN=$GATTE_DOMAIN needs at least one dot: Authelia sets its session cookie on it" ;;
	esac
	case "$GATTE_DOMAIN" in
	*[!A-Za-z0-9.-]*) die "GATTE_DOMAIN=$GATTE_DOMAIN is not a host name" ;;
	esac
	GATTE_PORT=${GATTE_PORT:-443}
	case "$GATTE_PORT" in
	'' | *[!0-9]*) die "GATTE_PORT=$GATTE_PORT is not a port number" ;;
	esac
	GATTE_TLS=${GATTE_TLS:-internal}
	case "$GATTE_TLS" in
	internal) ;;
	acme)
		[ "$GATTE_PORT" = 443 ] || die "GATTE_TLS=acme needs GATTE_PORT=443: a public CA validates on 443 and 80"
		[ -n "${GATTE_ACME_EMAIL:-}" ] || die "GATTE_TLS=acme needs GATTE_ACME_EMAIL"
		;;
	*) die "GATTE_TLS=$GATTE_TLS: use internal (a private CA this container makes) or acme (a public certificate)" ;;
	esac
	if [ "$GATTE_PORT" = 443 ]; then sfx=; else sfx=:$GATTE_PORT; fi
	IDP_HOST=auth.$GATTE_DOMAIN
	GW_URL=https://$GATTE_DOMAIN$sfx
	AUDIENCE=$GW_URL/
	IDP_URL=https://$IDP_HOST$sfx
	ISSUER=$IDP_URL
	GW_SITE=$GATTE_DOMAIN$sfx
	IDP_SITE=$IDP_HOST$sfx
}

# as_service runs a command as the service account, which owns the
# database: an operator command run as root would leave root-owned files
# the gateway cannot write.
as_service() {
	su-exec "$SERVICE_USER" env HOME="$SERVICE_HOME" "$@"
}

# mcp runs an mcp-gateway operator command as the service account, with
# -config placed right after the command words (Go's flag parsing stops at
# the first positional argument, so it cannot go at the end).
mcp() {
	case "$1" in
	upstream | tool | access | maintenance | quota)
		w1=$1 w2=$2
		shift 2
		as_service mcp-gateway "$w1" "$w2" -config "$CONFIG" "$@"
		;;
	*)
		w1=$1
		shift
		as_service mcp-gateway "$w1" -config "$CONFIG" "$@"
		;;
	esac
}

# assemble writes config.toml from base.toml and the operator's site files.
# root-owned and group-readable by the service: the gateway reads its policy
# and cannot change it (README, "Who owns what").
assemble_config() {
	[ -s "$BASE" ] || die "$BASE is missing: the first run (the init service) has not completed"
	[ -s "$GATTE_SITE/roles.toml" ] || install -m 0644 "$TEMPLATES/roles.toml" "$GATTE_SITE/roles.toml"
	tmp=$CONFIG.new
	{
		cat "$BASE"
		printf '\n# ---- config/roles.toml ----\n'
		cat "$GATTE_SITE/roles.toml"
		if [ -s "$GATTE_SITE/extra.toml" ]; then
			printf '\n# ---- config/extra.toml ----\n'
			cat "$GATTE_SITE/extra.toml"
		fi
	} >"$tmp"
	chown root:"$SERVICE_USER" "$tmp"
	chmod 0640 "$tmp"
	mv "$tmp" "$CONFIG"
}

# api_call METHOD SOCKET PATH [JSON] talks to the management API over its
# UNIX socket (design/adr/0040). The peer is root, which both sockets accept.
api_call() {
	method=$1 sock=$2 path=$3
	shift 3
	[ -S "$sock" ] || die "the management API socket $sock is not there: is the gatte service running?"
	if [ $# -gt 0 ]; then
		curl -sS --unix-socket "$sock" -X "$method" -H 'Gatte-Front: docker' \
			-H 'Content-Type: application/json' --data-binary "$1" "http://gatte$path"
	else
		curl -sS --unix-socket "$sock" -X "$method" -H 'Gatte-Front: docker' "http://gatte$path"
	fi
}
