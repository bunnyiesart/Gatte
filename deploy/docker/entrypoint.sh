#!/bin/sh
# gatte-entrypoint (design/adr/0049): the image's PID-1 child, under tini.
#
#   init   first run, idempotent: keys, vault, certificates, Authelia's
#          secrets, the configuration files Caddy and Authelia read. Runs
#          as the compose "init" service before anything else starts.
#   serve  every start: re-render the configuration, start the management
#          API's two sockets, wait for the IdP, run `check`, then exec
#          serve as the service account.
#
# Nothing here prints a secret. The one place a value is typed is
# `gatte secret set`, which reads it from the operator's terminal.

. /usr/local/share/gatte/lib.sh

TAB=$(printf '\t')

# mkdirs MODE OWNER DIR... creates the directories and (re)sets their owner and
# mode, which busybox `install -d` leaves alone on one that already exists --
# a fresh named volume is root's.
mkdirs() {
	m=$1 o=$2
	shift 2
	mkdir -p "$@"
	chown "$o" "$@"
	chmod "$m" "$@"
}

render() { # TEMPLATE DEST MODE OWNER
	sed -e "s|@ISSUER@|$ISSUER|g" \
		-e "s|@AUDIENCE@|$AUDIENCE|g" \
		-e "s|@IDP_URL@|$IDP_URL|g" \
		-e "s|@SESSION_DOMAIN@|$GATTE_DOMAIN|g" \
		-e "s|@TRUSTED_KEY@|$(cat "$SIGNING_PUB")|g" \
		-e "s|@CA_FILE_LINE@|$CA_FILE_LINE|g" \
		-e "s|@GW_SITE@|$GW_SITE|g" \
		-e "s|@IDP_SITE@|$IDP_SITE|g" \
		-e "s|@TLS@|$TLS_LINE|g" \
		-e "s|@GLOBAL@|$GLOBAL_LINE|g" \
		"$TEMPLATES/$1" >"$2.new"
	chmod "$3" "$2.new"
	chown "$4" "$2.new"
	mv "$2.new" "$2"
}

edge_lines() {
	if [ "$GATTE_TLS" = internal ]; then
		CA_FILE_LINE='ca_file       = "/etc/gatte-edge/public/ca.crt"'
		TLS_LINE="${TAB}tls /etc/gatte-edge/tls/cert.pem /etc/gatte-edge/tls/key.pem"
		GLOBAL_LINE="${TAB}auto_https disable_redirects"
	else
		CA_FILE_LINE='# ca_file: none, the certificate is from a public CA (GATTE_TLS=acme)'
		TLS_LINE=
		GLOBAL_LINE="${TAB}email $GATTE_ACME_EMAIL"
	fi
}

# A private CA and a leaf for both names, re-issued when the names changed
# or the leaf has less than 30 days left. Analysts install ca.crt once; the
# connect script does it for them (ca_file).
internal_tls() {
	if [ ! -s "$GATTE_CA/ca.key" ]; then
		openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
			-keyout "$GATTE_CA/ca.key" -out "$GATTE_CA/ca.crt" -days 3650 \
			-subj "/CN=Gatte private CA for $GATTE_DOMAIN" \
			-addext 'basicConstraints=critical,CA:TRUE' \
			-addext 'keyUsage=critical,keyCertSign,cRLSign' 2>/dev/null
		chmod 0600 "$GATTE_CA/ca.key"
		say "init: made a private certificate authority for $GATTE_DOMAIN"
	fi
	cert=$GATTE_EDGE/tls/cert.pem key=$GATTE_EDGE/tls/key.pem
	want="DNS:$GATTE_DOMAIN, DNS:$IDP_HOST"
	have=$(openssl x509 -in "$cert" -noout -ext subjectAltName 2>/dev/null | tail -n 1 | sed 's/^ *//') || have=
	if [ "$have" != "$want" ] || ! openssl x509 -in "$cert" -noout -checkend 2592000 >/dev/null 2>&1; then
		w=$(mktemp -d)
		printf 'subjectAltName=DNS:%s,DNS:%s\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n' \
			"$GATTE_DOMAIN" "$IDP_HOST" >"$w/ext"
		openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
			-keyout "$w/key.pem" -out "$w/csr" -subj "/CN=$GATTE_DOMAIN" 2>/dev/null
		openssl x509 -req -in "$w/csr" -CA "$GATTE_CA/ca.crt" -CAkey "$GATTE_CA/ca.key" \
			-set_serial "0x$(openssl rand -hex 16)" -days 397 -extfile "$w/ext" -out "$w/cert.pem" 2>/dev/null
		install -m 0600 "$w/key.pem" "$key"
		install -m 0644 "$w/cert.pem" "$cert"
		rm -rf "$w"
		say "init: issued the TLS certificate for $GATTE_DOMAIN and $IDP_HOST"
	fi
	install -m 0644 "$GATTE_CA/ca.crt" "$GATTE_EDGE/public/ca.crt"
}

cmd_init() {
	derive
	edge_lines
	umask 022
	mkdirs 0755 root:root "$GATTE_ETC"
	mkdirs 0700 root:root "$GATTE_KEYS" "$GATTE_CA"
	mkdirs 0750 "$SERVICE_USER:$SERVICE_USER" "$GATTE_DATA"
	mkdirs 0755 root:root "$GATTE_EDGE" "$GATTE_EDGE/tls" "$GATTE_EDGE/public" "$AUTHELIA_ETC"
	mkdirs 0700 root:root "$AUTHELIA_ETC/secrets"
	mkdir -p "$GATTE_SITE"

	# The signing key: root's, never readable by the service (design/adr/0010).
	if [ ! -s "$SIGNING_KEY" ]; then
		out=$(mcp-gateway sign -generate-key -out "$SIGNING_KEY")
		pub=$(printf '%s\n' "$out" | sed -n 's/^[[:space:]]*"\([A-Za-z0-9+/]\{42,\}=*\)".*/\1/p' | head -n 1)
		[ -n "$pub" ] || die "could not read the public key sign -generate-key printed"
		printf '%s\n' "$pub" >"$SIGNING_PUB"
		say "init: made the signing key"
	fi

	# The vault's key: the service's alone (README, "Who owns what").
	if [ ! -s "$AGE_KEY" ]; then
		age-keygen -o "$AGE_KEY" 2>/dev/null
		say "init: made the vault key"
	fi
	chown "$SERVICE_USER:$SERVICE_USER" "$AGE_KEY"
	chmod 0600 "$AGE_KEY"

	# An empty vault. Credentials go in with `gatte secret set NAME`.
	if [ ! -s "$VAULT" ]; then
		w=$(mktemp -d)
		printf '{}\n' >"$w/v.json"
		sops --encrypt --age "$(age-keygen -y "$AGE_KEY")" --input-type json --output-type json "$w/v.json" >"$VAULT.new"
		rm -rf "$w"
		mv "$VAULT.new" "$VAULT"
		say "init: made the (empty) vault"
	fi
	chown "root:$SERVICE_USER" "$VAULT"
	chmod 0640 "$VAULT"

	[ "$GATTE_TLS" = internal ] && internal_tls

	# Authelia's own secrets, generated here and never copied out.
	for s in session.secret storage.encryption.key identity_validation.jwt.secret oidc.hmac.secret; do
		[ -s "$AUTHELIA_ETC/secrets/$s" ] || (umask 077 && openssl rand -hex 32 >"$AUTHELIA_ETC/secrets/$s")
	done
	if [ ! -s "$AUTHELIA_ETC/secrets/oidc.jwks.main.pem" ]; then
		(umask 077 && openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
			-out "$AUTHELIA_ETC/secrets/oidc.jwks.main.pem" 2>/dev/null)
		say "init: made the identity provider's signing key"
	fi
	# Authelia refuses a users file with no user, and the accounts socket
	# that writes real ones only runs once the gateway does. So the first
	# run writes one disabled account that cannot sign in (its password is
	# random and never kept); the first `gatte user add` deletes it.
	if [ ! -s "$USERS_FILE" ]; then
		h=$(openssl rand -hex 32 | openssl passwd -6 -stdin)
		printf 'users:\n  %s:\n    disabled: true\n    displayname: "placeholder until the first gatte user add"\n    password: "%s"\n    groups: []\n' \
			"$BOOTSTRAP_USER" "$h" >"$USERS_FILE"
	fi
	chmod 0644 "$USERS_FILE"

	render gatte.toml "$BASE" 0640 "root:$SERVICE_USER"
	render authelia.yml "$AUTHELIA_ETC/configuration.yml" 0644 root:root
	render Caddyfile "$GATTE_EDGE/Caddyfile" 0644 root:root
	assemble_config

	say "init: ready for $GW_URL (identity provider $IDP_URL, TLS $GATTE_TLS)"
}

# keep SOCKET ARGS... restarts one management API socket if it exits; the
# console and `gatte user`/`gatte connect` need them, serve does not.
keep() {
	sock=$1
	shift
	while :; do
		rm -f "$sock"
		"$@" || true
		sleep 3
	done
}

wait_for_idp() {
	i=0
	until curl -fsS --max-time 5 "$ISSUER/.well-known/openid-configuration" >/dev/null 2>&1; do
		i=$((i + 1))
		[ "$i" -lt 60 ] || die "the identity provider at $ISSUER did not answer in 2 minutes (docker compose logs authelia caddy)"
		sleep 2
	done
}

cmd_serve() {
	derive
	edge_lines
	[ -s "$SIGNING_PUB" ] || die "the first run has not completed: docker compose up runs the init service first"
	# A volume's root directory can come back root's (a runtime that copies
	# the image's directory into an empty volume resets it), and check would
	# then refuse to start, rightly.
	mkdirs 0750 "$SERVICE_USER:$SERVICE_USER" "$GATTE_DATA"
	render gatte.toml "$BASE" 0640 "root:$SERVICE_USER"
	assemble_config

	# The gateway fetches the IdP's discovery document over Caddy, so it
	# must trust the private CA when there is one.
	if [ "$GATTE_TLS" = internal ]; then
		install -m 0644 "$GATTE_CA/ca.crt" /usr/local/share/ca-certificates/gatte-private-ca.crt
		update-ca-certificates >/dev/null 2>&1 || true
	fi

	mkdirs 0755 root:root "$RUN_DIR"
	mkdirs 0700 "$SERVICE_USER:$SERVICE_USER" "$RUN_DIR/op"
	mkdirs 0700 root:root "$RUN_DIR/accounts"
	keep "$OPERATOR_SOCKET" as_service mcp-gateway admin -config "$CONFIG" -socket "$OPERATOR_SOCKET" -idle 0 &
	keep "$ACCOUNTS_SOCKET" mcp-gateway admin -accounts -config "$CONFIG" -socket "$ACCOUNTS_SOCKET" -idle 0 &

	wait_for_idp
	if ! mcp-gateway check -config "$CONFIG" -user "$SERVICE_USER"; then
		die "check found a problem (above); not starting serve"
	fi
	exec su-exec "$SERVICE_USER" env HOME="$SERVICE_HOME" mcp-gateway serve -config "$CONFIG"
}

case "${1:-serve}" in
init) cmd_init ;;
serve) cmd_serve ;;
*) exec "$@" ;;
esac
