#!/bin/sh
# gatte-entrypoint (design/adr/0049): the image's PID-1 child, under tini.
#
#   run    (the default) first-run setup if needed, then Authelia, Caddy,
#          the management API's two sockets and the gateway, each as its
#          own account, all in this one container. If Authelia, Caddy or
#          the gateway exits, the others are stopped and the container
#          exits, so the restart policy brings the whole set back.
#   init   only the idempotent setup, then exit.
#
# All three share this container's loopback, which is what lets the gateway
# keep its loopback-only listener (design/adr/0011): Caddy reaches it on
# 127.0.0.1:8080 and Authelia on 127.0.0.1:9091. Nothing here prints a
# secret; the one place a value is typed is `gatte secret set`.

. /usr/local/share/gatte/lib.sh

TAB=$(printf '\t')

# mkdirs MODE OWNER DIR... creates the directories and (re)sets owner and
# mode, also on one that already exists: a fresh volume is root's.
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
		CA_FILE_LINE="ca_file       = \"$GATTE_EDGE/public/ca.crt\""
		TLS_LINE="${TAB}tls $GATTE_EDGE/tls/cert.pem $GATTE_EDGE/tls/key.pem"
		GLOBAL_LINE="${TAB}auto_https disable_redirects"
	else
		CA_FILE_LINE='# ca_file: none, the certificate is from a public CA (GATTE_TLS=acme)'
		TLS_LINE=
		GLOBAL_LINE="${TAB}email $GATTE_ACME_EMAIL"
	fi
}

# A private CA and a leaf for both names, re-issued when the names changed
# or the leaf has less than 30 days left. Analysts install ca.crt once; the
# connect script does it for them ([connect] ca_file).
internal_tls() {
	if [ ! -s "$GATTE_CA/ca.key" ]; then
		openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
			-keyout "$GATTE_CA/ca.key" -out "$GATTE_CA/ca.crt" -days 3650 \
			-subj "/CN=Gatte private CA for $GATTE_DOMAIN" \
			-addext 'basicConstraints=critical,CA:TRUE' \
			-addext 'keyUsage=critical,keyCertSign,cRLSign' 2>/dev/null
		chmod 0600 "$GATTE_CA/ca.key"
		say "gatte: made a private certificate authority for $GATTE_DOMAIN"
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
		install -m 0600 -o caddy -g caddy "$w/key.pem" "$key"
		install -m 0644 "$w/cert.pem" "$cert"
		rm -rf "$w"
		say "gatte: issued the TLS certificate for $GATTE_DOMAIN and $IDP_HOST"
	fi
	install -m 0644 "$GATTE_CA/ca.crt" "$GATTE_EDGE/public/ca.crt"
}

cmd_init() {
	derive
	edge_lines
	umask 022
	mkdirs 0755 root:root "$ROOT" "$GATTE_ETC" "$GATTE_SITE" "$GATTE_EDGE" "$GATTE_EDGE/public" "$AUTHELIA_ETC"
	mkdirs 0700 root:root "$GATTE_KEYS" "$GATTE_CA"
	mkdirs 0750 "$SERVICE_USER:$SERVICE_USER" "$GATTE_DATA"
	mkdirs 0700 caddy:caddy "$GATTE_EDGE/tls" "$CADDY_HOME"
	mkdirs 0700 authelia:authelia "$AUTHELIA_ETC/secrets" "$AUTHELIA_DATA"
	save_settings

	# The signing key: root's, never readable by the service (design/adr/0010).
	if [ ! -s "$SIGNING_KEY" ]; then
		out=$(mcp-gateway sign -generate-key -out "$SIGNING_KEY")
		pub=$(printf '%s\n' "$out" | sed -n 's/^[[:space:]]*"\([A-Za-z0-9+/]\{42,\}=*\)".*/\1/p' | head -n 1)
		[ -n "$pub" ] || die "could not read the public key sign -generate-key printed"
		printf '%s\n' "$pub" >"$SIGNING_PUB"
		say "gatte: made the signing key"
	fi

	# The vault's key: the service's alone (README, "Who owns what").
	if [ ! -s "$AGE_KEY" ]; then
		age-keygen -o "$AGE_KEY" 2>/dev/null
		say "gatte: made the vault key"
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
		say "gatte: made the (empty) vault"
	fi
	chown "root:$SERVICE_USER" "$VAULT"
	chmod 0640 "$VAULT"

	if [ "$GATTE_TLS" = internal ]; then internal_tls; fi

	# Authelia's own secrets, generated here and never copied out.
	for s in session.secret storage.encryption.key identity_validation.jwt.secret oidc.hmac.secret; do
		f=$AUTHELIA_ETC/secrets/$s
		[ -s "$f" ] || (umask 077 && openssl rand -hex 32 >"$f")
	done
	if [ ! -s "$AUTHELIA_ETC/secrets/oidc.jwks.main.pem" ]; then
		(umask 077 && openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
			-out "$AUTHELIA_ETC/secrets/oidc.jwks.main.pem" 2>/dev/null)
		say "gatte: made the identity provider's signing key"
	fi
	chown -R authelia:authelia "$AUTHELIA_ETC/secrets"
	chmod 0600 "$AUTHELIA_ETC/secrets"/*

	# Authelia refuses to start with a users file that holds no user, and
	# the accounts socket that writes real ones only runs once the gateway
	# does. So there is always one disabled account that cannot sign in (its
	# password is random and never kept): written on the first run, and
	# written again on any start that finds the file empty -- deleting the
	# last person used to leave an IdP that would not start again. `gatte
	# user list` does not show it.
	if [ ! -s "$USERS_FILE" ] || ! grep -q '^  [^ #]' "$USERS_FILE"; then
		h=$(openssl rand -hex 32 | openssl passwd -6 -stdin)
		printf 'users:\n  %s:\n    disabled: true\n    displayname: "placeholder until the first gatte user add"\n    password: "%s"\n    groups: []\n' \
			"$BOOTSTRAP_USER" "$h" >"$USERS_FILE"
	fi
	chown root:root "$USERS_FILE"
	chmod 0644 "$USERS_FILE"

	render gatte.toml "$BASE" 0640 "root:$SERVICE_USER"
	render authelia.yml "$AUTHELIA_ETC/configuration.yml" 0644 root:root
	render Caddyfile "$GATTE_EDGE/Caddyfile" 0644 root:root
	assemble_config
}

# Inside the container both public names are this container: the gateway
# fetches the IdP's discovery document at the same URL analysts use, and
# it must arrive at Caddy on loopback.
pin_hosts() {
	grep -q " $IDP_HOST\$" /etc/hosts 2>/dev/null && return 0
	printf '127.0.0.1 %s %s\n' "$GATTE_DOMAIN" "$IDP_HOST" >>/etc/hosts 2>/dev/null ||
		die "cannot write /etc/hosts; the gateway could not reach its own identity provider"
}

# keep SOCKET CMD... restarts one management API socket if it exits; the
# operator's commands need them, the gateway does not.
keep() {
	sock=$1
	shift
	while :; do
		rm -f "$sock"
		"$@" || true
		sleep 3
	done
}

# wait_for_idp waits for the discovery document, and gives up at once if
# Authelia or Caddy has already exited (its own log says why).
wait_for_idp() {
	i=0
	until curl -fsS --max-time 5 "$ISSUER/.well-known/openid-configuration" >/dev/null 2>&1; do
		kill -0 "$AUTHELIA_PID" 2>/dev/null || { WHY="authelia exited (its log is above)"; return 1; }
		kill -0 "$CADDY_PID" 2>/dev/null || { WHY="caddy exited (its log is above)"; return 1; }
		i=$((i + 1))
		[ "$i" -lt 60 ] || { WHY="the identity provider at $ISSUER did not answer in 2 minutes"; return 1; }
		sleep 2
	done
}

PIDS=
stop_all() {
	trap - TERM INT
	say "gatte: stopping"
	# The gateway first: it drains calls for up to 15 s, then reaps.
	if [ -n "${GW_PID:-}" ]; then
		kill -TERM "$GW_PID" 2>/dev/null || true
		wait "$GW_PID" 2>/dev/null || true
	fi
	for p in $PIDS; do kill -TERM "$p" 2>/dev/null || true; done
	wait 2>/dev/null || true
	exit "${1:-0}"
}

cmd_run() {
	cmd_init
	pin_hosts

	if [ "$GATTE_TLS" = internal ]; then
		install -m 0644 "$GATTE_CA/ca.crt" /usr/local/share/ca-certificates/gatte-private-ca.crt
		update-ca-certificates >/dev/null 2>&1 || true
	fi

	trap 'stop_all 0' TERM INT

	X_AUTHELIA_CONFIG=$AUTHELIA_ETC/configuration.yml X_AUTHELIA_CONFIG_FILTERS=template \
		as_user authelia authelia &
	AUTHELIA_PID=$!
	XDG_DATA_HOME=$CADDY_HOME XDG_CONFIG_HOME=$CADDY_HOME/config \
		as_user caddy caddy run --config "$GATTE_EDGE/Caddyfile" --adapter caddyfile &
	CADDY_PID=$!
	PIDS="$AUTHELIA_PID $CADDY_PID"

	mkdirs 0755 root:root "$RUN_DIR"
	# A console of a previous start is gone with its process; its pidfile
	# would name whatever reuses the number.
	rm -f "$RUN_DIR"/console.*
	mkdirs 0700 "$SERVICE_USER:$SERVICE_USER" "$RUN_DIR/op"
	mkdirs 0700 root:root "$RUN_DIR/accounts"
	keep "$OPERATOR_SOCKET" as_service mcp-gateway admin -config "$CONFIG" -socket "$OPERATOR_SOCKET" -idle 0 &
	PIDS="$PIDS $!"
	keep "$ACCOUNTS_SOCKET" mcp-gateway admin -accounts -config "$CONFIG" -socket "$ACCOUNTS_SOCKET" -idle 0 &
	PIDS="$PIDS $!"

	if ! wait_for_idp; then
		say "gatte: $WHY; stopping so the container restarts" >&2
		stop_all 1
	fi
	if ! mcp-gateway check -config "$CONFIG" -user "$SERVICE_USER"; then
		say "gatte: check found a problem (above); not starting the gateway" >&2
		stop_all 1
	fi
	as_service mcp-gateway serve -config "$CONFIG" &
	GW_PID=$!

	say "gatte: up at $GW_URL (identity provider $IDP_URL, TLS $GATTE_TLS). Operator commands: docker exec -it CONTAINER gatte help"
	while kill -0 "$GW_PID" 2>/dev/null && kill -0 "$CADDY_PID" 2>/dev/null && kill -0 "$AUTHELIA_PID" 2>/dev/null; do
		sleep 2 &
		wait $! 2>/dev/null || true
	done
	for n in GW CADDY AUTHELIA; do
		eval "p=\$${n}_PID"
		kill -0 "$p" 2>/dev/null || say "gatte: $(printf '%s' "$n" | tr '[:upper:]' '[:lower:]') exited; stopping the others so the container restarts whole" >&2
	done
	stop_all 1
}

case "${1:-run}" in
run) cmd_run ;;
init) cmd_init && say "gatte: ready" ;;
*) exec "$@" ;;
esac
