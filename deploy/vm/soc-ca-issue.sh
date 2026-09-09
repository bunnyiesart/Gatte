#!/bin/sh
# soc-ca issue.sh -- issue a server certificate from the SOC lab internal CA.
#
# Installed by deploy/soc-ca-bootstrap.sh as:
#
#     /usr/local/etc/soc-ca/issue.sh NAME IP
#
# and it writes, in that same directory:
#
#     /usr/local/etc/soc-ca/NAME.crt    0644  leaf certificate
#     /usr/local/etc/soc-ca/NAME.key    0600  leaf private key (unencrypted)
#
# The SAN carries BOTH the DNS name and the IP, because a lab is reached
# both ways -- by name once /etc/hosts is populated, and by literal IP
# before that, or from anything that never got the hosts entry. A cert with
# only a DNS SAN fails IP-address verification in Go and in curl, and the
# usual "fix" for that is --insecure, which is how a lab quietly stops
# testing TLS at all.
#
# NOT A PUBLIC PKI. See deploy/authelia-jail.md, "What the CA is not".
#
# Idempotent: if NAME.crt already exists, is signed by the current CA, has
# exactly the requested SANs, and is valid for more than SOC_CA_MIN_DAYS
# (default 30) more days, it is left alone. SOC_CA_FORCE=1 re-issues
# regardless. Re-issuing changes the key, so anything already serving the
# old one has to be restarted -- that is the whole reason for the skip.
set -eu

CA_DIR="${SOC_CA_DIR:-/usr/local/etc/soc-ca}"
CA_CRT="$CA_DIR/ca.crt"
CA_KEY="$CA_DIR/ca.key"
LEAF_DAYS="${SOC_CA_LEAF_DAYS:-825}"
MIN_DAYS="${SOC_CA_MIN_DAYS:-30}"

usage() {
	echo "usage: $0 NAME IP" >&2
	echo "  e.g. $0 id.soc.internal 10.17.89.20" >&2
	exit 2
}

[ $# -eq 2 ] || usage
NAME="$1"
IP="$2"

case "$NAME" in
	*/*|""|.|..) echo "issue.sh: refusing NAME '$NAME'" >&2; exit 2 ;;
esac
echo "$IP" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' || {
	echo "issue.sh: '$IP' is not a dotted-quad IPv4 address" >&2; exit 2; }

[ -f "$CA_CRT" ] && [ -f "$CA_KEY" ] || {
	echo "issue.sh: no CA at $CA_DIR -- run deploy/soc-ca-bootstrap.sh first" >&2
	exit 1; }

CRT="$CA_DIR/$NAME.crt"
KEY="$CA_DIR/$NAME.key"
SAN="DNS:$NAME,IP:$IP"

# ---------------------------------------------------------------- skip path
if [ -z "${SOC_CA_FORCE:-}" ] && [ -f "$CRT" ] && [ -f "$KEY" ]; then
	ok=yes
	openssl verify -CAfile "$CA_CRT" "$CRT" >/dev/null 2>&1 || ok=no
	openssl x509 -in "$CRT" -noout -checkend $((MIN_DAYS * 86400)) >/dev/null 2>&1 || ok=no
	# openssl prints 'IP Address:' where the ext file writes 'IP:', so both
	# sides get normalised before comparison. Without this the check never
	# matches and every run silently re-issues -- which defeats the point.
	have=$(openssl x509 -in "$CRT" -noout -ext subjectAltName 2>/dev/null \
		| grep -v 'X509v3' | tr -d ' ' | sed 's/IPAddress:/IP:/g' \
		| tr ',' '\n' | sort | tr '\n' ',')
	want=$(echo "$SAN" | tr -d ' ' | tr ',' '\n' | sort | tr '\n' ',')
	[ "$have" = "$want" ] || ok=no
	if [ "$ok" = yes ]; then
		echo "issue.sh: $NAME already has a current cert with SAN $SAN -- keeping it"
		echo "$CRT"
		echo "$KEY"
		exit 0
	fi
fi

# --------------------------------------------------------------- issue path
umask 077
TMP=$(mktemp -d "${TMPDIR:-/tmp}/soc-ca.XXXXXX")
trap 'rm -rf "$TMP"' EXIT INT TERM

cat >"$TMP/leaf.ext" <<EOF
basicConstraints       = critical, CA:FALSE
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = serverAuth
subjectAltName         = $SAN
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
EOF

openssl req -new -newkey rsa:2048 -nodes \
	-keyout "$TMP/leaf.key" -out "$TMP/leaf.csr" \
	-subj "/O=SOC Lab/OU=internal/CN=$NAME" 2>/dev/null

openssl x509 -req -in "$TMP/leaf.csr" \
	-CA "$CA_CRT" -CAkey "$CA_KEY" -CAcreateserial -CAserial "$CA_DIR/ca.srl" \
	-days "$LEAF_DAYS" -sha256 -extfile "$TMP/leaf.ext" \
	-out "$TMP/leaf.crt" 2>/dev/null

openssl verify -CAfile "$CA_CRT" "$TMP/leaf.crt" >/dev/null

cat "$TMP/leaf.crt" >"$CRT"
cat "$TMP/leaf.key" >"$KEY"
chmod 0644 "$CRT"
chmod 0600 "$KEY"

echo "issue.sh: issued $NAME  SAN=$SAN  days=$LEAF_DAYS"
echo "$CRT"
echo "$KEY"
