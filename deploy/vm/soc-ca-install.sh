#!/bin/sh
# Runs INSIDE the jailmachine VM (as root, on the VM host, not in a jail).
# Driven by deploy/soc-ca-bootstrap.sh -- do not run it by hand from the Mac.
#
# Creates the SOC lab internal CA at /usr/local/etc/soc-ca and installs
# issue.sh beside it. Idempotent: an existing, self-consistent, non-expiring
# CA is left exactly as it is, because re-rolling the root invalidates every
# certificate already issued from it and every trust store that pinned it.
set -eu

CA_DIR=/usr/local/etc/soc-ca
CA_CRT="$CA_DIR/ca.crt"
CA_KEY="$CA_DIR/ca.key"
CA_DAYS="${SOC_CA_DAYS:-3650}"
CA_MIN_DAYS="${SOC_CA_MIN_DAYS:-365}"
CA_CN="${SOC_CA_CN:-SOC Lab Internal CA}"
SRC="${1:?usage: soc-ca-install.sh /path/to/soc-ca-issue.sh}"

mkdir -p "$CA_DIR"
chmod 0755 "$CA_DIR"

need_ca=yes
if [ -f "$CA_CRT" ] && [ -f "$CA_KEY" ]; then
	if openssl x509 -in "$CA_CRT" -noout -checkend $((CA_MIN_DAYS * 86400)) >/dev/null 2>&1 &&
		[ "$(openssl x509 -in "$CA_CRT" -noout -pubkey 2>/dev/null)" = \
			"$(openssl pkey -in "$CA_KEY" -pubout 2>/dev/null)" ]; then
		need_ca=no
	else
		echo "soc-ca: existing CA is expiring or key/cert mismatch -- replacing" >&2
	fi
fi

if [ "$need_ca" = yes ]; then
	umask 077
	openssl req -x509 -newkey rsa:4096 -nodes -sha256 \
		-days "$CA_DAYS" \
		-keyout "$CA_KEY.new" -out "$CA_CRT.new" \
		-subj "/O=SOC Lab/CN=$CA_CN" \
		-addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
		-addext "keyUsage=critical,keyCertSign,cRLSign" \
		-addext "subjectKeyIdentifier=hash" 2>/dev/null
	mv "$CA_KEY.new" "$CA_KEY"
	mv "$CA_CRT.new" "$CA_CRT"
	chmod 0600 "$CA_KEY"
	chmod 0644 "$CA_CRT"
	rm -f "$CA_DIR/ca.srl"
	echo "soc-ca: created a new root at $CA_CRT (valid $CA_DAYS days)"
else
	echo "soc-ca: keeping the existing root at $CA_CRT"
fi

install -m 0755 "$SRC" "$CA_DIR/issue.sh"

echo "soc-ca: ---- root certificate ----"
openssl x509 -in "$CA_CRT" -noout -subject -issuer -dates -ext basicConstraints
ls -l "$CA_DIR"
