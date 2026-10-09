# syntax=docker/dockerfile:1
#
# Gatte as one OCI image (design/adr/0049): the gateway, its TLS proxy
# (Caddy) and its identity provider (Authelia) in ONE container, so an
# installation is a single `docker run`:
#
#     docker run -d --name gatte --restart unless-stopped -p 443:443 \
#       -e GATTE_DOMAIN=gatte.example.org -v gatte:/gatte \
#       ghcr.io/bunnyiesart/gatte
#
# Build from the repository root:
#
#     docker build -f deploy/docker/Dockerfile -t gatte:local .
#
# Every base image is pinned by the digest of its multi-architecture index,
# not by a tag a publisher can move. The runtime is Debian, not Alpine,
# because Authelia's release binary is linked against glibc.

# --- 1. The gateway: a static binary (modernc.org/sqlite is pure Go). ---
FROM golang:1.27.1-trixie@sha256:8f58fd67ea075142d947a60e0caa4317746a55118d312f027793d382c7741734 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=docker
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.buildVersion=${VERSION}" \
      -o /out/mcp-gateway ./cmd/mcp-gateway

# --- 2. sops, from its release, checked against the release's checksums. ---
FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f AS sops
ARG SOPS_VERSION=v3.13.2
RUN set -eu; apt-get update -qq; apt-get install -y -qq --no-install-recommends ca-certificates curl >/dev/null; \
    arch=$(dpkg --print-architecture); \
    base="https://github.com/getsops/sops/releases/download/${SOPS_VERSION}"; \
    f="sops-${SOPS_VERSION}.linux.${arch}"; cd /tmp; \
    curl -fsSLO "$base/$f"; curl -fsSLO "$base/sops-${SOPS_VERSION}.checksums.txt"; \
    grep " ${f}\$" "sops-${SOPS_VERSION}.checksums.txt" | sha256sum -c -; \
    install -D -m 0755 "$f" /out/sops

# --- 3. Caddy and Authelia, from their official images. ---
FROM caddy:2.11.7-alpine@sha256:d8542f48d34a9cf4e4c11a478865229840e87e4c96ea3f439101f31a5d35f75f AS caddy
FROM authelia/authelia:4.39.28@sha256:bd97cff4fcbf715b5ff1f9ae286afbe6033afce385302520b0368122d43a6f54 AS authelia

# --- 4. The runtime. ---
FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
# tini is PID 1, so signals reach the entrypoint, which stops the three
# processes in order; setpriv (util-linux) drops each one to its own
# account; curl talks to the management API's UNIX sockets.
RUN set -eu; apt-get update -qq; \
    apt-get install -y -qq --no-install-recommends age ca-certificates curl jq libcap2-bin openssl tini tzdata >/dev/null; \
    groupadd -r -g 10001 gatte;    useradd -r -u 10001 -g gatte    -d /gatte/data -M -s /usr/sbin/nologin gatte; \
    groupadd -r -g 10002 authelia; useradd -r -u 10002 -g authelia -d /gatte/authelia-data -M -s /usr/sbin/nologin authelia; \
    groupadd -r -g 10003 caddy;    useradd -r -u 10003 -g caddy    -d /gatte/caddy -M -s /usr/sbin/nologin caddy; \
    rm -rf /var/lib/apt/lists/*
COPY --from=build    /out/mcp-gateway /usr/local/bin/mcp-gateway
COPY --from=sops     /out/sops        /usr/local/bin/sops
COPY --from=caddy    /usr/bin/caddy   /usr/local/bin/caddy
COPY --from=authelia /app/authelia    /usr/local/bin/authelia
COPY --from=authelia /app/LICENSE     /usr/local/share/doc/authelia/LICENSE
COPY deploy/docker/entrypoint.sh   /usr/local/bin/gatte-entrypoint
COPY deploy/docker/gatte           /usr/local/bin/gatte
COPY deploy/docker/lib.sh          /usr/local/share/gatte/lib.sh
COPY deploy/docker/selftest.sh     /usr/local/share/gatte/selftest.sh
COPY deploy/docker/templates/      /usr/local/share/gatte/templates/
# Caddy runs as its own account and still binds 443.
RUN chmod 0755 /usr/local/bin/gatte-entrypoint /usr/local/bin/gatte /usr/local/share/gatte/selftest.sh \
 && setcap 'cap_net_bind_service=+ep' /usr/local/bin/caddy \
 && install -d -m 0755 /gatte

# Everything that must survive a restart is under /gatte: one volume.
VOLUME ["/gatte"]
EXPOSE 443 80
HEALTHCHECK --interval=30s --timeout=5s --start-period=2m \
  CMD curl -fsS -o /dev/null http://127.0.0.1:8080/.well-known/oauth-protected-resource || exit 1
ENTRYPOINT ["/usr/bin/tini", "--", "gatte-entrypoint"]
CMD ["run"]
