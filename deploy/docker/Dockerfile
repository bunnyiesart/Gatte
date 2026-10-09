# syntax=docker/dockerfile:1
#
# Gatte as one OCI image (design/adr/0049).
#
# Build from the repository root:
#
#     docker build -f deploy/docker/Dockerfile -t gatte:local .
#
# The image holds the gateway and the three tools its boot path calls out
# to -- sops (the vault, ADR-0005), age (the vault's key) and openssl (the
# first-run certificate authority) -- and the two scripts that turn
# "docker compose up" into a configured gateway: gatte-entrypoint (first
# run and start) and gatte (the operator's commands). It serves REST
# backends (-transport http); it carries no podman, so oci backends are
# not served from it, by the owner's decision of 07 Oct 2026.

# --- 1. The gateway: a static binary (modernc.org/sqlite is pure Go). ---
FROM golang:1.27.1-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=docker
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.buildVersion=${VERSION}" \
      -o /out/mcp-gateway ./cmd/mcp-gateway

# --- 2. sops, from its release, checked against the release's checksums. ---
# Alpine's own sops lags behind the 3.13.2 the gateway requires (README).
FROM alpine:3.22 AS sops
ARG SOPS_VERSION=v3.13.2
RUN set -eu; apk add --no-cache curl >/dev/null; \
    case "$(uname -m)" in x86_64) arch=amd64 ;; aarch64) arch=arm64 ;; \
      *) echo "unsupported architecture $(uname -m)" >&2; exit 1 ;; esac; \
    base="https://github.com/getsops/sops/releases/download/${SOPS_VERSION}"; \
    f="sops-${SOPS_VERSION}.linux.${arch}"; cd /tmp; \
    curl -fsSLO "$base/$f"; curl -fsSLO "$base/sops-${SOPS_VERSION}.checksums.txt"; \
    grep " ${f}\$" "sops-${SOPS_VERSION}.checksums.txt" | sha256sum -c -; \
    install -D -m 0755 "$f" /out/sops

# --- 3. The runtime. ---
FROM alpine:3.22
# tini is PID 1 so signals reach serve and the background admin sockets are
# reaped; su-exec drops root to the service account; curl talks to the
# management API's UNIX sockets and waits for the IdP.
RUN apk add --no-cache age ca-certificates curl jq openssl su-exec tini tzdata \
 && addgroup -S -g 10001 gatte \
 && adduser -S -D -H -u 10001 -G gatte -h /var/lib/gatte -s /sbin/nologin gatte \
 && install -d -m 0750 -o gatte -g gatte /var/lib/gatte \
 && install -d -m 0755 /etc/gatte
COPY --from=build /out/mcp-gateway /usr/local/bin/mcp-gateway
COPY --from=sops  /out/sops        /usr/local/bin/sops
COPY deploy/docker/entrypoint.sh   /usr/local/bin/gatte-entrypoint
COPY deploy/docker/gatte           /usr/local/bin/gatte
COPY deploy/docker/lib.sh          /usr/local/share/gatte/lib.sh
COPY deploy/docker/templates/      /usr/local/share/gatte/templates/
RUN chmod 0755 /usr/local/bin/gatte-entrypoint /usr/local/bin/gatte

# The service runs as gatte (uid 10001); the entrypoint starts as root only
# to lay out files the service must not be able to write (README, "Who owns
# what") and then drops to it.
VOLUME ["/etc/gatte", "/var/lib/gatte"]
ENTRYPOINT ["/sbin/tini", "--", "gatte-entrypoint"]
CMD ["serve"]
