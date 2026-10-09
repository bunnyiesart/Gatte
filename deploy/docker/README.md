# Gatte in Docker

One `docker compose up` brings up the gateway, its TLS proxy (Caddy) and its
identity provider (Authelia), configured. Every operator task after that is
one command. Why it is built this way: `design/adr/0049`.

This image serves **REST APIs** (`-transport http`): Gatte reads an API's
OpenAPI document and turns each operation into a tool your analysts' Claude
Code can call, with the API key injected server-side. MCP servers that run
as a process or a container (`stdio`, `oci`) are not served from this image;
use the host install in the top-level `README.md` for those.

## Install

You need Docker with Compose (or Podman with `docker compose`), and DNS for
two names pointing at the host: `GATTE_DOMAIN` and `auth.GATTE_DOMAIN`.
Then two files and one command:

```sh
mkdir gatte && cd gatte
base=https://raw.githubusercontent.com/bunnyiesart/Gatte/main/deploy/docker
curl -fsSLO "$base/compose.yaml"
curl -fsSL "$base/.env.example" -o .env
vi .env                       # set GATTE_DOMAIN; everything else has a default
docker compose up -d
```

`compose.yaml` pulls the published image, `ghcr.io/bunnyiesart/gatte`,
built by this repository's `image` workflow from the public source. Pin a
release with `GATTE_VERSION` in `.env`.

The first start makes every key, the encrypted vault, a private certificate
authority and the identity provider's secrets. Nothing to edit.

To build the image from a clone instead:

```sh
cd deploy/docker && cp .env.example .env
docker compose -f compose.yaml -f compose.build.yaml up -d --build
```

From here on, every command is `docker compose exec gatte gatte ...`. To
shorten it:

```sh
alias gatte='docker compose exec gatte gatte'
```

### Add an API

Put its OpenAPI document (JSON or YAML) in the `config/` directory next to
`compose.yaml` (the first start creates it), or use its URL, then:

```sh
gatte api add abuseipdb -url https://api.abuseipdb.com/api/v2 \
  -openapi abuseipdb.json -auth-kind header -auth-name Key
gatte secret set ABUSEIPDB_API_KEY      # asks for the value; it is never echoed
gatte api approve abuseipdb             # shows every tool, then asks y/N
```

- `api add` registers the API, signs it and grants its read-only tools to
  the `analyst` role in `config/roles.toml`.
- Without `-auth-kind`, Gatte takes it from the document when it declares
  exactly one API key or bearer scheme. Use `-keyless` for an API without a
  key.
- The key's vault name defaults to `NAME_API_KEY`; `-key VAR` picks another.

**Tools that change something** (POST, PUT, PATCH, DELETE) are not served
after approval alone. Name the tool in a role marked `non_read = true` in
`config/roles.toml` (the file has a commented example), then:

```sh
gatte reload
gatte clear abuseipdb report
```

### Add a person

```sh
gatte user add maria -name "Maria Silva" -email maria@example.org
gatte connect maria -os macos > connect-maria.sh
```

`user add` prints a one-time password, once. Send the password and the
script to the person over a channel you trust. The script installs the
private CA, adds Gatte to Claude Code, and tells them to run `/mcp` and sign
in.

New people go in the `soc-analysts` group, which maps to the `analyst` role.
`-group G` picks another group from `config/roles.toml`.

### Everyday

| Task | Command |
|---|---|
| What is registered, what waits for review | `gatte status` |
| Apply an edit to `config/roles.toml` | `gatte reload` |
| Rotate an API key | `gatte secret set NAME` (takes effect on the next call) |
| List people / reset a password / remove one | `gatte user list` / `gatte user reset U` / `gatte user rm U` |
| Cut a person off immediately | `gatte mcp access block U` |
| Read the audit trail | `gatte mcp audit -limit 50` |
| Any other mcp-gateway command | `gatte mcp ...` |
| Logs | `docker compose logs -f gatte` |

## What lives where

| Path on the host | What |
|---|---|
| `.env` | the settings (`GATTE_DOMAIN` is the only required one) |
| `config/roles.toml` | who may call what. Yours: review and version it |
| `config/extra.toml` | optional, any other `config.toml` section, e.g. `[audit.siem]` |
| volume `gatte-etc` | signing key, vault and its key, private CA, generated config |
| volume `gatte-data` | the database: registry, approvals, audit trail |
| volumes `authelia-etc`, `authelia-data` | the identity provider's config, secrets, accounts |

Back up `gatte-etc` and `gatte-data` together: the signatures in one are
checked against the key in the other.

## Certificates

- `GATTE_TLS=internal` (default): the private CA signs a certificate for both
  names. `gatte ca` prints the CA certificate, and
  `https://GATTE_DOMAIN/ca.crt` serves it. The connect script installs it on
  the analyst's machine.
- `GATTE_TLS=acme`: Caddy gets a public certificate from Let's Encrypt. Both
  names must be reachable from the internet on 443 and 80, and
  `GATTE_ACME_EMAIL` must be set.

## Try it on one machine

`gatte.localtest.me` and every name under it resolve to `127.0.0.1`, so:

```sh
printf 'GATTE_DOMAIN=gatte.localtest.me\nGATTE_PORT=8443\nGATTE_HTTP_PORT=8081\n' > .env
docker compose up -d
curl --cacert <(docker compose exec -T gatte gatte ca) \
  https://gatte.localtest.me:8443/.well-known/oauth-protected-resource
```

## Check it end to end

`smoke.sh` (in this directory of the repository) does what an analyst does: it creates a throwaway person, signs
in at Authelia with the same PKCE flow Claude Code uses, calls a tool through
the gateway, checks that a sensitive tool is refused, and deletes the person.

```sh
./smoke.sh petstore findPetsByStatus addPet '{"query_status":"available"}'
```

## Upgrade

```sh
docker compose pull && docker compose up -d
```

With a pinned `GATTE_VERSION`, change it first. From a clone:
`git pull`, then the build command above.

Only the Gatte containers are recreated; the keys, the vault, the database
and the accounts live in the volumes.

## Limits

- Gatte refuses an API on a private or loopback address (`10.x`,
  `192.168.x`, `127.x`). This is its egress guard (`design/adr/0048`).
- The web console is not exposed yet. Everything it does for people and
  tools is a `gatte` command above.
- `upstream update` does not re-read an OpenAPI document. To pick up a new
  version: `gatte api rm NAME`, then `gatte api add` again.
