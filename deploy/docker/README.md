# Gatte in Docker

One `docker run` brings up the gateway, its TLS proxy (Caddy) and its
identity provider (Authelia), configured, in one container. No file to
download, nothing to clone. Every operator task after that is one command.
Why it is built this way: `design/adr/0049`.

This image serves **REST APIs** (`-transport http`): Gatte reads an API's
OpenAPI document and turns each operation into a tool your analysts' Claude
Code can call, with the API key injected server-side. MCP servers that run
as a process or a container (`stdio`, `oci`) are not served from this image;
use the host install in the top-level `README.md` for those.

## Install

You need Docker (or Podman), and DNS for two names pointing at the host:
`gatte.example.org` and `auth.gatte.example.org`. Then:

```sh
docker run -d --name gatte --restart unless-stopped \
  -p 443:443 -p 127.0.0.1:8090:8090 -e GATTE_DOMAIN=gatte.example.org \
  -v gatte:/gatte ghcr.io/bunnyiesart/gatte:0.3.0
```

The first start makes every key, the encrypted vault, a private certificate
authority and the identity provider's secrets, and keeps them in the `gatte`
volume. `docker logs gatte` ends with `gatte: up at https://...` when it is
ready.

Options, all `-e`:

| Setting | Default | What |
|---|---|---|
| `GATTE_DOMAIN` | (required) | The name analysts reach Gatte on; the IdP is `auth.` + it |
| `GATTE_TLS` | `internal` | `internal`: a private CA made here. `acme`: a public certificate from Let's Encrypt (add `-p 80:80` and `GATTE_ACME_EMAIL`) |
| `GATTE_PORT` | `443` | The HTTPS port, when 443 is taken. Publish the same number: `-p 8443:8443 -e GATTE_PORT=8443` |
| `TZ` | `UTC` | Time zone of the logs |

The settings are kept in the volume: an upgrade can drop the `-e` flags.

Every command below is `docker exec -it gatte gatte ...`. To shorten it:

```sh
alias gatte='docker exec -it gatte gatte'
```

## The web console

Everything below can also be done in the browser: add, sign and remove
APIs, approve and clear tools, set and delete API keys, edit the roles,
manage people, read the audit trail (design/adr/0050). The console is never
exposed to the network: the container publishes it on the host's loopback
only (`-p 127.0.0.1:8090:8090`), and you reach it through SSH. Other
containers on the same Docker network can reach the container's 8090; what
stops them is the one-time login link, which only `docker exec` prints.

```sh
docker exec gatte gatte console            # prints a one-time login link
ssh -L 8090:127.0.0.1:8090 you@the-host    # from your machine, then open the link
```

The link works once. Running `gatte console` again ends the session and
prints a new one; `gatte console stop` closes it.

## Add an API

```sh
gatte api add abuseipdb -url https://api.abuseipdb.com/api/v2 \
  -openapi https://example.org/abuseipdb-openapi.json -auth-kind header -auth-name Key
gatte secret set ABUSEIPDB_API_KEY      # asks for the value; it is never echoed
gatte api approve abuseipdb             # shows every tool, then asks y/N
```

- The OpenAPI document can be a URL, or come from your machine on standard
  input:

  ```sh
  docker exec -i gatte gatte api add abuseipdb -url https://api.abuseipdb.com/api/v2 \
    -openapi - -auth-kind header -auth-name Key < abuseipdb.json
  ```

- `api add` registers the API, signs it and grants its read-only tools to
  the `analyst` role.
- Without `-auth-kind`, Gatte takes it from the document when it declares
  exactly one API key or bearer scheme. Use `-keyless` for an API without a
  key.
- The key's vault name defaults to `NAME_API_KEY`; `-key VAR` picks another.

**Tools that change something** (POST, PUT, PATCH, DELETE) are not served
after approval alone. Name the tool in a role marked `non_read = true`
(`gatte roles edit`; the file has a commented example), then:

```sh
gatte clear abuseipdb report
```

## Add a person

```sh
gatte user add maria -name "Maria Silva" -email maria@example.org
docker exec gatte gatte connect maria -os macos > connect-maria.sh
```

`user add` prints a one-time password, once. Send the password and the
script to the person over a channel you trust. The script installs the
private CA, adds Gatte to Claude Code, and tells them to run `/mcp` and sign
in.

New people go in the `soc-analysts` group, which maps to the `analyst` role.
`-group G` picks another group.

## Roles

Who may call what is one file, `roles.toml` (design/adr/0009):

```sh
gatte roles edit                                  # in vi; applied on save
docker exec gatte gatte roles show > roles.toml   # keep it in version control...
docker exec -i gatte gatte roles set < roles.toml # ...and load it back
```

A file the gateway refuses is not applied: the previous one is put back.

## Everyday

| Task | Command |
|---|---|
| What is registered, what waits for review | `gatte status` |
| Check everything end to end | `gatte selftest SERVER SAFE_TOOL [SENSITIVE_TOOL [ARGS_JSON]]` |
| Rotate an API key | `gatte secret set NAME` (takes effect on the next call) |
| List people / reset a password / remove one | `gatte user list` / `gatte user reset U` / `gatte user rm U` |
| Cut a person off immediately | `gatte mcp access block U` |
| Read the audit trail | `gatte mcp audit -limit 50` |
| Any other mcp-gateway command | `gatte mcp ...` |
| Logs | `docker logs -f gatte` |

`gatte selftest` signs in as a throwaway analyst with the same PKCE flow
Claude Code uses, calls a tool through the gateway, checks that a sensitive
tool is refused, and deletes the analyst:

```sh
docker exec gatte gatte selftest petstore findPetsByStatus addPet '{"query_status":"available"}'
```

## Upgrade

```sh
docker pull ghcr.io/bunnyiesart/gatte:NEW
docker rm -f gatte
docker run -d --name gatte --restart unless-stopped -p 443:443 \
  -v gatte:/gatte ghcr.io/bunnyiesart/gatte:NEW
```

Keys, vault, database and accounts live in the volume.

## Inside the container

Each process runs as its own account:

| Process | Account |
|---|---|
| Authelia | `authelia` |
| Caddy | `caddy` (binds 443 by capability, not as root) |
| the gateway and its operator socket | `gatte` |
| the accounts socket (edits the IdP's users) | `root`, as on a host install (design/adr/0038) |

Everything is under `/gatte`:

| Path | What |
|---|---|
| `/gatte/etc` | settings, signing key (root only), vault and its key, private CA, generated config |
| `/gatte/site` | `roles.toml`, optional `extra.toml` (any other `config.toml` section), OpenAPI documents |
| `/gatte/data` | the database: registry, approvals, audit trail |
| `/gatte/authelia`, `/gatte/authelia-data` | the identity provider's config, secrets, accounts |
| `/gatte/edge`, `/gatte/caddy` | Caddy's config, certificate, ACME state |

Back up the volume as one: the signatures in the database are checked
against the key beside them.

## Certificates

- `GATTE_TLS=internal` (default): the private CA signs a certificate for both
  names. `gatte ca` prints the CA certificate, and
  `https://GATTE_DOMAIN/ca.crt` serves it. The connect script installs it on
  the analyst's machine.
- `GATTE_TLS=acme`: Caddy gets a public certificate from Let's Encrypt. Both
  names must be reachable from the internet on 443 and 80.

## Try it on one machine

`gatte.localtest.me` and every name under it resolve to `127.0.0.1`:

```sh
docker run -d --name gatte -p 8443:8443 -e GATTE_DOMAIN=gatte.localtest.me \
  -e GATTE_PORT=8443 -v gatte:/gatte ghcr.io/bunnyiesart/gatte:0.3.0
```

## Build it yourself

```sh
docker build -f deploy/docker/Dockerfile -t gatte:local .
```

`deploy/docker/compose.yaml` runs the same single container, for those who
keep their services in a compose file.

## Limits

- Gatte refuses an API on a private or loopback address (`10.x`,
  `192.168.x`, `127.x`). This is its egress guard (`design/adr/0048`).
- The console has one session at a time, and records its actions in the
  audit trail as `root`: who was at the other end of the SSH tunnel is in
  the host's SSH log.
- `upstream update` does not re-read an OpenAPI document. To pick up a new
  version: `gatte api rm NAME`, then `gatte api add` again.
- No backup timer. With the container stopped,
  `docker run --rm -v gatte:/gatte -v "$PWD":/out debian tar czf /out/gatte.tgz /gatte`
  is a full backup.
