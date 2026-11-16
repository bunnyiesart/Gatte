# Gatte in Docker

One `docker run` brings up the gateway, its TLS proxy (Caddy) and its
identity provider (Authelia) in one container, and `gatte setup` configures
it. No file to download, nothing to clone. Every operator task after that is
one command. Why it is built this way: `design/adr/0049`.

This image serves **REST APIs** (`-transport http`): Gatte reads an API's
OpenAPI document and turns each operation into a tool your analysts' Claude
Code can call, with the API key injected server-side. MCP servers that run
as a process or a container (`stdio`, `oci`) are not served from this image;
use the host install in the top-level `README.md` for those.

This README is the canonical guide for installing and running the image. It
supersedes any standalone "Gatte setup" or "Gatte VM setup" guide handed out
separately; follow this file.

## Install

You need Docker (or Podman), and DNS for two names pointing at the host:
`gatte.example.org` and `auth.gatte.example.org`. Analysts reach both on
443. Three steps:

**1. Verify the image.** Take the digest of the latest release from its
GitHub release page, and check it was built by this repository's workflow:

```sh
IMAGE=ghcr.io/bunnyiesart/gatte@sha256:DIGEST
gh attestation verify oci://$IMAGE --repo bunnyiesart/Gatte
```

**2. Run it, by digest.** A tag can be moved to another image; a digest
cannot.

```sh
docker run -d --name gatte --restart unless-stopped \
  -p 443:443 -p 127.0.0.1:8090:8090 -v gatte:/gatte "$IMAGE"
```

Add `-p 80:80` only if you will pick Let's Encrypt (`acme`) in the next
step. Until setup is done the container starts nothing and opens no port:
`docker logs gatte` says `not configured: docker exec -it gatte gatte setup`,
and the healthcheck stays unhealthy.

**3. Set it up.**

```sh
docker exec -it gatte gatte setup
```

It asks, in order, and skips any step already done, so it is safe to run
again:

1. The domain, and TLS: `internal` (a private CA made here, the default) or
   `acme` (Let's Encrypt, with an email). It warns when a name does not
   resolve.
2. An optional second factor at sign-in: TOTP, off by default. Opting in
   asks for a `docker restart gatte` to apply it; see "Second factor" below.
3. It waits for `gatte: up`.
4. The first person: username, display name, email, group (`soc-analysts`
   or `dfir-leads`). It prints their one-time password, once, and the line
   that writes their connect script.
5. Backends (below). None are bundled.
6. An optional self-test, then a summary: URLs, the CA fingerprint, the
   backup and upgrade commands.

Every prompt that approves something defaults to no. Setup has no option to
serve plain HTTP, skip TLS, turn off signatures or the quarantine, allow
private addresses, approve on its own, or grant a sensitive tool.

Running it again with a different domain warns that this invalidates the
CA certificate, the token audience, every client and every token, asks you
to type the new domain again, and then asks for `docker restart gatte`.

Without questions: `-e GATTE_DOMAIN=gatte.example.org` (and the options
below) on `docker run` configures the container at its first start, and
`gatte setup` then only does the steps that remain. The first start makes
every key, the encrypted vault, a private certificate authority and the
identity provider's secrets, and keeps them in the `gatte` volume.

Options, all `-e`:

| Setting | Default | What |
|---|---|---|
| `GATTE_DOMAIN` | (from `gatte setup`) | The name analysts reach Gatte on; the IdP is `auth.` + it |
| `GATTE_TLS` | `internal` | `internal`: a private CA made here. `acme`: a public certificate from Let's Encrypt (add `-p 80:80` and `GATTE_ACME_EMAIL`) |
| `GATTE_PORT` | `443` | The HTTPS port, when 443 is taken. Publish the same number: `-p 8443:8443 -e GATTE_PORT=8443` |
| `GATTE_2FA` | `off` | `off`: password only. `totp`: require a TOTP second factor at sign-in (see "Second factor") |
| `TZ` | `UTC` | Time zone of the logs |

The settings are kept in the volume: an upgrade can drop the `-e` flags.

## Backends from an MCP JSON file

If your analysts already list their servers in a Claude Code `.mcp.json`,
hand the file to setup on standard input, from the host, while `gatte setup`
is at its backends step (or before it):

```sh
docker exec -i gatte gatte setup import < .mcp.json
```

The import is a shortlist of names, not a turnkey conversion. `setup import`
keeps only each server's name, its kind, the scheme, host and
port of its URL (a path or query can carry a key), and the NAMES of its
headers. No header value,
`env` value or `args` entry is copied anywhere: not to the volume, not to the
log, not to the screen. Setup then lists the servers and, for each one you
pick, registers it and asks for its token with `gatte secret set`, which
does not echo. Retype a token the file held there; it was not kept.

What the image can and cannot register from that file:

- **`"type": "http"` / `"url"` entries** are remote MCP servers. Setup
  registers them natively with `gatte remote add`. Only the URL's origin
  was kept, so setup asks for the full endpoint URL, offering the origin as
  the default: type the path too (for example `https://host/mcp`). A URL
  with no path is registered only if you confirm it, since such a server
  is reached but serves no tools. Where the token goes comes from the
  entry's one header (`Authorization` is a bearer token; any other name is
  that header). An entry with no header is registered with no
  authentication only if you confirm it; one with more than one header is
  left for you to add by hand. A REST API is a separate backend: it is
  not in the file, and you add it by hand with its OpenAPI document.
- **`"command"` entries** (`docker run ...`, `npx ...`, any local process)
  are skipped with a one-line reason. This image runs no backend processes
  and no containers: it has no runtime for them, and it is never given the
  Docker socket, which would hand root on the host to anything in it.

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

## Reaching the gateway and the backends

Three network paths, each different on purpose.

- **Analysts to the gateway.** `https://GATTE_DOMAIN` and
  `https://auth.GATTE_DOMAIN`, both on 443 (or `GATTE_PORT`). Publish that
  port where analysts can reach it. On a private deployment that is usually a
  VPN or a reverse proxy already in front of the host. The connect script each
  analyst runs targets these two names, so both must resolve and be reachable
  from the analyst's machine.

- **You to the console.** The console is never on the network: the container
  publishes it on the host's loopback only (`-p 127.0.0.1:8090:8090`), so you
  reach it through an SSH tunnel to the host and open the one-time link
  `gatte console` prints (see "The web console" above). Only `docker exec`
  prints that link.

- **The gateway to the backends.** The container is the HTTP client: it calls
  each API's base URL outbound, over the host's own routes, so a backend the
  host can reach -- including one behind a VPN or reverse proxy the host holds --
  the container reaches too. Two limits are Gatte's own, not the network's:

  - The egress guard (`design/adr/0048`) refuses a backend whose name resolves
    to a loopback, private (`10/8`, `172.16/12`, `192.168/16`, `fc00::/7`),
    link-local or carrier-grade-NAT (`100.64/10`) address, unless that backend
    opts in (next bullet).
  - The guarded client ignores `HTTPS_PROXY` by design, so backend calls
    cannot be routed through an outbound proxy.

  A backend that lives only on a private address -- a SIEM or case system the
  host reaches over a VPN -- has two answers:

  - **Per-backend allowlist (`-allow-cidr`).** Opt that one backend into the
    private ranges it may reach: `gatte api add NAME -url http://10.1.2.3 ...
    -allow-cidr 10.0.0.0/8` (repeat the flag for more ranges). Only private
    ranges are accepted (`10/8`, `172.16/12`, `192.168/16`, `100.64/10`,
    `fc00::/7`); loopback, link-local and public space are always refused. The
    allowlist is signed with the entry, so it is reviewed and cannot be widened
    by a database write -- it is a scoped opt-in for one backend, never a
    blanket disable of the guard. The web console does not take an allowlist;
    register a private backend in the terminal.
  - **A routable front.** Front the backend at a public name the container
    reaches directly -- commonly the same VPN or reverse-proxy endpoint
    analysts use -- and register that name with no allowlist.

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
- For a backend on a private address, add `-allow-cidr CIDR` (repeat for more)
  to opt its REST egress guard into that private range. See "Reaching the
  gateway and the backends" above.

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

## Second factor

Sign-in is a password by default. Because the gateway brokers production
credentials, `gatte setup` offers an opt-in TOTP second factor, and `-e
GATTE_2FA=totp` turns it on without the prompt. Default (`off`) is unchanged,
so an existing install is unaffected until you opt in.

The choice is applied when the container renders Authelia's configuration, so
turning it on or off takes a `docker restart gatte`. After it is on, each
person enrols an authenticator app the next time they sign in; no
administrator step is needed. WebAuthn/passkeys are not offered here.

```sh
docker exec -it gatte gatte setup        # answer yes at the second-factor step
docker restart gatte                      # apply it
```

## Everyday

| Task | Command |
|---|---|
| What is registered, what waits for review | `gatte status` |
| Check everything end to end | `gatte selftest [SERVER SAFE_TOOL [SENSITIVE_TOOL [ARGS_JSON]]]` |
| Rotate an API key | `gatte secret set NAME`, then `gatte redial NAME` to apply it to the connected backend |
| Re-dial one backend (rotated key, restarted backend) | `gatte redial NAME` |
| List people / reset a password / remove one | `gatte user list` / `gatte user reset U` / `gatte user rm U` |
| Cut a person off immediately | `gatte mcp access block U` |
| Read the audit trail | `gatte mcp audit -limit 50` |
| Any other mcp-gateway command | `gatte mcp ...` |
| Logs | `docker logs -f gatte` |

`gatte selftest` signs in as a throwaway analyst with the same PKCE flow
Claude Code uses, checks the token carries the `groups` claim, refreshes it,
checks the analyst resolves to a role, calls a tool through the gateway,
checks that a sensitive tool is refused, and deletes the analyst:

```sh
docker exec gatte gatte selftest petstore findPetsByStatus addPet '{"query_status":"available"}'
```

## Upgrade

Keys, vault, database and accounts live in the volume; the container is
disposable. An upgrade is a checked backup, then a new container on the new
digest (design/adr/0045 is the same recipe on a host):

```sh
# 1. A consistent copy of the database, checked (integrity, audit chain,
#    signatures), while Gatte runs. Note the audit head it prints.
docker exec gatte gatte mcp backup -out /gatte/backup -keep 7
# 2. Off the volume: a backup on the same disk is not a backup.
docker cp gatte:/gatte/backup ./gatte-backup-$(date +%F)
# 3. Verify the new image, then pull it by digest.
NEW=ghcr.io/bunnyiesart/gatte@sha256:NEW-DIGEST
gh attestation verify oci://$NEW --repo bunnyiesart/Gatte
docker pull "$NEW"
# 4. Stop it, keep a full copy of the volume (keys, vault, accounts and the
#    identity provider's data, which a newer Authelia may migrate), then
#    replace the container; the settings come back from the volume.
docker stop gatte
docker run --rm -v gatte:/gatte:ro -v "$PWD":/out "$NEW" tar czf /out/gatte-$(date +%F).tgz /gatte
docker rm gatte
docker run -d --name gatte --restart unless-stopped \
  -p 443:443 -p 127.0.0.1:8090:8090 -v gatte:/gatte "$NEW"
docker logs -f gatte                       # until "gatte: up at ..."
docker exec gatte gatte selftest
```

**From an image that used the bare domain as the token audience.** The
audience is now the MCP endpoint URL, `https://DOMAIN/mcp`, and the new image
applies it on its first start. A Claude Code entry whose URL is already
`https://DOMAIN/mcp` needs nothing: its next token refresh returns a token for
the new audience. An entry on the bare domain, which connect scripts from
earlier images wrote, stops working: re-issue the scripts
(`gatte connect -all`), and each such analyst runs theirs once and signs in
again from `/mcp`.

**Rollback.** Keep the old digest. If the new release migrated the database,
the old one may refuse it; put the backup from step 1 back with the old
image, then run the old image:

```sh
OLD=ghcr.io/bunnyiesart/gatte@sha256:OLD-DIGEST
docker rm -f gatte
docker run --rm -v gatte:/gatte "$OLD" gatte mcp restore \
  -in /gatte/backup/mcp-gateway-YYYYMMDDTHHMMSSZ.db -expect-head HEAD
docker run -d --name gatte --restart unless-stopped \
  -p 443:443 -p 127.0.0.1:8090:8090 -v gatte:/gatte "$OLD"
```

`restore` refuses a copy that fails the integrity check, the audit chain or
a signature, and keeps the database it replaces beside it. It puts back the
gateway's database only: if the old image's identity provider will not read
its data, restore the whole volume from the copy of step 4 instead. What the trail
recorded after the backup is gone from the database (it is still in your
SIEM copy).

## Scheduled backups

The `Upgrade` step above backs up by hand. For a recurring copy, point cron or
a systemd timer at `deploy/docker/gatte-backup.sh`. It runs `gatte mcp backup`
inside the container -- a consistent, checked copy of the database while Gatte
runs -- and copies it off the volume, keeping the newest few:

```sh
install -m 0755 deploy/docker/gatte-backup.sh /usr/local/sbin/gatte-backup
# 03:30 daily; writes copies under /var/backups/gatte.
echo '30 3 * * * /usr/local/sbin/gatte-backup' | crontab -
```

It reads three optional settings from its environment: `GATTE_CONTAINER` (the
container name, default `gatte`), `GATTE_BACKUP_DIR` (where the off-volume
copies land, default `/var/backups/gatte`), and `GATTE_BACKUP_KEEP` (how many
timestamped copies to keep, default `7`; `0` keeps all). Pruning only touches
directories named in the script's UTC stamp format (`20260101T033000Z`), so
other directories under `GATTE_BACKUP_DIR` are left alone. Put `GATTE_BACKUP_DIR` on storage
separate from the Docker volume for a real off-box backup.

It is not a Compose sidecar on purpose: a sidecar reaching into the container
would need the Docker socket, which is root on the host. The script needs only
the `docker` CLI, as the host user that already runs it.

This copies the **database** only -- the keys, the vault, the private CA and
the accounts are the rest of the volume. For those, the full-volume `tar` in
`Upgrade` step 4 is the backup, and it needs the container stopped.

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

  A CA made by 0.4.0 or later is name-constrained: it can only sign for
  `GATTE_DOMAIN` and the names under it, and never for an IP address, so a
  stolen `ca.key` cannot impersonate any other site to an analyst who trusts
  it. A CA made by an earlier release has no such limit and keeps working.
  To replace it with a constrained one (every analyst then runs a new connect
  script, which installs the new CA):

  ```sh
  docker exec gatte sh -c 'rm -rf /gatte/etc/ca'
  docker restart gatte              # makes a new CA and re-issues the certificate
  docker exec gatte gatte connect USER -os macos > connect-USER.sh   # per person
  ```

  Remove the old CA from the analysts' machines afterwards; it is no longer
  used.
- `GATTE_TLS=acme`: Caddy gets a public certificate from Let's Encrypt. Both
  names must be reachable from the internet on 443 and 80, so publish
  `-p 80:80` too. Port 80 is not needed otherwise.

## Try it on one machine

`gatte.localtest.me` and every name under it resolve to `127.0.0.1`:

```sh
docker run -d --name gatte -p 8443:8443 -e GATTE_DOMAIN=gatte.localtest.me \
  -e GATTE_PORT=8443 -v gatte:/gatte "$IMAGE"
docker exec -it gatte gatte setup
```

## Compose

`deploy/docker/compose.yaml` runs the same single container, for those who
keep their services in a compose file. It has no default image: set
`GATTE_IMAGE` to a verified release digest.

## Limits

- Gatte refuses an API on a private or loopback address (`10.x`,
  `192.168.x`, `127.x`). This is its egress guard (`design/adr/0048`).
- The console has one session at a time, and records its actions in the
  audit trail as `root`: who was at the other end of the SSH tunnel is in
  the host's SSH log.
- `upstream update` does not re-read an OpenAPI document. To pick up a new
  version: `gatte api rm NAME`, then `gatte api add` again.
- No built-in backup timer, but `deploy/docker/gatte-backup.sh` is a ready
  cron/timer job for it (`Scheduled backups` above). It copies the database
  only. The keys, the vault, the CA and the accounts are the rest of the
  volume; with the container stopped,
  `docker run --rm -v gatte:/gatte:ro -v "$PWD":/out "$IMAGE" tar czf /out/gatte.tgz /gatte`
  is a full backup. It holds every secret Gatte has: keep it offline.
