# Gatte

A self-hosted MCP gateway for blue teams.

Analysts today run each MCP server -- SIEM search, EDR, threat intel, case
management, a script someone wrote -- on their own laptop, each with its
own copy of a production API key. Gatte replaces that with **one
authenticated endpoint on one host**. The keys live there, encrypted; the
analysts' MCP clients hold only a short-lived login token; and every call
is checked, recorded and shipped to your SIEM.

```
 analyst's MCP client                        gateway host
 (Claude Code, an IDE, ...)   ┌───────────────────────────────────────────────┐
   holds: an OIDC token       │ reverse proxy   TLS, request rate, body size  │
   holds: no API keys         │      │                                        │
          │  HTTPS            │      ▼  loopback only                         │
          └──────────────────►│ Gatte ── checks the call (below)              │
                              │      │                                        │
                              │      ├──► tool process (stdio)      ◄── keys  │
                              │      └──► tool container (podman)   ◄── keys  │
                              │                                   from vault  │
                              │ audit trail (SQLite) ──► JSONL / GELF ─► SIEM │
                              └───────────────────────────────────────────────┘
```

**Contents:**
[How a call is handled](#how-a-call-is-handled) ·
[What you get](#what-you-get) ·
[Quick start](#quick-start) ·
[First call](#first-call) ·
[Connecting analysts](#connecting-analysts) ·
[Adding any tool](#adding-any-tool) ·
[Day-to-day operation](#day-to-day-operation) ·
[The web console](#the-web-console) ·
[The management API](#the-management-api) ·
[Security model](#security-model) ·
[Status](#status) ·
[Repository map](#repository-map)

New to MCP or credential brokering? [`CONCEPTS.md`](CONCEPTS.md) is a primer.

## How a call is handled

Every `tools/call` goes through the same gates, in this order. The first
one that says no ends the call, and the refusal is written to the audit
trail with its reason.

1. **Who are you?** The request carries a bearer token (a JWT) from your
   OIDC provider. Gatte checks its signature against the provider's
   published keys, its issuer, its expiry and that its audience is this
   gateway -- so a token minted for another service of the same provider is
   refused (RFC 8707). A bad token gets `401` and nothing that says which
   check failed.
2. **Are you blocked?** An operator can block one analyst, for good or
   until a set time. That takes effect on their next request, whatever
   token they hold, without a restart.
3. **Does your role allow this tool?** Groups in the token map to roles;
   roles list the tools they may use. A tool you are not granted looks
   exactly like a tool that does not exist.
4. **Has a human approved this tool?** Every tool a backend advertises
   starts in *quarantine*: invisible and uncallable until an operator reads
   its definition and approves it. If the backend later changes the tool's
   name, description or schemas, the tool stops being served until someone
   approves the new version against a diff.
5. **Is the backend there?** A backend that is down, reconnecting or in
   planned maintenance is not called; the analyst's model is told which
   backend, since when and when Gatte retries, instead of a bare error.
6. **Are you within your limits?** At most 4 calls in flight per analyst
   (configurable), and, optionally, a per-analyst budget against each paid
   third-party API.
7. **Record it, or refuse it.** The call is written to the audit trail
   *before* it is forwarded. A call that cannot be recorded is not made.
8. **Run it with the real credential.** Gatte starts the backend (a local
   process or a hardened container) with the API keys that backend was
   registered for, decrypted in memory. The analyst's own token is never
   passed on.
9. **Check what comes back.** The result must fit the size ceiling and the
   tool's declared output schema, and it is scrubbed of the credential
   values Gatte injected -- so a backend that echoes its own API key does
   not hand it to the analyst.

When Gatte refuses or gives up for a reason of its own (a limit, a spent
budget, a backend that is down), it says so in words the analyst's model
can act on, to an analyst granted that tool and nobody else.

## What you get

**Protecting the credentials and the calls**

| Feature | What Gatte does | Decided in |
|---|---|---|
| **Secrets** | All backend credentials in one sops+age encrypted file. Decrypted in memory, injected into the backend's environment at spawn, never logged, never returned. The backend's environment is built from scratch, not inherited. | `design/adr/0003`, `0005` |
| **Identity** | OIDC bearer tokens, asymmetric signatures only, validated audience. Protected-resource metadata (RFC 9728), with the scopes clients must request, so clients discover the IdP by themselves. | `0008`, `0042` |
| **Access** | Token groups → roles → tools, by exact name or per backend. Roles live in the config file, so widening one is a reviewed diff, applied with `reload` without a restart. | `0003`, `0044` |
| **Kill switch** | `access block SUBJECT` refuses one analyst from their next request; `-until` makes the block end by itself. Block, unblock and expiry are audited. | `0031`, `0046` |
| **Tool quarantine** | Per-tool approval pinned to a SHA-256 fingerprint of the definition. Hidden characters shown as `\u{XXXX}`, a changed tool shown as a diff. A backend's whole waiting set can be reviewed and approved at once, bound to a manifest of exactly what was shown. | `0032`, `0043` |
| **Signed backends** | A registered backend (command, arguments, image digest, credential *names*) must carry an Ed25519 signature from a key listed in the config file before it is served. Someone who can write the database cannot add or change a backend. | `0010` |
| **Container backends** | `-transport oci` runs a backend with rootless podman from a digest-pinned image: read-only root, no capabilities, non-root uid, pids/memory/CPU limits, no network unless the signed entry grants one. `upstream update -image` moves it to a new digest keeping the approvals of unchanged tools. | `0028`, `0034`, `0043` |
| **Egress** | Network grants are limited to `none` (default), `slirp4netns`, `pasta` or a named podman network. `upstream list -json` shows each backend's network so the host firewall can build its allowlist. | `0033` |
| **Resilience** | Per-call time and size ceilings, a per-analyst concurrency cap, a 1 MiB request body cap, JWKS refetch at most every 30 s, and a panic contained to the one call that hit it. | `0025`, `0035` |
| **Quota** | Optional: cap how many calls each analyst spends against one third-party account per window, so a runaway agent loop cannot burn an API budget. | `0030` |

**Seeing what happened**

| Feature | What Gatte does | Decided in |
|---|---|---|
| **Audit trail** | One hash-chained SQLite record per call, refusal and failure, naming the analyst by stable subject and display name. A JSONL copy for any log shipper and optional GELF straight to Graylog, plus a heartbeat so a dead shipper is noticed. Searchable by analyst, outcome, tool, backend and time range, and exportable as CSV or JSON Lines. | `0012`, `0021`, `0029`, `0037`, `0046` |
| **Backend health** | Each backend is up, reconnecting, down or in maintenance. A down backend's tools stay listed; a call answers with its state; every transition is a `(backend health)` row. Planned maintenance of one backend or of the whole gateway, with a message analysts read. | `0041` |

**Working with it**

| Feature | What Gatte does | Decided in |
|---|---|---|
| **Honest answers to the analyst** | Refusals the model can act on (result too large, timeout, spent budget with its reset time, calls in flight, a tool pulled mid-session, a blocked account), server instructions that explain missing tools, and a built-in `gatte.status` tool with the caller's backends, roles and budget use. | `0041`, `0042` |
| **Connect script** | For each analyst, a script for macOS, Linux or Windows that sets up Claude Code against the gateway and installs `gatte-status`, a local check for when Gatte cannot be reached at all. | `0039`, `0041` |
| **People** | Roles, their groups and who has used the gateway. With the root-only accounts socket, edit the identity provider's accounts (Authelia file backend): add a person with a one-time password, change groups, disable, **offboard** (disable + block in one audited action) or delete. | `0038`, `0046` |
| **Change without a restart** | `reload` applies roles, groups and quota to the running gateway and records what changed; `upstream redial` picks up one backend's rotated credential or new container. | `0044` |
| **Safe host care** | `check` says whether the host is right (owners, modes, vault, signatures, chain, schema) with the fix for each problem; `backup` takes a consistent, verified copy while `serve` runs; `restore` refuses a copy it cannot verify; a schema guard stops an old binary from opening a newer database. | `0045` |
| **Web console** | `mcp-gateway ui` serves the operator console on loopback: the approval queue with diffs, people, access, the audit trail, backends and maintenance, quota. No JavaScript, strict CSP, a one-time login link. Optional: `-tags nofront` builds the binary without it. | `0036`, `0040` |
| **Management API** | `mcp-gateway admin` serves every console operation as versioned JSON (`api/admin.openapi.yaml`) on UNIX sockets only, socket-activated and idle-exiting. The operator is whoever the kernel says connected. Any front can be built on `pkg/adminapi` and `pkg/frontkit`. | `0040` |

Gatte was built for one SOC team fronting four existing stdio MCP servers
(lab names `casemgmt`, `logsearch`, `docsearch`, `threatintel`). It is not
a wrapper around an existing product: six gateways were lab-tested
hands-on, and each failed the requirement this project exists for --
brokering static API keys, not only OAuth (`DEVELOPMENT-LOG.md`). Nothing
in the code is specific to those four servers; [`examples/`](examples/)
covers other kinds of blue team tooling.

## Quick start

**The short way, for REST APIs: Docker.** Two files and one
`docker compose up` bring up the gateway, its TLS proxy and its identity
provider, from the published image `ghcr.io/bunnyiesart/gatte`; every task
after that is one `gatte` command
([deploy/docker/README.md](deploy/docker/README.md), `design/adr/0049`).

The rest of this section sets up a gateway by hand on one Linux or FreeBSD
host, with one backend. Use it for MCP servers that run as a process or a
container (`stdio`, `oci`), which the image does not serve.

### What you need

- **Go**, the version in `go.mod` (1.27.1). Distribution packages are
  usually older (Ubuntu 24.04's is), so take the tarball from
  <https://go.dev/dl/> and check its sha256
  (`https://go.dev/dl/?mode=json&include=all` lists every file's):

  ```sh
  curl -fLO https://go.dev/dl/go1.27.1.linux-amd64.tar.gz
  echo "63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445  go1.27.1.linux-amd64.tar.gz" | sha256sum -c
  # linux-arm64: 3450b45a3f9ee8568792736a5c5e70a1f2e9b36c35a8f74958c03e51d7d92bec
  sudo tar -C /usr/local -xzf go1.27.1.linux-amd64.tar.gz
  export PATH=/usr/local/go/bin:$PATH
  echo 'export PATH=/usr/local/go/bin:$PATH' >> ~/.profile   # so a new login finds go
  ```

- **`sops`** 3.13.2 or later. Ubuntu does not package it; take the release
  binary and check it against the release's checksum file (FreeBSD:
  `pkg install sops`):

  ```sh
  V=v3.13.2 A=amd64                  # or A=arm64
  base=https://github.com/getsops/sops/releases/download/$V
  curl -fLO "$base/sops-$V.linux.$A" -fLO "$base/sops-$V.checksums.txt"
  sha256sum -c --ignore-missing "sops-$V.checksums.txt"
  sudo install -m 0755 "sops-$V.linux.$A" /usr/local/bin/sops
  ```

- **`age`** (`apt install age`, `pkg install age`) and `make`.
- **An OIDC provider** that puts group names in a token claim.
- **A TLS-terminating reverse proxy** on the same host. Gatte listens on
  loopback only, terminates no TLS, and refuses to start on any other
  address. `deploy/gateway-jail/nginx.conf` is a working nginx example.
- **Rootless podman**, only if you want container backends
  (`-transport oci`).

### Who owns what

The gateway runs as an unprivileged service account, `mcpgw` below. The
layout matters for security, so it is worth understanding before you type
(`mcp-gateway check` verifies it for you):

| File | Owner | Why |
|---|---|---|
| `signing.key` | root, `0600`, in a directory the service cannot write | Only root can sign a backend. If the service account could read or replace it, anyone who can write the database could sign their own backend. |
| `config.toml` | root, readable by `mcpgw` | Holds the trusted public keys and the role policy; the service reads it but cannot change it. |
| `age.key` | `mcpgw`, `0600` | The service needs it to decrypt the vault. |
| `secrets.enc.json` | root, group `mcpgw`, `0640` | Encrypted credentials. Rotating one is `sops secrets.enc.json`; Gatte never writes it. |
| database, audit log | `mcpgw` | The only things the service writes. |

### Steps

```sh
make build                                        # -> bin/mcp-gateway
sudo install -m 0755 bin/mcp-gateway /usr/local/bin/mcp-gateway

# 0. The service account and the three directories base.toml names.
#    Linux:   sudo useradd --system --home-dir /var/db/mcp-gateway --no-create-home \
#               --shell /usr/sbin/nologin mcpgw
#    FreeBSD: sudo pw useradd mcpgw -d /var/db/mcp-gateway -s /usr/sbin/nologin
sudo install -d -m 0750 -o root  -g mcpgw /usr/local/etc/mcp-gateway   # service reads, cannot write
sudo install -d -m 0750 -o mcpgw -g mcpgw /var/db/mcp-gateway /var/log/mcp-gateway

# 1. A signing key, owned by root (0600). Prints the [signer] lines for the config.
sudo mcp-gateway sign -generate-key -out /usr/local/etc/mcp-gateway/signing.key

# 2. A configuration: the minimal base plus a role policy.
cat examples/base.toml examples/blue-team-roles.toml |
  sudo tee /usr/local/etc/mcp-gateway/config.toml >/dev/null
#    edit: signer.trusted_keys (the line step 1 printed), oidc.issuer, oidc.audience,
#    oidc.scopes_supported (the scopes your IdP's client allows, groups included)
CFG=/usr/local/etc/mcp-gateway/config.toml

# 3. The vault: a flat JSON object of VAR_NAME -> value, encrypted.
#    The plaintext is created owner-only and removed as soon as it is encrypted.
sudo age-keygen -o /usr/local/etc/mcp-gateway/age.key
sudo chown mcpgw:mcpgw /usr/local/etc/mcp-gateway/age.key          # 0600, service only
R=$(sudo age-keygen -y /usr/local/etc/mcp-gateway/age.key)          # the public recipient
umask 077
vi secrets.json      # {"EDR_CLIENT_ID": "...", "EDR_CLIENT_SECRET": "..."}
sops --encrypt --age "$R" --input-type json --output-type json secrets.json |
  sudo tee /usr/local/etc/mcp-gateway/secrets.enc.json >/dev/null
shred -u secrets.json                                              # FreeBSD: rm -P
sudo chgrp mcpgw /usr/local/etc/mcp-gateway/secrets.enc.json
sudo chmod 0640  /usr/local/etc/mcp-gateway/secrets.enc.json

# 4. Register each backend, naming its credentials (names only), and sign it.
#    Operator commands run as the service account, because they write the
#    database it writes; sign runs as root, because only root reads the key.
#    It reads the key as root and then becomes the database directory's owner
#    before opening the database, so it leaves no root-owned file there.
sudo -u mcpgw mcp-gateway upstream register -config "$CFG" -name edr -transport stdio \
  -command /usr/local/bin/your-edr-mcp -env EDR_CLIENT_ID -env EDR_CLIENT_SECRET
sudo mcp-gateway sign -config "$CFG" edr        # or: sign -all -dry-run, then sign -all -manifest SHA256

# 5. Check the configuration and this host's files offline, then run (in
#    the foreground here; under your service manager in production:
#    examples/systemd/).  Every FAIL line carries the command that fixes it.
sudo mcp-gateway check -config "$CFG" -user mcpgw     # -online also asks the IdP
sudo -u mcpgw mcp-gateway serve -config "$CFG"

# 6. In a second shell, while serve runs: approve the tools it observed.
#    An approval, like a revoke, takes effect on the next call, without a restart.
sudo -u mcpgw mcp-gateway tool review  -config "$CFG" -server edr   # every waiting tool + a manifest
sudo -u mcpgw mcp-gateway tool approve -config "$CFG" -server edr -manifest SHA256
#    or one at a time:
sudo -u mcpgw mcp-gateway tool show    -config "$CFG" edr get_host  # the definition and its SHA256
sudo -u mcpgw mcp-gateway tool approve -config "$CFG" -fingerprint SHA256 edr get_host
```

What each step is for:

- **Step 1** creates the key that vouches for backends. The public half goes
  in the config file; the gateway serves only entries signed by a key
  listed there.
- **Step 2.** `scopes_supported` is what MCP clients such as Claude Code
  request when they sign in. Without it they request no scope, which with
  most IdPs means a token without the groups claim, and so no role
  ([Connecting analysts](#connecting-analysts)).
- **Step 3** is the only place a credential value is ever typed. Everything
  else -- the registry, the config, the logs -- refers to it by name.
- **Step 4** uses a placeholder, `your-edr-mcp`. To try it with a real
  backend today, install `examples/ioc_sweep.py` (`examples/byo-script.toml`,
  steps 2-4), register it as `ioc-sweep` with `-env IOC_SWEEP_API_KEY`, put
  `IOC_SWEEP_API_KEY` in `secrets.json`, sign it, and approve
  `ioc-sweep sweep_iocs` in step 6.
- **Step 4 and credentials over stdio.** A stdio backend runs as the
  gateway's own user, so it could read the vault. Gatte therefore refuses a
  stdio entry that declares `-env` credentials unless the config sets
  `[upstreams] allow_credentialed_stdio = true`. `examples/base.toml` sets
  it so this quick start works without podman, and every boot then logs a
  WARN. For production, prefer `-transport oci` and remove that line
  ([Security model](#security-model)).
- **Step 5.** `check` exits 0 when nothing failed, 1 when something did,
  2 when it could not run. It writes nothing.
- **Step 6** is the quarantine. `tool review` and `tool show` print each
  definition with hidden characters made visible; approving needs the
  manifest or fingerprint they printed, so you approve exactly what you
  read. If anything changed in between, nothing is approved.

**Expected warnings.** On this first run `serve` logs "a role grants tools
that match nothing this gateway observed" and "a role grants a backend this
gateway has no upstream registered for". `blue-team-roles.toml` grants tools
on backends you have not registered yet; each grant takes effect once its
backend is registered, signed and approved. Register those backends or
delete the grants you will not use.

**`PATH`.** `serve` runs `sops`, so `sops` must be on the service account's
`PATH`. On Ubuntu, `sudo` resets `PATH` to a `secure_path` that includes
`/usr/local/bin`; elsewhere, check it. That `PATH` and the account's `HOME`
are also what a spawned backend receives.

**Wiring the proxy.** Point the reverse proxy at `listen` (default
`127.0.0.1:8080`) and point MCP clients at the URL you set as
`oidc.audience`. The gateway publishes OAuth protected resource metadata
(RFC 9728) at `/.well-known/oauth-protected-resource`, and also at that
prefix plus the audience's path.

**Next.** Enable the management API and open the web console
([The management API](#the-management-api), [The web console](#the-web-console)),
then add your analysts ([Connecting analysts](#connecting-analysts)).

To try the whole flow without real backends, `make lab-build` builds four
mock MCP servers and one fake REST API into `bin/lab/` that report whether
the injected credential arrived without echoing it (`lab/README.md`).

## First call

The endpoint is MCP's streamable HTTP transport in stateless mode: every
request is one `POST` of one JSON-RPC message, no `Mcp-Session-Id` is
issued or expected, and the answer comes back as `text/event-stream` (one
`data:` line carrying the JSON-RPC response). Use the URL in
`oidc.audience`.

`oidc.issuer` and `oidc.audience` must be absolute `https` URLs with no
query or fragment (`http` only for `localhost`, `127.0.0.1` and `::1`).
`serve` reads the issuer's discovery document at startup and refuses to
start without it.

The bearer token must be a JWT from that issuer, signed with an asymmetric
algorithm (RS\*, PS\*, ES\* or EdDSA) by a key in its `jwks_uri`, unexpired,
with:

| Claim | Must be |
|---|---|
| `iss` | exactly `oidc.issuer` |
| `aud` | `oidc.audience`, or a list containing it (RFC 8707) |
| `sub` | present, with no control characters or edge whitespace |
| `oidc.groups_claim` (default `groups`) | a list with at least one group mapped in `[group_to_role]` |

A token whose groups map to no role authenticates and sees no tools.

```sh
URL=https://gatte.example.org/mcp      # = oidc.audience
TOKEN=...                              # an access token from your IdP
mcp() {
  curl -s "$URL" -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    -H 'MCP-Protocol-Version: 2025-06-18' -d "$1" | sed -n 's/^data: //p'
}
mcp '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}'
mcp '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
mcp '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"edr.get_host","arguments":{"host":"ws-042"}}}'
mcp '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"gatte.status","arguments":{}}}'
# With ioc-sweep registered instead (step 4), the call that answers today:
mcp '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"ioc-sweep.sweep_iocs","arguments":{"iocs":["198.51.100.7"]}}}'
# -> "swept 1 ioc(s): 198.51.100.7; key_present=true; env_names=..." (examples/byo-script.toml, step 4)
```

`tools/list` returns the tools your roles grant and an operator approved,
named `backend.tool`, plus the built-in `gatte.status`. Anything else is
answered as `unknown tool`. A missing, malformed, expired or wrong-audience
token gets:

```
HTTP/1.1 401 Unauthorized
Www-Authenticate: Bearer resource_metadata="https://gatte.example.org/.well-known/oauth-protected-resource/mcp", scope="openid profile email groups offline_access"
```

(`scope=` appears when `oidc.scopes_supported` is set.)

## Connecting analysts

Gatte is built and measured against **Claude Code** as the analysts' MCP
client (2.1.285 at the time of writing). Any MCP client that speaks
streamable HTTP and OAuth with PKCE can connect the same way; only Claude
Code has a connect script.

### What the operator sets up once

1. **An OAuth client for Claude Code at the IdP**: a public client (no
   secret, PKCE), with the redirect URI `http://127.0.0.1:PORT/callback`
   and at least the scopes `openid`, `groups` and `offline_access`
   (`offline_access` gives a refresh token, so the short access token
   renews silently).
2. **The gateway's config**:

   ```toml
   [oidc]
   scopes_supported = ["openid", "profile", "email", "groups", "offline_access"]

   [connect]                          # what the connect script carries (all public)
   client_id     = "claude-code"      # the IdP client from step 1
   callback_port = 47823              # the PORT of its redirect URI
   # ca_file     = "/etc/ssl/example-ca/ca.crt"   # when the gateway's CA is your own
   # server_name = "gatte"                        # the server's name in Claude Code

   [analyst]                          # optional: shown to the analyst's model
   contact = "SOC on-call, channel #soc-gatte"

   [analyst.backend_notes]            # one line per backend, only to analysts with a tool on it
   casemgmt = "Cases, alerts and tasks"
   ```

   `scopes_supported` goes into the protected-resource metadata and the 401
   challenge; Claude Code with no scope of its own requests exactly that
   list, so the connect script stores no scope on the analyst's machine
   and a change reaches everyone at their next sign-in. `[analyst]` lines
   are one line of visible characters each, without quotes; `serve`
   refuses a set whose instructions would pass 2000 characters.
   `[oidc]` and `[analyst]` need a restart of `serve`; `[connect]` does
   not, because only the management API reads it, on every request.

### Adding a person

In the web console (`sudo mcp-gateway ui -manage-users`), **People → Add
person** is a four-step assistant: **Person** (full name, username and an
optional email), **Access** (the groups, only groups that map to a role),
**Review** (then **Create account**), and **Connect**: a one-time password,
shown once and stored only as an argon2id hash, and a connect script for
macOS, Linux or Windows. Hand both to the person over a
channel you trust. A front of your own gets the same script from the
management API (`GET /v1/connect/script?os=linux&username=NAME`).

The analyst runs the script on their own machine. It checks that `claude`
is installed, installs the gateway's CA when `ca_file` is set, installs
`gatte-status` and puts it on the `PATH` (on macOS and Linux a line in each
of `~/.zshrc`, `~/.bashrc` and `~/.profile` that exists, or a new
`~/.profile`; on Windows the user `PATH`), checks that Gatte answers
(skipped on macOS and Linux when `curl` is missing, and on Windows when a
CA is set; a failure only warns), adds the server to Claude Code (`claude
mcp add --transport http --scope user --client-id ... --callback-port ...`,
replacing an older entry of the same name), and prints the next step: open
Claude Code, run `/mcp` and sign in. The browser opens at the IdP;
after the sign-in the gateway's tools appear.

### What the analyst sees

- **Tools** named `mcp__<server>__<backend>_<tool>` in Claude Code, plus
  `gatte.status`. The list is fetched once, when Claude Code connects: after
  an operator grants or approves something, reconnect with `/mcp`.
- **A missing tool** is either not granted to the analyst's role or waiting
  for an operator's review; the server instructions tell the model so, and
  name `[analyst] contact`.
- **`gatte.status`** reports the analyst's own name, roles and use of each
  budget their tools spend, the state of the backends of their tools
  (up, reconnecting, down, maintenance, with the operator's message), and
  any maintenance of the whole gateway.
- **Refusals in words**, instead of `internal error`: a result over
  `response.max_bytes` ("larger than Gatte's limit ... narrow the request";
  the call did run), a call over the per-call time limit ("a narrower
  request may finish"), a spent quota (the account, its limit and window,
  when it resets, "do not retry before then"), too many calls in flight
  ("wait for one to finish, retry with the same arguments"), a backend down
  or in maintenance, and a tool pulled from them during the session ("no
  longer available to you, do not try other names").
- **Token renewal is silent**: Claude Code refreshes the short access token
  with the refresh token. When the refresh token itself expires (the IdP's
  setting, e.g. 8 hours), Claude Code shows "Needs authentication": run
  `/mcp` and sign in again.
- **A blocked analyst** also sees "Needs authentication", because Claude
  Code shows every 403 that way; signing in again does not help, and
  `gatte-status` says so.

### When Gatte cannot be reached at all

The connect script installs `gatte-status` (`~/.config/gatte/bin`, or
`%USERPROFILE%\.gatte` on Windows). It needs no token and tells apart:

| Exit | Meaning | What to do |
|---|---|---|
| 0 | Gatte answers and Claude Code is signed in | nothing; `gatte-status -backends` also asks `gatte.status`, at the cost of one model request |
| 1 | the network does not reach Gatte | VPN, DNS, route |
| 2 | TLS failed | the CA, the certificate |
| 3 | Gatte, or the proxy in front of it, is not serving | tell the operator |
| 4 | Gatte is up and Claude Code is not signed in, or the account is refused | `/mcp` and sign in; if it persists, the account is blocked or disabled |
| 5 | unexpected: something that is not Gatte answered at its address, an error the check does not recognise, `curl` missing, or `claude -p` failed under `-backends` | tell the operator, with the line it printed |

It uses only the public protected-resource metadata, the MCP endpoint's
401 challenge and `claude mcp get`, and runs Claude Code from its own
temporary directory with only the user's settings, so a checkout the
analyst stands in cannot load its hooks or MCP servers into the check.
There is no `/healthz`: those public answers already prove DNS, network,
TLS, proxy and the process, and per-backend state needs the caller's
identity.

## Adding any tool

[`examples/README.md`](examples/README.md) walks through the five steps --
register, put credentials in the vault, sign, approve tools, grant to
roles -- with one example per blue team category: SIEM / log search, EDR,
threat intel enrichment, case management, vulnerability scanner, cloud
security posture, and bring your own script. Each example is a config
snippet that was loaded by the real binary.

What a backend must be:

- **An MCP server speaking stdio**, either spawned as a local process
  (`-transport stdio`) or run from a digest-pinned container image
  (`-transport oci`, which needs rootless podman for the gateway's user).
  An HTTP-only MCP server cannot be registered directly; `http` is
  recognised and refused.
- **Configured by arguments and environment variables.** It receives its
  signed arguments, `PATH`, `HOME`, and the variables it declared.
- **No variable whose value is code.** `LD_*`, `DYLD_*`, `GCONV_PATH`, the
  interpreter knobs (`NODE_OPTIONS`, `PYTHONPATH`, `PYTHONSTARTUP`,
  `PERL5OPT`, `BASH_ENV`, `BASH_FUNC_*`, `JAVA_TOOL_OPTIONS`, ...), `PATH`
  and `HOME` are refused as `-env` names on both transports. The names are
  signed; the vault's values are not, so a value must never be able to
  change what code runs.
- **For a stdio backend: code you would trust with the service account**,
  because it runs as that account. Prefer `-transport oci` for anything
  third-party.

### Container backends

```sh
# as the service account: the image must be in mcpgw's own podman store
sudo -u mcpgw podman pull ghcr.io/example/edr-mcp:1.4
sudo -u mcpgw podman inspect --format '{{index .RepoDigests 0}}' ghcr.io/example/edr-mcp:1.4
sudo -u mcpgw mcp-gateway upstream register -config "$CFG" -name edr -transport oci \
  -image ghcr.io/example/edr-mcp@sha256:<64 hex> -arg --network=slirp4netns \
  -env EDR_CLIENT_ID -env EDR_CLIENT_SECRET
```

The image must be pinned by digest, because the signature covers it and a
tag can be repointed. It must already be in the service account's own
(rootless) podman store: the gateway runs `podman run --pull=never`, so an
image pulled by root or by you is not found, and the backend does not
start (`internal/gateway/oci/invocation.go`). Every container gets `--rm -i`, a read-only root,
`--cap-drop=all`, `--security-opt=no-new-privileges`, a numeric non-root
`--user` (default `65534:65534`; set `[oci] user` to the image's own uid if
its files need it) and `--pids-limit`, `--memory`, `--cpus` from `[oci]`
(defaults 256, `512m`, 1.0). No network unless the entry grants one.

The limits need cgroup v2 with the `cpu`, `memory` and `pids` controllers
delegated to the gateway's user. Check before relying on them
(`design/adr/0034`, and `config.example.toml`'s `[oci]` section); where a
controller is missing, the container does not start and the backend shows
up as not connected.

## Day-to-day operation

Every command takes `-config` and validates the whole configuration file,
refusing unknown keys, before doing anything. `mcp-gateway help` and
`mcp-gateway COMMAND` print the full usage. Exit codes everywhere: 0 ok,
1 ran and found a problem, 2 could not run.

Who runs what: operator commands run **as the service account**
(`sudo -u mcpgw`), because they write the database it writes; `sign`,
`check` and `restore` run **as root**, and drop to the database owner
before opening the database. `reload` and `upstream redial` refuse root.
The [web console](#the-web-console) has a button for reviewing, approving
and revoking tools, blocking and unblocking, maintenance, the audit trail
and people. It has none for registering, deregistering, signing or
updating a backend (`upstream update`), for `reload` or `upstream redial`
(the management API has those two, the console does not), or for the host
tasks (`check`, `backup`, `restore`): those stay in the terminal.

### Reviewing tools

| Task | Command | Takes effect |
|---|---|---|
| See what needs approval | `tool list [-server NAME]` | -- |
| Review one tool, or a change to one | `tool show SERVER TOOL` | -- |
| Approve exactly what you reviewed | `tool approve -fingerprint SHA256 SERVER TOOL` | next call |
| Review all of one backend's waiting tools | `tool review -server NAME` | -- |
| Approve exactly that set, all or nothing | `tool approve -server NAME -manifest SHA256` | next call |
| Withdraw an approval | `tool revoke SERVER TOOL` | next call |

`tool review -server NAME` prints every pending and changed tool of one
backend as `tool show` would, diffs included, who can call each once
approved, and a manifest: the hash of exactly that set. `tool approve
-server NAME -manifest SHA256` approves all of them in one transaction, or
none if any tool of the backend appeared, disappeared or changed since.
There is no "approve everything" without a manifest. Each tool gets its own
`(tool approve)` row, plus one `(tool approve set)` row for the act.

**Approving is not granting.** A tool is callable only when it is approved
*and* a role grants it. `tool review` shows who can call each tool, and
says "callable by nobody" when no role grants it.

### Backends

| Task | Command | Takes effect |
|---|---|---|
| See what is registered, signed and up | `upstream list [-json]` | -- |
| Add a backend | `upstream register ...`, then `sign NAME` as root | within one `quarantine.refresh_interval` (default 5 m) |
| Remove a backend (forgets its approvals) | `upstream deregister NAME` | within one interval |
| Move a container backend to a new image digest | `upstream update -image NAME@sha256:HEX NAME`, then `sign NAME` as root | after the signature, within one interval |
| Rotate one backend's credential | `sops secrets.enc.json`, then `upstream redial NAME` | after one round, for that backend only |
| Pick up a backend container you restarted | `upstream redial NAME` | after one round, for that backend only |
| Take one backend out for maintenance | `upstream maintenance on NAME -message TEXT [-until 2h]` | next call |
| Bring it back | `upstream maintenance off NAME` | next call |
| Announce maintenance of the whole gateway | `maintenance on -message TEXT [-until 2026-09-29T15:00:00Z]`, later `maintenance off` | next call |
| See what is in maintenance | `maintenance list [-json]` | -- |

**Upgrading a container backend.** `upstream update -image` changes only
the image and keeps the quarantine. The old signature no longer verifies
the entry, so the gateway stops serving it (whatever
`signer.require_signed` says) until root runs `sign NAME`. At the new
image's first discovery a tool whose definition is byte-identical stays
approved, one that differs becomes `changed` (not served until reviewed),
and a new one is pending; `tool review -server NAME` then shows exactly
those. It keeps an approval for identical text, not identical behaviour:
the new code is what the re-signature vouches for. Deregister instead when
it is not the same backend. The update is an `(upstream update)` row.

**Redial.** `upstream redial NAME` drops the connection to one backend and
dials it again with the vault as it is now. Its calls are answered as
reconnecting until the new process has listed its tools; the other
backends are not touched. It waits for `serve`'s answer (`-wait`, default
2 m) and is an `(upstream redial)` row.

**When a backend goes down** (`design/adr/0041`), its tools stay listed and
a call to one is answered, only to an analyst granted that tool, with which
backend is unavailable, since when and when Gatte retries, and the model is
told to call `gatte.status` before blaming the request. Each up and down is
one `(backend health)` row attributed to `(gateway)`, written only on the
transition (`denied` when it goes down, `allowed` when it comes back).

**Planned maintenance.** `upstream maintenance on NAME -message TEXT`
answers that backend's calls with your message, without calling it, until
`off`; its tools stay listed. `-until` only announces the end: running `on`
again changes the message, keeps the end already announced unless given a
new one, and `-until none` takes it back. `maintenance on` for the whole
gateway is a notice, not a block: calls are still served, and results and
`gatte.status` carry it. The message goes in front of analysts and their
models: one line, at most 200 characters, no hidden characters. Each on and
off is a `(maintenance on)` or `(maintenance off)` row.

### People and access

| Task | Command | Takes effect |
|---|---|---|
| Cut off one analyst | `access block -reason TEXT SUBJECT` | next request |
| Cut them off for a while | `access block -until 8h -reason TEXT SUBJECT` (or `-until 2026-10-01T08:00:00Z`) | next request; ends by itself at that instant, recorded as `(access block expired)` |
| Restore them | `access unblock SUBJECT` | next request |
| See who is blocked | `access list [-json]` | -- |
| Add a person, change their groups, disable them, give a new one-time password | console, **People** (`sudo mcp-gateway ui -manage-users`) | next sign-in, once the IdP reloads its users file |
| Someone leaves | console, the person's page: **Offboard** (blocks their subject and disables the account in one call), then revoke their sessions at the IdP by hand, as the result page says | next request (block); next sign-in (disable) |
| Remove the account | console, the person's page: **Delete**; the trail keeps their rows | once the IdP reloads its users file |

Account editing goes through the management API's accounts socket, served
by root: run the console with `sudo`, or delegate it to a group with
`[admin] account_group`, which then reaches only accounts whose groups all
map to a role. Every change is an audited operator row.

### The audit trail

| Task | Command |
|---|---|
| Read the trail | `audit [-subject ID] [-outcome denied] [-tool SERVER.TOOL] [-server NAME] [-source SRC] [-since TIME] [-until TIME] [-limit N] [-json]` |
| Hand the trail to someone | console, **Audit**: filter, then **CSV** or **JSON Lines** (the filtered rows, newest first, up to 50 000) |
| Check the trail was not edited | `audit -verify [-expect-head HASH]` |
| See quota spend | `quota usage [-analyst SUBJECT]` |

Operator actions are rows too, attributed to the operator and tagged with
where they came from (`[cli]`, `[cli env]`, `[ui]`, `[api]`): `(tool
approve)`, `(tool approve set)`, `(tool revoke)`, `(upstream update)`,
`(upstream redial)`, `(config reload)` (`[signal]` for a bare SIGHUP),
`(maintenance on)`, `(maintenance off)`, `(access block)`, `(access
unblock)`, `(restore)`, and the account rows: `(account add)`, `(account
groups)`, `(account disable)`, `(account enable)`, `(account reset
password)`, `(account offboard)`, `(account delete)`. `upstream register`,
`upstream deregister` and `sign` write **no** row: a backend shows in the
trail only once `serve` acts on it, as a `(backend health)` row with the
reason `backend up: first observed` or `backend removed: ...`, and
`upstream list` is where you see what is registered and signed. Gateway events are
attributed to `(gateway)`: `(boot)`, `(backend health)`, `(access block
expired)`, and the `denied` rows for a new tool, a changed tool and a
signature that fails. In the CSV export,
hidden characters are written as `\u{XXXX}` and a cell a spreadsheet would
run as a formula starts with an apostrophe.

### Changing the configuration

| What changed | How to apply it | Takes effect |
|---|---|---|
| `[[role]]`, `[group_to_role]`, `[quota]` | `reload` (or `systemctl reload mcp-gateway`) | next call; a client sees tools it gained after it reconnects (`/mcp`) |
| Anything else: `listen`, `[oidc]` (`scopes_supported` included), `[analyst]`, `[signer]` (`trusted_keys` included), `[vault]`, `[audit]`, `[telemetry]`, `[response]`, `[oci]`, `[upstreams]`, `[quarantine]` | restart `serve` | after restart |
| `[connect]`, `[idp]`, `signer.key_file` | nothing: `serve` does not read them; the management API reads `[connect]` and `[idp]` on every request, and `sign` reads the key on every run | next use |
| `[admin]` (`operator_group`, `account_group`) | restart the management API backend: it resolves both groups once, when it starts; under systemd that is its next socket activation after its idle exit, or `systemctl restart mcp-gateway-admin.service mcp-gateway-admin-accounts.service` | next start of the backend |

`reload` asks the running `serve`, through a row in its database and a
SIGHUP, to re-read its own `-config` (`design/adr/0044`). The whole file is
loaded and validated first; if it does not load, or the new `[quota]`
disagrees with the registry, nothing changes, and the refusal is printed
and recorded. Applied, it prints and records, as one `(config reload)` row,
which role gained and lost which tool, whose grant was rewritten (even when
it reaches the same tools today) and which group moved, plus every key that
differs from the file `serve` started with and is **not** applied until a
restart. A bare SIGHUP (`kill -HUP`) reloads too, and its row says
`[signal]`; `examples/systemd/mcp-gateway.service` has the `ExecReload=`.

### Taking care of the host

| Task | Command | Takes effect |
|---|---|---|
| Check the host before a start or after a change | `check [-user mcpgw] [-online] [-json]`, as root | -- |
| Take a consistent copy of the database | `backup -out DIR [-keep N]` (serve may run; `examples/systemd/mcp-gateway-backup.timer` daily) | -- |
| Put a copy back | `restore -in FILE -expect-head HASH`, as root, with serve and the management sockets stopped | at the next start |
| Upgrade or roll back the binary | [`docs/upgrade.md`](docs/upgrade.md) | at the next start |
| Re-sign everything, e.g. after rotating the signing key | `sign -all -dry-run`, read the plan, then `sign -all -manifest SHA256`, as root | within one interval |
| Print the build and database schema | `version` | -- |

**`check`** answers "is this host right?" (`design/adr/0045`): the
configuration loads; the signing key is root's, `0600`, unreadable by the
service account and in a directory it cannot write; the configuration is
not writable by it; the age key is owner-only and its; the database, its
`-wal` and `-shm` and the SIEM file are writable by it; `sops` is on `PATH`
and the vault decrypts and holds every credential name a backend declares
(no value is printed); `oci` backends have `podman` and subordinate ids;
every entry is signed by a trusted key; the audit chain verifies; the
database's schema is one this binary knows and has no trigger, view or
index the binary did not create; with `-online`, the IdP's discovery
document names this issuer. Each FAIL and WARN comes with the command that
fixes it, and the report ends with what it does not check (ACLs and MAC,
the service manager's `PATH`, whether each backend answers).

**`backup`** copies the database with `VACUUM INTO` while `serve` runs,
without migrating it, checks the copy (integrity, schema, chain,
signatures), prints its sha256 and audit head, and lists what is **not** in
it with this configuration's paths: the configuration, the vault, the age
key, the signing key, the IdP's accounts, the SIEM copy, the connect
scripts' CA (`connect.ca_file`), the proxy's TLS material and the `oci`
backends' images. Keep those separately, and the two keys
offline.

**`restore`** refuses, and changes nothing, unless serve is stopped (it
refuses while anything listens on `listen`; it does not look for the
management sockets, so stop those yourself) and the copy passes the integrity check, the schema guard (including objects the
binary did not create), the chain (to `-expect-head`) and the signatures
against this configuration's trusted keys. It keeps the database it
replaced and records a `(restore)` row. Rows written after the copy was
taken are not in the restored trail; without `-expect-head` the chain only
proves the trail agrees with itself, and `restore` says so.

**The schema guard.** The database records its schema
(`PRAGMA user_version`): every command, `serve` included, refuses a file
written by a newer binary and says what to do, and the first row of each
boot is `(boot)`, naming the build and the schema.

**Rotating the signing key takes two restarts**, because `trusted_keys`
is deliberately not reloadable:

1. `sudo mcp-gateway sign -generate-key -out /usr/local/etc/mcp-gateway/signing-2.key`
   and add its public half to `trusted_keys` **beside** the old one.
   Restart `serve` (the new key is trusted from here).
2. Point `signer.key_file` at the new key (only `sign` reads it, on every
   run), then `sudo mcp-gateway sign -config "$CFG" -all -dry-run`, read
   the plan, and `sudo mcp-gateway sign -config "$CFG" -all -manifest SHA256`.
   `upstream list` shows `yes` for every entry.
3. Remove the old key's line from `trusted_keys` and restart `serve`.
   Delete the old key file.

**Stopping `serve` itself** (an upgrade, a host reboot):
`maintenance on -until ...`, give open sessions a few minutes to read it,
stop `serve`, work, start it, then `maintenance off`; for an upgrade,
`docs/upgrade.md` puts a `backup` and two `check` runs in between. While
`serve` is stopped nothing answers inside MCP; the service manager
restarts it on failure (`Restart=on-failure` under systemd, `daemon -r` in
the FreeBSD rc.d script, `deploy/gateway-serve.md`). A proxy in front of
`serve` may answer 503 with a one-line maintenance sentence meanwhile: that
body reaches Claude Code and `gatte-status`.

### During an incident

Do two things. `access block` (or **Offboard** for someone who leaves)
stops the analyst at the gateway immediately. It does not touch the IdP:
their token stays valid there until it expires, so revoke the session at
the IdP too. The block's audit row names the login account that ran it and
says where the name came from: `[cli]` when the kernel said it (on Linux,
the loginuid, which survives `sudo`), `[cli env]` when it was `SUDO_USER`
or `USER`, `[ui]` from the console. Say who did it in `-reason` when the
row can only name a shared account.

### What to alert on in the SIEM

Gatte sends no alerts itself; the SIEM does, from the JSONL copy of the
trail (`[audit.siem]`) or the GELF copy (`[telemetry]`). The two name the
same things differently: in JSONL the caller is `caller`, the backend
`backend` and the outcome `verdict`; in GELF they are
`_analyst_identity`, `_target_upstream` and `_outcome`. The queries below
use the JSONL names.

- **Silence.** A heartbeat line (`type:heartbeat`) arrives at boot and on
  every maintenance tick, with counters, backends up/reconnecting/down,
  tools pending and changed. It is written only to the JSONL copy; GELF
  carries no heartbeat. Alert when it stops arriving for three intervals,
  not only on what it says (`deploy/freebsd-jail.md`, "Alerting on a chain
  that went quiet").
- **A restart**: a new `boot` value on the heartbeat, or a `(boot)` row.
- **A backend down**: `tool:"(backend health)" AND verdict:denied`, closed
  by the `allowed` row of the same backend.
- **A tool changed**: a `changed` row means a backend altered a tool you
  approved; read the diff before re-approving. New tools and failed
  signatures are `denied` rows attributed to `(gateway)` too.
- **Access and policy changes**: `(config reload)`, `(access block)`,
  `(access unblock)`, `(access block expired)`, `(upstream update)`,
  `(restore)`, and the `(account ...)` rows.
- **Refusal spikes**: `verdict:denied AND NOT caller:"(gateway)" AND NOT
  caller:"(operator*"` (an operator's refused action is a `denied` row too).
  [`docs/how-to/alert-from-the-siem.md`](docs/how-to/alert-from-the-siem.md)
  has every query and the field names of both copies.

## The web console

The same console, as a page in your browser. It is a client of the
management API (below): run it as yourself, as a member of the operator
socket's group, with the backend's socket enabled. It reads no
configuration file and opens no database, and the audit trail names you
from the kernel's credentials of the process.

```sh
mcp-gateway ui                                       # listens on 127.0.0.1:8090
# prints: http://127.0.0.1:8090/login?token=...      works once; keep it private
mcp-gateway ui -socket /run/mcp-gateway-admin/operator/operator.sock   # the default
sudo mcp-gateway ui -manage-users                    # also the accounts socket (root's)
```

On the gateway host itself, open the link. From your own machine, forward the
port first with `ssh -L 8090:127.0.0.1:8090 gateway-host` and open the same
link locally.

| Page | What you do there |
|---|---|
| Overview | See what needs attention: `serve` not reporting, changed and pending tools, unsigned backends, backends down, reconnecting or in maintenance, the gateway's maintenance, blocked analysts, the latest refusals. |
| People | Each role, the groups that map to it and its tools, and everyone the gateway has seen, with a Block button. With `-manage-users`: add a person (a four-step assistant, Person, Access, Review, Connect, ending with the one-time password and the connect script), change groups, disable, give a new one-time password, **Offboard** or **Delete** (`design/adr/0038`, `0039`, `0046`). |
| Tools | Review a definition with hidden characters escaped and the diff coloured, then approve that exact fingerprint (the next waiting tool opens), or revoke. Filter by backend, and review all of one backend's waiting tools on one page, approved together by one "Approve these N" button that carries the set's manifest (`design/adr/0043`). |
| Access | Block, with an optional end, or unblock an analyst, with a reason that goes in the trail. |
| Audit | Filter the trail by analyst, outcome, tool, backend, source and time range, page through it, export the filtered rows as CSV or JSON Lines, and verify the hash chain against your SIEM's head. |
| Backends | What is registered and signed, each backend's state (up, reconnecting, down, in maintenance), since when and why, and a form to start, update or end the maintenance of one backend or of the whole gateway. |
| Quota | Read-only: what each analyst has spent. |

Every button is the management API's action of the same name, the one the
commands above call too, with the same checks and the same audit rows
(tagged `[ui]`); the page shows what the backend answered. `-manage-users`
opens the accounts socket as well and refuses one whose server is not
root. Registering and signing stay in the terminal, because signing needs
root's key.

The console runs only while you run it (Ctrl-C stops it) and binds
loopback only. It uses no JavaScript and a strict Content-Security-Policy.
The login link works once and opens one session of up to 12 hours; for a
new one, restart `mcp-gateway ui`. Requests without that session, from a
non-loopback `Host`, or, for a POST, without the form token or from another
origin are refused (`design/adr/0036`).

## The management API

Every console operation is also a versioned JSON API, `mcp-gateway admin`,
for fronts other than the one above (a deployment's own web console, a
TUI, a bot on the gateway host). It listens on UNIX sockets and nothing
else, and takes the operator's name from the kernel, never from the
request:

```sh
# systemd: examples/systemd/ (socket-activated, exits 5 minutes after the last request)
sudo systemctl enable --now mcp-gateway-admin.socket mcp-gateway-admin-accounts.socket
# elsewhere, in the foreground, as the service account (root is refused):
sudo -u mcpgw mcp-gateway admin -config "$CFG" \
    -socket /run/mcp-gateway-admin/operator/operator.sock -socket-group gatte-operators
# (in the foreground it does not exit when idle unless -idle is given)
```

- **Two sockets.** The operator socket (group `[admin] operator_group`,
  e.g. `gatte-operators`) serves the tools, access, audit, backends,
  maintenance, quota, reload and connect-script routes. Identity provider
  accounts are served by a second, root-only socket (`admin -accounts`);
  a group it is delegated to (`[admin] account_group`) reaches only the
  accounts whose groups all map to a role. Both backends resolve
  `operator_group` and `account_group` once, when they start, so a change
  to either takes effect at the backend's next start.
- **The contract** is `api/admin.openapi.yaml`, version 1.4.0, additive
  since 1.0. `GET /v1/whoami` lists the features the backend has --
  `maintenance`, `backend_health`, `tool_review_set`, `serve_control`
  (reload and redial), `audit_filters`, `block_until`, `account_delete`,
  `offboard` -- so a front shows a button only when its action exists.
- **Writing a front**: `docs/admin-api.md`. `pkg/adminapi` is the typed
  client; `pkg/frontkit` carries the loopback, session, CSRF, CSP and
  visible-escaping defences the Gatte console uses. A front adds no rule
  and skips none: it only calls the API.

## Security model

The limits are part of the claim. This section says what Gatte protects
against, and -- just as important -- what it does not.

### At a glance

| Threat | Covered? |
|---|---|
| API keys stolen from an analyst's laptop | **Yes** -- the keys are not on laptops. |
| An analyst using a tool their role does not grant | **Yes** |
| A token minted for another service of the same IdP | **Yes** -- audience is validated. |
| A stolen token after the analyst is revoked | **Partly** -- `access block` is immediate; otherwise the token lives until its `exp`. |
| A backend silently changing a tool's description ("rug pull") | **Yes** -- the tool is withdrawn until re-approved. |
| Hidden instructions in a tool description | **Made visible** -- `tool show` escapes them; a human still has to read it. |
| A tool changing between review and a batch approval | **Yes** -- the manifest no longer matches and nothing is approved. |
| Someone with write access to the database adding a backend | **Yes** -- entries must be signed, and the key is root's. |
| A tampered backup (edited trail, extra trigger, unsigned entry) | **Refused by `restore`** -- except a trail rewritten whole and re-chained, without `-expect-head`. |
| A backend echoing its credential back to the analyst | **Yes** -- results are scrubbed. |
| A compromised container backend reading the vault | **Narrowed** -- takes a container escape, not an `open()`. |
| A compromised stdio backend reading the vault | **No** -- it runs as the gateway's user. |
| A compromised backend sending data anywhere on the network | **Not by Gatte** -- that is the host firewall's job. |
| Prompt injection through a tool's result | **No** |
| Someone running code as the service account | **No** |
| Someone who controls the host rewriting the audit trail | **Detectable only** while a shipper forwards it. |
| One analyst flooding the gateway | **Yes** -- 4 calls in flight per analyst; request rate at the proxy. |
| An unauthenticated flood denying service to analysts | **Mitigated** -- audit rows for failed logins are rate-limited per source. |
| A caller learning which backends are down | **Only their own** -- the state of a backend reaches a caller who holds an approved tool on it, nobody else. |
| A caller probing for tool names through the new refusal texts | **No oracle** -- "no longer available" only for names that caller was listed; anything else is `unknown tool`. |
| Backend text posing as a Gatte status message | **Not preventable in the text** -- `gatte.status` is named as the only authoritative source. |
| A caller learning another analyst's quota use | **Yes** -- `gatte.status` reads only the caller's own counters. |

### In detail

**What it covers.** The production credentials of every backend stop
living on analyst laptops and live in one sops+age file on one host.
Against the analyst -- the actor the design centres on -- the gateway
enforces OIDC with a validated audience, role-to-tool access, and the
per-tool quarantine. Every call, refusal and failure lands in the audit
trail, and the JSONL copy gives the SIEM a record the gateway cannot
rewrite once it has been shipped.

**Revocation has two clocks.** A token is valid until its `exp`, which is
the IdP's to set; revoking an analyst at the IdP does not shorten a token
already issued. Keep access tokens short (the reference Authelia config in
`deploy/vm/` issues 10-minute tokens). `mcp-gateway access block` is
immediate, from the next request (`design/adr/0031`), so an incident needs
both.

**The quarantine is a human check, and it shows what it checks**
(`design/adr/0032`). The approved and the latest observed definition of
each tool are kept under their fingerprints, never rewritten; a definition
over 64 KiB is refused at discovery. `tool show` prints a definition with
invisible code points escaped as `\u{XXXX}`, plus a diff against the
approved one, and `tool approve` needs the `-fingerprint` of what was
shown. A batch approval (`design/adr/0043`) needs the manifest of the whole
set shown, re-derived and compared in the same database transaction that
approves it. Tool names outside `[A-Za-z0-9_-]{1,64}` are not served. Every
approval and revocation writes an operator row with the fingerprints
(`design/adr/0040`). Not covered: nothing judges the text for the
operator.

**Against someone with write access to the SQLite database**, registry
entries are signed with Ed25519 and verified against public keys that live
in the configuration file. That holds only while the private signing key is
out of that actor's reach: `check` fails when the service account can read
the key or write its directory. The provisioning recipe here got that
wrong until 16 Sep 2026 and now keeps the key owned by root. `sign -all`
signs only a plan it printed first, bound by a manifest, so an entry the
attacker left behind is shown before it is signed.

**It is not a control against someone executing code as the service
user.** That actor reads the decrypted vault and writes the trail. A stdio
backend -- the least trusted code in the system -- runs as that same user,
with nothing between it and the process holding every credential
(`AGENTS.md` §2). That is why a stdio entry is not given credentials unless
`[upstreams] allow_credentialed_stdio = true` says so, loudly
(`design/adr/0034`). `reload` and `upstream redial` refuse to run as root,
because the process they signal is named in a table the service account
writes.

The oci transport narrows this without closing it. A container backend has
its own mount namespace with a read-only root and none of the gateway's
files, no capabilities, and a non-root uid that rootless podman maps to a
subordinate host uid rather than the gateway's. Reading the vault then
takes a container escape rather than an `open()`. The container runtime
itself still runs as the gateway's user, and the resource limits hold only
where cgroup v2 delegates them (`design/adr/0028` §D, `design/adr/0034`).

**It does not contain a backend's egress.** A stdio backend has the host's
network, and an oci backend with a network grant reaches anything that
network reaches -- a public API, the rest of RFC 1918, `169.254.169.254` --
so a compromised backend can send its own credential anywhere. Gatte only
chooses the network namespace (`none` by default; `host` and the
namespace-joining modes are refused). Limiting destinations is the host
firewall's job: an outbound rule on the service uid, with the allowlist
derived from `upstream list -json` (`design/adr/0033`). Without that rule,
nothing limits it. Host podman configuration (`containers.conf` network
options) can still open the host's loopback to an accepted mode, so probe
every mode you use.

**What a caller learns about a backend that is down** (`design/adr/0041`).
Only a caller who is authenticated, not blocked, and holds an approved tool
on that backend is told anything, and only through that tool or the
built-in `gatte.status` (which reports the backends of the caller's own
listed tools). To everyone else a call answers exactly what it answered
before -- the policy's `forbidden`, or `unknown tool` for a tool in
quarantine or outside the role. What that caller is told, field by field:
the backend's name (already in the tool's name); its state (`up`,
`reconnecting`, `down`, `maintenance`); since when; the last reconnect
attempt and roughly the next one; and, in maintenance, the operator's
message, its start and its announced end, and whether that end has passed.
Never the cause, the backend's error text, an exit code, a host, an image,
a command, who set a maintenance or when it last changed, any backend the
caller has no tool on, or counts of tools or analysts. Two revelations are
accepted and stated: a caller whose call is in flight when the backend dies
is told it is now reconnecting -- the caller learns the backend died during
their call, which the trail records as `failed (upstream gone)` with their
identity -- and a call a live backend fails is answered "the backend failed
this call", without its error.

Text inside a backend's result that claims to come from Gatte is that
backend's data: nothing in text can prove its origin, so the server
instructions name `gatte.status` as the only authoritative source, and
results Gatte builds itself carry `_meta` key
`io.github.bunnyiesart.gatte/origin`, which an upstream result never does.
No unauthenticated endpoint reports health: the state of backends is only
ever told to an authenticated caller, as above, and to the operator (the
Backends page and `GET /v1/overview` of the management API, over its
operator socket). A tool of a backend that is down stays listed for as long
as its registry entry is servable (registered, valid, signed, covered by
the quota), from the definition a human approved and the backend last
announced; removing or unsigning the entry removes it.

**What a caller learns about Gatte's own limits** (`design/adr/0042`).
Again only a caller granted and approved for the tool: that its result was
over the size ceiling, and the ceiling (the call ran; no byte of the result
is sent); that the backend did not answer within the per-call limit, and the
limit; that their own allowance on an account is spent, with the account's
name, its limit, its window and when it resets -- never a count; and that
they already have N calls in flight, N being the cap. `gatte.status` adds
the caller's display name, role names and, for each budget their served
tools spend, their own use in the current window: the one counter read on
the request path, through a port that answers for one analyst per question
and is called with the request's verified subject only (a fitness function
pins the call site). A tool the caller was listed in their own `tools/list`
and that is no longer served to them answers "no longer available to you",
the same words for every cause, from a memory of what each subject was
listed that lives in the process for seven days; a name the caller was
never listed gets the SDK's `unknown tool` as before, and a restart
forgets. The 403 of a blocked account says signing in again will not help,
and never why.

**A backend that echoes its own credential does not hand it to the
analyst.** Every result is scrubbed of the values the gateway injected into
that backend, in raw and escaped forms, and a result that cannot be
scrubbed is refused rather than forwarded. No decision record covers it;
the behaviour is `scrubResult` in `internal/gateway/endpoint.go`, and its
tests beside it.

**An `http` backend is a REST API Gatte itself calls** (`design/adr/0047`,
`design/adr/0048`). Its tools are generated at `upstream register` from
the API's OpenAPI document, one per operation, frozen in the entry and
covered by its signature, so a changed document changes nothing served
until the entry is registered again. For each call Gatte is the HTTP
client: the API key is resolved from the vault and injected server-side,
where the signed entry says (a bearer token, a header or a query
parameter), into a request the analyst's client never held a key for. The
document is third-party text at every edge -- only the base path of its
`servers[]` is used, its host never; a path, a parameter or a tool name it
declares is refused unless it passes the adapter's own checks -- and the
destination is pinned to the registered URL, with redirects to any other
origin refused and loopback, private, link-local and the cloud metadata
range refused by the resolved address, not by the name. A key the API
reflects -- in a redirect's `Location`, a `Set-Cookie`, a body quoting it
-- is masked twice, by the adapter with the value it injected and by
`scrubResult`, and never appears in an error either. Every non-safe
operation (`POST`, `PUT`, `PATCH`, `DELETE`) is a *sensitive* tool: approval
alone does not make it callable, the operator must also `tool clear` it,
and it is reachable only from a role marked `non_read` that names it, never
through a wildcard grant. `make lab-probe-rest` proves all of this against
the lab's fake API (`lab/README.md`, "The REST probe").

**It does not guarantee the trail's integrity against whoever controls the
host.** Records are hash-chained, not individually signed, and the chain
has no key. Comparing the chain head against the SIEM's copy with
`mcp-gateway audit -verify -expect-head HASH` detects truncation or
rewriting of the local trail, but only while a shipper is actually
forwarding the file, and not against an attacker who also forges the
shipped lines. Nothing compares the two automatically.

**It terminates no TLS** and refuses at startup any bind that is not
loopback, with no override. Everything network-facing depends on a
co-located reverse proxy and your network controls (`design/adr/0011`).

**It is a single point of failure, knowingly** (`design/adr/0001`): one
binary, one process, one SQLite file. `backup` and `restore` are how you
survive losing the disk. What bounds the load:

- a per-call time and size ceiling (`design/adr/0025`);
- at most `response.max_concurrent_calls_per_analyst` calls in flight per
  analyst, default 4, refused before any quota is spent (`design/adr/0035`).
  There is no global or per-backend cap, so seven analysts can together
  hold 28 slots;
- request bodies over 1 MiB get `413`;
- the IdP's keys are refetched at most once per 30 s, however many forged
  tokens arrive;
- a panic fails only the call that hit it, and is audited;
- audit rows for failed authentication are rate-limited per source
  (`design/adr/0027`). Measured: without that, an unauthenticated flood
  exhausted SQLite's busy timeout and got analysts' calls refused, because
  a call that cannot be audited is refused.

Request-rate limiting belongs to the reverse proxy; the reference nginx
configs in `deploy/` set `limit_req` and `limit_conn`.

**Prompt injection through a tool's result is not covered.** The response
check is a size ceiling plus validation against a declared output schema
(`design/adr/0014`). Neither can tell a malicious result from a real one.

**Credentials are resolved when a backend is spawned**, so rotating one in
the vault reaches an already-connected backend only when it is dialled
again: `upstream redial NAME` for that backend, or a restart for all of
them. The gateway warns while the old value is in use
(`deploy/freebsd-jail.md`, "Rotating credentials").

These limits came out of repeated adversarial review rounds, one of which
audited the whole system; each round found controls that were documented as
working and could not fire. The repository is written so that the next
finding can be proved rather than argued.

## Status

**Read [`CLOSEOUT.md`](CLOSEOUT.md) before trusting this in production.**

- All seven build phases in `WORKFLOW.md` are closed, and the v1 criterion
  (`design/adr/0026`) is met -- but its three conditions are about a
  development machine. "v1 declared" and "v1 running" are different claims,
  and only the first has been made.
- The end-to-end checkpoint passes: a client holding no backend credential
  reaches four spawned backends over HTTP, each receiving its injected
  secret, with that secret appearing nowhere the client can observe.
- The controls in ADRs 0031-0035 (kill switch, quarantine events, egress,
  container hardening, call resilience) were exercised on a Linux test VM
  with rootless podman on 28 Sep 2026. Panic containment is proven by unit
  tests only.
- ADRs 0036-0046 (web console, analyst name, IdP accounts, connect script,
  management API, backend health and maintenance, analyst refusals and
  scopes, batch review and image update, reload and redial, check, backup
  and restore, audit search and offboarding) were exercised on the same
  test VM on 29-30 Sep 2026, including after a reboot. The sign-in flow
  Claude Code uses with no scope of its own was reproduced there against
  the advertised scopes (groups claim and refresh token present); a real
  interactive Claude Code sign-in was measured against a stand-in server.
- Open tracks: the SIEM anchor comparison has no owner, the older half of
  the design record has not been swept, and some proofs skip where `sops`
  and `age` are missing.
- This repository is a sanitized public copy of an internal SOC build.
  Backend names, addresses and hostnames are stand-ins (RFC 5737 / RFC 2544
  addresses, `*.example.internal`), held there by
  `internal/fitness/sanitize_test.go`. Older pushed history still carries
  the real ones (`CLOSEOUT.md` Track 6). Some ADRs referred to in
  `CLOSEOUT.md` live only in the private repository.

A running gateway keeps itself in step with the registry: `upstream
register`, `upstream deregister` and a signature that stops verifying take
effect within one `quarantine.refresh_interval` plus the time one
maintenance round takes (`design/adr/0013`, 28 Sep 2026 correction). An
unreadable registry serves nothing until it can be read again
(`design/adr/0020`). Role, group and quota changes take effect with
`reload`, and a rotated credential with `upstream redial NAME`, without a
restart (`design/adr/0044`); the rest of the configuration needs one.

## Repository map

| Path | What it is |
|---|---|
| `cmd/mcp-gateway/` | The binary: `serve` (composition root), the operator commands, `admin`, `ui`, `check`, `backup`, `restore`. |
| `internal/config/` | The TOML configuration contract and its validation. |
| `internal/access/` | OIDC token verification, roles, grants, and the analyst blocklist. |
| `internal/registry/` | Registered backends. |
| `internal/signer/` | Ed25519 signing and verification of registry entries. |
| `internal/quarantine/` | Tool quarantine: pending, approved, changed, the definitions they refer to, and review sets. |
| `internal/visible/` | Escapes invisible and control code points in untrusted text as `\u{XXXX}`. |
| `internal/vault/` | Credential vault; `sopsage/` is the sops+age adapter. |
| `internal/gateway/` | Routing, dispatch, the stdio and oci dialers, the HTTP MCP endpoint, refusals, `gatte.status`. |
| `internal/health/`, `internal/control/`, `internal/reload/` | Backend health and maintenance; operator requests to the running `serve`; the reload diff. |
| `internal/audit/` | Hash-chained SQLite trail and the JSONL SIEM sink. |
| `internal/telemetry/` | GELF copy of the trail, straight to Graylog. |
| `internal/quota/` | Per-analyst call budgets against third-party accounts. |
| `internal/admin/` | The management service every front and the CLI call, and its HTTP-over-UNIX-socket server (`adminhttp/`). |
| `internal/idp/`, `internal/peercred/` | The identity provider's accounts (Authelia file backend); the kernel's peer credentials of a socket client. |
| `internal/front/gatteweb/` | The Gatte web console (left out with `-tags nofront`). |
| `pkg/adminapi/`, `pkg/frontkit/` | Public: the management API's typed client, and the defences a web front needs. |
| `api/admin.openapi.yaml` | The management API's contract. |
| `internal/store/` | The single shared SQLite connection and the schema guard. |
| `internal/e2e/`, `internal/fitness/` | End-to-end checkpoint and architecture fitness tests. |
| `lab/` | Mock MCP servers, a fake REST API, the credential-leak probe, and a traffic generator. |
| `deploy/`, `scripts/` | Provisioning scripts and runbooks for the reference test deployments. |
| `design/` | Discovery, components, style, and one ADR per significant decision. |
| `examples/` | Blue team configuration examples, and systemd units (`examples/systemd/`). |
| `config.example.toml` | The full configuration reference, every key documented. |

## Documentation map

- **`examples/README.md`** -- how to put any tool behind the gateway.
- **`config.example.toml`** -- every configuration key and what goes wrong
  if you get it wrong. Its comments are in Portuguese.
- **`docs/upgrade.md`** -- upgrading the binary with a checked backup,
  and rolling back.
- **`docs/admin-api.md`** and **`api/admin.openapi.yaml`** -- the
  management API, and how to write a front for it.
- **`examples/systemd/README.md`** -- the units for `serve`, the
  management API sockets and the daily backup.
- **`CONCEPTS.md`** -- a primer on MCP, gateways, credential brokering and
  API security.
- **`design/adr/`** -- one file per decision, with context, decision and
  consequences. The later ones are in Portuguese.
- **`PRODUCT.md`**, **`DESIGN.md`** -- who the web console is for, and its
  visual system.
- **`AGENTS.md`** -- the build brief: confirmed architecture, declared
  limits, what is still open.
- **`WORKFLOW.md`** -- the phased build order and gates. All seven phases
  are closed.
- **`CLOSEOUT.md`** -- what separates "v1 declared" from "v1 running".
- **`DEVELOPMENT-LOG.md`** / **`RESEARCH-recovered.md`** -- the
  investigation history and evidence behind each decision, including the
  six gateways evaluated.
- **`deploy/`** -- runbooks for the reference deployments, including
  credential rotation and alerting on a trail that went quiet.

## Development

Written in Go (`design/adr/0002-language-runtime.md`). `make check` runs
formatting, vet, lint, tests, race tests and the build; `make ci` is the
full gate and needs `sops` and `age` on `PATH`, because it refuses to skip
the vault tests. `go build -tags nofront ./cmd/mcp-gateway` builds the
binary without the web console, and `make nofront` tests that build.

Every behaviour change comes with a regression test that failed before the
change, and a significant decision gets an ADR in `design/adr/`. The
fitness tests in `internal/fitness/` hold the architecture in place: which
package may read a secret, that every adapter's migration is wired, that
every test a document cites exists, and that no real deployment value
reaches this public tree.

This repository follows the `solo` profile of a repository-hardening
standard (`.hardening.toml`). The pre-commit hook in `.githooks/` is a local
guardrail, not a control. **Commits are not signed.** An earlier version of
this README said they were; measured on 12 Sep 2026, no commit in the
history ever was. The owner decided to keep signing off, and
`.hardening.toml` declares that as a `commit-signing` exception with its
reason, approver and a review date of 12 Mar 2027.

## License

Apache License 2.0. Copyright 2026 Gabriel Coelho. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
