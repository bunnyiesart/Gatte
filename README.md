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
[Adding any tool](#adding-any-tool) ·
[Day-to-day operation](#day-to-day-operation) ·
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
2. **Are you blocked?** An operator can block one analyst with
   `mcp-gateway access block`. That takes effect on their next request,
   whatever token they hold, without a restart.
3. **Does your role allow this tool?** Groups in the token map to roles;
   roles list the tools they may use. A tool you are not granted looks
   exactly like a tool that does not exist.
4. **Has a human approved this tool?** Every tool a backend advertises
   starts in *quarantine*: invisible and uncallable until an operator reads
   its definition and approves it. If the backend later changes the tool's
   name, description or schemas, the tool stops being served until someone
   approves the new version against a diff.
5. **Are you within your limits?** At most 4 calls in flight per analyst
   (configurable), and, optionally, a per-analyst budget against each paid
   third-party API.
6. **Record it, or refuse it.** The call is written to the audit trail
   *before* it is forwarded. A call that cannot be recorded is not made.
7. **Run it with the real credential.** Gatte starts the backend (a local
   process or a hardened container) with the API keys that backend was
   registered for, decrypted in memory. The analyst's own token is never
   passed on.
8. **Check what comes back.** The result must fit the size ceiling and the
   tool's declared output schema, and it is scrubbed of the credential
   values Gatte injected -- so a backend that echoes its own API key does
   not hand it to the analyst.

## What you get

| Area | What Gatte does | Where it is decided |
|---|---|---|
| **Secrets** | All backend credentials in one sops+age encrypted file. Decrypted in memory, injected into the backend's environment at spawn, never logged, never returned. The backend's environment is built from scratch, not inherited. | `design/adr/0003`, `0005` |
| **Identity** | OIDC bearer tokens, asymmetric signatures only, validated audience. Protected-resource metadata (RFC 9728) so clients can discover the IdP. | `design/adr/0008` |
| **Access** | Token groups → roles → tools, by exact name or per backend. Roles live in the config file, so widening one is a reviewed diff. | `design/adr/0003` |
| **Kill switch** | `access block SUBJECT` refuses one analyst from their next request, no restart. Block and unblock are audited operator actions. | `design/adr/0031` |
| **Tool quarantine** | Per-tool approval pinned to a SHA-256 fingerprint of the definition. `tool show` escapes invisible characters (a common way to hide instructions in a tool description) and diffs against the approved version. | `design/adr/0032` |
| **Signed backends** | A registered backend (command, arguments, image digest, credential *names*) must carry an Ed25519 signature from a key listed in the config file before it is served. Someone who can write the database cannot add or change a backend. | `design/adr/0010` |
| **Container backends** | `-transport oci` runs a backend with rootless podman from a digest-pinned image: read-only root, no capabilities, non-root uid, pids/memory/CPU limits, no network unless the signed entry grants one. | `design/adr/0028`, `0034` |
| **Egress** | Network grants are limited to `none` (default), `slirp4netns`, `pasta` or a named podman network. `upstream list -json` shows each backend's network so the host firewall can build its allowlist. | `design/adr/0033` |
| **Audit** | One hash-chained SQLite record per call, refusal and failure, naming the analyst by stable subject and, for reading, display name. A JSONL copy for any log shipper and optional GELF straight to Graylog, plus a heartbeat so a dead shipper is noticed. | `design/adr/0012`, `0021`, `0029`, `0037` |
| **Resilience** | Per-call time and size ceilings, a per-analyst concurrency cap, a 1 MiB request body cap, JWKS refetch at most every 30 s, and a panic contained to the one call that hit it. | `design/adr/0025`, `0035` |
| **People** | The console shows roles, their groups and who has used the gateway. Run as root with `-manage-users`, it also edits the identity provider's accounts (Authelia file backend): one-time passwords stored only as argon2id hashes, groups limited to those that map to a role, every change audited. | `design/adr/0038` |
| **Web console** | `mcp-gateway ui` serves the operator console as a page on loopback: review and approve tools with a coloured diff, block analysts, read and verify the audit trail. Every button is the CLI command of the same name. | `design/adr/0036` |
| **Quota** | Optional: cap how many calls each analyst spends against one third-party account per window, so a runaway agent loop cannot burn an API budget. | `design/adr/0030` |

Gatte was built for one SOC team fronting four existing stdio MCP servers
(lab names `casemgmt`, `logsearch`, `docsearch`, `threatintel`). It is not
a wrapper around an existing product: six gateways were lab-tested
hands-on, and each failed the requirement this project exists for --
brokering static API keys, not only OAuth (`DEVELOPMENT-LOG.md`). Nothing
in the code is specific to those four servers; [`examples/`](examples/)
covers other kinds of blue team tooling.

## Quick start

This sets up a gateway on one Linux or FreeBSD host, with one backend.

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
layout matters for security, so it is worth understanding before you type:

| File | Owner | Why |
|---|---|---|
| `signing.key` | root, `0600` | Only root can sign a backend. If the service account could read it, anyone who can write the database could sign their own backend. |
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
#    edit: signer.trusted_keys (the line step 1 printed), oidc.issuer, oidc.audience
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
#    database it writes; sign runs as root, because only root reads the key,
#    and SQLite may leave root-owned -wal/-shm files behind, hence the chown.
sudo -u mcpgw mcp-gateway upstream register -config "$CFG" -name edr -transport stdio \
  -command /usr/local/bin/your-edr-mcp -env EDR_CLIENT_ID -env EDR_CLIENT_SECRET
sudo mcp-gateway sign -config "$CFG" edr
sudo chown -R mcpgw:mcpgw /var/db/mcp-gateway

# 5. Check the configuration offline, then run (in the foreground here;
#    under your service manager in production).
sudo -u mcpgw mcp-gateway upstream list -config "$CFG"
sudo -u mcpgw mcp-gateway serve -config "$CFG"

# 6. In a second shell, while serve runs: approve the tools it observed.
#    The console shares the SQLite file with the running server; an approval,
#    like a revoke, takes effect on the next call, without a restart.
sudo -u mcpgw mcp-gateway tool list    -config "$CFG" -server edr
sudo -u mcpgw mcp-gateway tool show    -config "$CFG" edr get_host   # the definition and its SHA256
sudo -u mcpgw mcp-gateway tool approve -config "$CFG" -fingerprint SHA256 edr get_host
```

What each step is for:

- **Step 1** creates the key that vouches for backends. The public half goes
  in the config file; the gateway serves only entries signed by a key
  listed there.
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
- **Step 6** is the quarantine. `tool show` prints the definition with
  hidden characters made visible and gives its fingerprint; `tool approve`
  needs that fingerprint, so you approve exactly what you read. Take tool
  names from `tool list`, not from memory.

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

To try the whole flow without real backends, `make lab-build` builds four
mock MCP servers into `bin/lab/` that report whether the injected
credential arrived without echoing it (`lab/README.md`).

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
# With ioc-sweep registered instead (step 4), the call that answers today:
mcp '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"ioc-sweep.sweep_iocs","arguments":{"iocs":["198.51.100.7"]}}}'
# -> "swept 1 ioc(s): 198.51.100.7; key_present=true; env_names=..." (examples/byo-script.toml, step 4)
```

`tools/list` returns the tools your roles grant and an operator approved,
named `backend.tool`. Anything else is answered as `unknown tool`. A
missing, malformed, expired or wrong-audience token gets:

```
HTTP/1.1 401 Unauthorized
Www-Authenticate: Bearer resource_metadata="https://gatte.example.org/.well-known/oauth-protected-resource/mcp"
```

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
podman pull ghcr.io/example/edr-mcp:1.4
podman inspect --format '{{index .RepoDigests 0}}' ghcr.io/example/edr-mcp:1.4
sudo -u mcpgw mcp-gateway upstream register -config "$CFG" -name edr -transport oci \
  -image ghcr.io/example/edr-mcp@sha256:<64 hex> -arg --network=slirp4netns \
  -env EDR_CLIENT_ID -env EDR_CLIENT_SECRET
```

The image must be pinned by digest, because the signature covers it and a
tag can be repointed. Every container gets `--rm -i`, a read-only root,
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
`mcp-gateway COMMAND` print the full usage.

| Task | Command | Takes effect |
|---|---|---|
| See what needs approval | `tool list` | -- |
| Review a tool (or a change to one) | `tool show SERVER TOOL` | -- |
| Approve exactly what you reviewed | `tool approve -fingerprint SHA256 SERVER TOOL` | next call |
| Withdraw an approval | `tool revoke SERVER TOOL` | next call |
| Add or remove a backend | `upstream register` + `sign`, or `upstream deregister` | within one `quarantine.refresh_interval` (default 5 m) |
| Cut off one analyst | `access block -reason TEXT SUBJECT` | next request |
| Restore them | `access unblock SUBJECT` | next request |
| Read the trail | `audit [-subject ID] [-outcome denied] [-since TIME]` | -- |
| Check the trail was not edited | `audit -verify [-expect-head HASH]` | -- |
| See quota spend | `quota usage [-analyst SUBJECT]` | -- |
| Change roles or rotate a credential | edit `config.toml` / `sops secrets.enc.json`, then restart | after restart |

**During an incident, do two things.** `access block` stops the analyst at
the gateway immediately. It does not touch the IdP: their token stays
valid there until it expires, so revoke the session at the IdP too. The
block's audit row names the login account that ran it (`SUDO_USER`, else
`USER`), so say who did it in `-reason`.

**Watch for silence.** The JSONL copy of the trail carries a heartbeat at
boot and on every maintenance tick, including the number of tools pending
and changed. Alert when it stops arriving, not only on what it says
(`deploy/freebsd-jail.md`, "Alerting on a chain that went quiet").

**Watch for tool changes.** The first sighting of a tool, a change to an
approved tool and a registry entry whose signature fails are each written
to the trail as a `denied` row attributed to `(gateway)`. A `changed` row
means a backend altered a tool you approved: read the diff before
re-approving.

### The web console

The same console, as a page in your browser:

```sh
sudo -u mcpgw mcp-gateway ui -config "$CFG"          # listens on 127.0.0.1:8090
# prints: http://127.0.0.1:8090/login?token=...      works once; keep it private
```

On the gateway host itself, open the link. From your own machine, forward the
port first with `ssh -L 8090:127.0.0.1:8090 gateway-host` and open the same
link locally.

| Page | What you do there |
|---|---|
| Overview | See what needs attention: changed and pending tools, unsigned backends, blocked analysts, the latest refusals. |
| People | See each role, the groups that map to it and its tools, and everyone the gateway has seen, with a Block button. With `sudo mcp-gateway ui -manage-users`, also add people at the identity provider, change their groups, disable them or give them a new one-time password (`design/adr/0038`). Adding a person is a three-step assistant that ends with their one-time password and a connect script for macOS, Linux or Windows that sets up Claude Code on their machine (`[connect]`, `design/adr/0039`). |
| Tools | Review a definition with hidden characters escaped and the diff coloured, then approve that exact fingerprint, or revoke. |
| Access | Block or unblock an analyst, with a reason that goes in the trail. |
| Audit | Filter the trail by analyst and outcome, and verify the hash chain against your SIEM's head. |
| Backends, Quota | Read-only: what is registered and signed, and what each analyst has spent. |

Every button runs the command of the same name in the table above, with the
same checks and the same audit rows; the page shows what the command
printed. Registering and signing stay in the terminal, because signing needs
root's key. The console runs only while you run it (Ctrl-C stops it) and
binds loopback only. The login link works once and opens one session of up to
12 hours; for a new one, restart `mcp-gateway ui`. Requests without that
session, from a non-loopback `Host`, or, for a POST, without the form token or
from another origin are refused (`design/adr/0036`).

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
| Someone with write access to the database adding a backend | **Yes** -- entries must be signed, and the key is root's. |
| A backend echoing its credential back to the analyst | **Yes** -- results are scrubbed. |
| A compromised container backend reading the vault | **Narrowed** -- takes a container escape, not an `open()`. |
| A compromised stdio backend reading the vault | **No** -- it runs as the gateway's user. |
| A compromised backend sending data anywhere on the network | **Not by Gatte** -- that is the host firewall's job. |
| Prompt injection through a tool's result | **No** |
| Someone running code as the service account | **No** |
| Someone who controls the host rewriting the audit trail | **Detectable only** while a shipper forwards it. |
| One analyst flooding the gateway | **Yes** -- 4 calls in flight per analyst; request rate at the proxy. |
| An unauthenticated flood denying service to analysts | **Mitigated** -- audit rows for failed logins are rate-limited per source. |

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
shown. Tool names outside `[A-Za-z0-9_-]{1,64}` are not served. Not
covered: who approved is not in the trail, and nothing judges the text for
the operator.

**Against someone with write access to the SQLite database**, registry
entries are signed with Ed25519 and verified against public keys that live
in the configuration file. That holds only while the private signing key is
out of that actor's reach; the provisioning recipe here got that wrong
until 16 Sep 2026 and now keeps the key owned by root.

**It is not a control against someone executing code as the service
user.** That actor reads the decrypted vault and the signing key and writes
the trail. A stdio backend -- the least trusted code in the system -- runs
as that same user, with nothing between it and the process holding every
credential (`AGENTS.md` §2). That is why a stdio entry is not given
credentials unless `[upstreams] allow_credentialed_stdio = true` says so,
loudly (`design/adr/0034`).

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

**A backend that echoes its own credential does not hand it to the
analyst.** Every result is scrubbed of the values the gateway injected into
that backend, in raw and escaped forms, and a result that cannot be
scrubbed is refused rather than forwarded.

**It does not guarantee the trail's integrity against whoever controls the
host.** Records are hash-chained, not individually signed. Comparing the
chain head against the SIEM's copy with `mcp-gateway audit -verify
-expect-head HASH` detects truncation or rewriting of the local trail, but
only while a shipper is actually forwarding the file, and not against an
attacker who also forges the shipped lines. Nothing compares the two
automatically.

**It terminates no TLS** and refuses at startup any bind that is not
loopback, with no override. Everything network-facing depends on a
co-located reverse proxy and your network controls (`design/adr/0011`).

**It is a single point of failure, knowingly** (`design/adr/0001`): one
binary, one process, one SQLite file. What bounds the load:

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
the vault reaches an already-connected backend only after a restart; the
gateway warns while the old value is in use (`deploy/freebsd-jail.md`,
"Rotating credentials").

These limits came out of five adversarial review rounds, one of which
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
- The controls in ADRs 0031-0035 (kill switch, quarantine events,
  egress, container hardening, call resilience) were exercised on a Linux
  test VM with rootless podman on 28 Sep 2026: the kill switch, fingerprint
  approval, concurrency cap, container capabilities and limits, and an
  outbound firewall on the service uid were each measured there. Panic
  containment is proven by unit tests only.
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
(`design/adr/0020`). Role changes and credential rotation need a restart.

## Repository map

| Path | What it is |
|---|---|
| `cmd/mcp-gateway/` | The binary: `serve` (composition root) and the operator console. |
| `internal/config/` | The TOML configuration contract and its validation. |
| `internal/access/` | OIDC token verification, roles, grants, and the analyst blocklist. |
| `internal/registry/` | Registered backends. |
| `internal/signer/` | Ed25519 signing and verification of registry entries. |
| `internal/quarantine/` | Tool quarantine: pending, approved, changed, and the definitions they refer to. |
| `internal/visible/` | Escapes invisible and control code points in untrusted text as `\u{XXXX}`. |
| `internal/vault/` | Credential vault; `sopsage/` is the sops+age adapter. |
| `internal/gateway/` | Routing, dispatch, the stdio and oci dialers, and the HTTP MCP endpoint. |
| `internal/audit/` | Hash-chained SQLite trail and the JSONL SIEM sink. |
| `internal/telemetry/` | GELF copy of the trail, straight to Graylog. |
| `internal/quota/` | Per-analyst call budgets against third-party accounts. |
| `internal/store/` | The single shared SQLite connection. |
| `internal/e2e/`, `internal/fitness/` | End-to-end checkpoint and architecture fitness tests. |
| `lab/` | Mock MCP servers, the credential-leak probe, and a traffic generator. |
| `deploy/`, `scripts/` | Provisioning scripts and runbooks for the reference test deployments. |
| `design/` | Discovery, components, style, and one ADR per significant decision. |
| `examples/` | Blue team configuration examples. |
| `config.example.toml` | The full configuration reference, every key documented. |

## Documentation map

- **`examples/README.md`** -- how to put any tool behind the gateway.
- **`config.example.toml`** -- every configuration key and what goes wrong
  if you get it wrong. Its comments are in Portuguese.
- **`CONCEPTS.md`** -- a primer on MCP, gateways, credential brokering and
  API security.
- **`design/adr/`** -- one file per decision, with context, decision and
  consequences. The later ones are in Portuguese.
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
the vault tests.

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
