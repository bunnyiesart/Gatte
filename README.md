# Gatte

A self-hosted MCP gateway for blue teams. One authenticated endpoint in
front of all the MCP servers your analysts use -- SIEM search, EDR, threat
intel, case management, vulnerability and cloud posture tooling, or a
script you wrote yourself -- so that the production API keys behind those
tools live on one host instead of on every analyst's laptop.

What it does, for any stdio MCP server you put behind it:

- **One endpoint.** Analysts' MCP clients connect to one URL, authenticate
  with a token from your OIDC provider, and see the tools their role
  allows, each named `upstream.tool`.
- **Secrets stay on the gateway.** Credentials live in one sops+age
  encrypted file. The gateway resolves them in memory and injects them into
  each tool's process when it spawns it. The process environment is built,
  not inherited; secrets are never written back, logged or returned to a
  client, and the analyst's own token is never forwarded to a tool.
- **Per-tool quarantine.** Every tool a server advertises starts out
  invisible and uncallable until an operator approves its definition. If
  the server later changes a tool's name, description or input schema, that
  tool stops being served until someone looks again.
- **Signed definitions.** A registered server (command, arguments,
  credential names) must carry an Ed25519 signature from a key listed in
  the configuration file, outside the database, before it is served.
- **Per-role access.** Groups from the token map to roles; roles grant
  tools by exact name or per server. Roles live in the configuration file,
  so widening one is a reviewed diff.
- **Audit trail to any SIEM.** Every call, refusal and failure is recorded
  in a hash-chained SQLite trail, with an optional JSONL copy that any log
  shipper can forward to whatever SIEM you run, plus a heartbeat line so
  that a silent shipper is detectable.
- **Per-call ceilings.** Each call has a time limit (`response.call_timeout`)
  and a result size limit (`response.max_bytes`).
- **Backends as containers, optionally.** `-transport oci` runs a backend
  as an ephemeral rootless `podman run --rm -i` from a digest-pinned image,
  read-only root, no network unless the signed entry grants it; the digest
  is inside the signature (`design/adr/0028-transporte-oci.md`). A grant is
  `slirp4netns`, `pasta` or a named podman network; `host`, `private`,
  `container:*`, `ns:*` and `:options` are refused. A granted network is
  not a destination allowlist: which hosts the backend reaches is the host
  firewall's job (`design/adr/0033-egresso-dos-backends.md`).
- **Per-analyst quota, optionally.** `[[quota.provider]]` caps how many
  calls one analyst may spend against one third-party account per window,
  so a runaway agent loop cannot burn an API budget
  (`design/adr/0030-quota-por-analista.md`).
- **GELF to Graylog, optionally.** `[telemetry]` sends a copy of every
  accepted audit record straight to a GELF input, no shipper needed
  (`design/adr/0029-telemetria-gelf.md`).

There is **no concurrency limit** per analyst. See
[Security model](#security-model).

Gatte was built for one SOC team fronting four existing stdio MCP servers
(`casemgmt`, `logsearch`, `docsearch`, `threatintel`). It is not an adoption
of an existing gateway product: six candidates were lab-tested hands-on and
each failed the requirement this project exists for, brokering static API
keys rather than only OAuth (`DEVELOPMENT-LOG.md`). Nothing in the code is
specific to those four servers, and [`examples/`](examples/) shows the same
steps for other kinds of blue team tooling.

## Quick start

You need, on the gateway host:

- **Go**, the version in `go.mod` (1.27.1). Distribution packages are
  usually older (Ubuntu 24.04's is), so take the tarball from
  <https://go.dev/dl/> and check it against the sha256 published there
  (`https://go.dev/dl/?mode=json&include=all` lists every file's):

  ```sh
  curl -fLO https://go.dev/dl/go1.27.1.linux-amd64.tar.gz
  echo "63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445  go1.27.1.linux-amd64.tar.gz" | sha256sum -c
  # linux-arm64: 3450b45a3f9ee8568792736a5c5e70a1f2e9b36c35a8f74958c03e51d7d92bec
  sudo tar -C /usr/local -xzf go1.27.1.linux-amd64.tar.gz
  export PATH=/usr/local/go/bin:$PATH
  echo 'export PATH=/usr/local/go/bin:$PATH' >> ~/.profile   # so a new shell finds go
  ```

  The `export` lasts for this shell only; the `~/.profile` line (FreeBSD:
  the same file) is what makes `make build`, or a rebuild months later,
  work from a fresh login. The second shell in step 6 below needs only
  `/usr/local/bin`, which `sudo` already has.

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
- **An OIDC provider** that puts group names in a token claim, and a
  **TLS-terminating reverse proxy**. The gateway binds loopback only and
  terminates no TLS.

The gateway runs as an unprivileged service account; these steps call it
`mcpgw`. The layout keeps the signing key owned by root, out of that
account's reach (see [Security model](#security-model)), and gives the
account only what it has to write: its database and its audit log.

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

# 4. Register each tool, naming its credentials (names only), and sign it.
#    Operator commands run as the service account, because they write the
#    database it writes; sign runs as root, because only root reads the key,
#    and SQLite may leave root-owned -wal/-shm files behind, hence the chown.
sudo -u mcpgw mcp-gateway upstream register -config "$CFG" -name edr -transport stdio \
  -command /usr/local/bin/your-edr-mcp -env EDR_CLIENT_ID -env EDR_CLIENT_SECRET
sudo mcp-gateway sign -config "$CFG" edr
sudo chown -R mcpgw:mcpgw /var/db/mcp-gateway
#    your-edr-mcp is a placeholder. To run these steps against a real upstream
#    today: install examples/ioc_sweep.py (examples/byo-script.toml, steps
#    2-4), register it as ioc-sweep with -env IOC_SWEEP_API_KEY, put
#    IOC_SWEEP_API_KEY in secrets.json (step 3), sign, and approve
#    `ioc-sweep sweep_iocs` in step 6; a token in group blue-ir then reaches
#    ioc-sweep.sweep_iocs (examples/blue-team-roles.toml).

# 5. Check the configuration offline, then run (in the foreground here;
#    under your service manager in production).
sudo -u mcpgw mcp-gateway upstream list -config "$CFG"
sudo -u mcpgw mcp-gateway serve -config "$CFG"

# 6. In a second shell, while serve runs: approve the tools it observed.
#    The console shares the SQLite file with the running server; an approval,
#    like a revoke, takes effect on the next call, without a restart.
sudo -u mcpgw mcp-gateway tool list    -config "$CFG" -server edr
sudo -u mcpgw mcp-gateway tool approve -config "$CFG" edr get_host
```

On this first run, with only `edr` registered, `serve` logs two `WARN`
lines: "a role grants tools that match nothing this gateway observed" and
"a role grants a backend this gateway has no upstream registered for".
They are expected. `blue-team-roles.toml` grants tools on upstreams you
have not registered yet, and each grant takes effect once its upstream is
registered, signed and approved. To stop the warnings, register those
upstreams or delete the grants you will not use.

`serve` runs `sops`, so it must be on the service account's `PATH`. On
Ubuntu, `sudo` resets `PATH` to a `secure_path` that includes
`/usr/local/bin`; elsewhere, check it. That `PATH`, and the account's
`HOME`, are what the spawned upstreams receive. Tool names come from
`tool list`, not from memory.

Point the reverse proxy at `listen` (default `127.0.0.1:8080`) and point
MCP clients at the URL you set as `oidc.audience`. The gateway publishes
OAuth protected resource metadata (RFC 9728) at
`/.well-known/oauth-protected-resource`, and also at that prefix plus the
audience's path.

### First call

The endpoint is MCP's streamable HTTP transport in stateless mode: every
request is a `POST` of one JSON-RPC message, no `Mcp-Session-Id` is issued
or expected, and the answer comes back as `text/event-stream` (one
`data:` line carrying the JSON-RPC response). The gateway answers MCP on
every path except the metadata ones, so the path that matters is the one
in `oidc.audience`: use that URL, and route it to `listen` at the proxy.

Both `oidc.issuer` and `oidc.audience` must be absolute `https` URLs with no
query or fragment; `http` is accepted only for `localhost`, `127.0.0.1` and
`::1`, which is enough for a test IdP on the same host. `serve` reads the
issuer's discovery document at startup and refuses to start without it.

The bearer token must be a JWT from that issuer, signed with an
asymmetric algorithm (RS*, PS*, ES* or EdDSA) by a key in its `jwks_uri`,
unexpired, with:

| Claim | Must be |
|---|---|
| `iss` | exactly `oidc.issuer` |
| `aud` | `oidc.audience`, or a list containing it (RFC 8707) |
| `sub` | present |
| `oidc.groups_claim` (default `groups`) | a list with at least one group mapped in `[group_to_role]` |

A token for a group that maps to no role authenticates and sees no tools.

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

`tools/list` returns the tools the token's roles grant and an operator
approved, named `upstream.tool`. A tool outside that set is answered as
`unknown tool` (`examples/README.md`, step 5). A missing, malformed,
expired or wrong-audience token gets `401` and a challenge pointing at the
metadata document, with nothing in it that says which check failed:

```
HTTP/1.1 401 Unauthorized
Www-Authenticate: Bearer resource_metadata="https://gatte.example.org/.well-known/oauth-protected-resource/mcp"
```

`mcp-gateway help` lists every command: `serve`, `upstream
list|register|deregister`, `sign`, `tool list|approve|revoke`, `audit`,
`version`. `serve` and the operator commands (all but `sign -generate-key`)
take `-config`, and load and validate the whole configuration file before doing anything,
refusing unknown keys.

To try the flow without real backends, `make lab-build` builds four mock
MCP servers into `bin/lab/` that read `MOCK_SECRET` and `MOCK_EXPECT` and
report whether the injected credential arrived without echoing it
(`lab/README.md`).

## Adding any tool

[`examples/README.md`](examples/README.md) walks through the five steps --
register, put credentials in the vault, sign, approve tools, grant to
roles -- with one example per blue team category: SIEM / log search, EDR,
threat intel enrichment, case management, vulnerability scanner, cloud
security posture, and bring your own script. Each example is a config
snippet that was loaded by the real binary.

What an upstream must be, in this build:

- **A process speaking MCP over stdio**, either spawned locally
  (`-transport stdio`) or run from a digest-pinned container image
  (`-transport oci`, which needs rootless podman for the gateway's user).
  `http` is recognised and refused at registration; a server reachable only
  over HTTP cannot be registered directly.
- **Configured by arguments and environment variables.** It receives its
  signed arguments, `PATH` and `HOME`, and the variables it declared.
- **Code you would trust with the gateway's service account** if it is a
  stdio upstream, because it runs as that account (below). An oci upstream
  runs as the same host user too, but inside a container that has neither
  the vault nor the signing key mounted.

## Security model

The limits are part of the claim.

**What it covers.** The production credentials of every backend stop
living on analyst laptops and live in one sops+age file on one host.
Against the analyst -- the actor the design centres on -- the gateway
enforces OIDC with a validated audience (RFC 8707, so a token minted for
another service of the same IdP is refused), role to tool subset, and the
per-tool quarantine. Every call, refusal and failure lands in the audit
trail, and the JSONL copy gives the SIEM a record the gateway cannot
rewrite once it has been shipped.

**Against someone with write access to the SQLite database**, registry
entries are signed with Ed25519 and verified against public keys that live
in the configuration file. That holds only while the private signing key is
out of that actor's reach; the provisioning recipe here got that wrong
until 16 Sep 2026 and now keeps the key owned by root.

**It is not a control against someone executing code as the service
user.** That actor reads the decrypted vault and the signing key and writes
the trail. The backends -- the least trusted code in the system -- run as
that same user, with no separate uid, nested jail or Capsicum between them
and the process holding every credential. Declared in `AGENTS.md` §2, not
solved. The oci transport narrows it without closing it: a containerised
backend has its own mount namespace with a read-only root and none of the
gateway's files, so reading the vault takes a container escape rather than
an `open()`; it is still the same host uid under rootless podman
(`design/adr/0028-transporte-oci.md` §D).

**It does not contain a backend's egress.** A stdio backend has the host's
network, and an oci backend with a network grant reaches anything that
network reaches -- a public API, the rest of RFC 1918, `169.254.169.254` --
so a compromised backend can send its own credential anywhere. The gateway
only chooses the namespace (`none` by default; `host` and the
namespace-joining modes are refused). Limiting destinations is the host
firewall's job: an outbound rule on the service uid, with the allowlist
derived from `upstream list -json` (`design/adr/0033`). Without that rule,
nothing limits it. The allowlist governs only what the entry writes: host
podman configuration (`containers.conf` network options) can still open the
host's loopback to an accepted mode, so the deploy probes every mode in use.

**A backend that echoes its own credential does not hand it to the
analyst.** Every result is scrubbed of the values the gateway injected into
that backend, in raw and escaped forms, and a result that cannot be
scrubbed is refused rather than forwarded.

**It does not guarantee the trail's integrity against whoever controls the
host.** Records are not individually signed. The chain head, compared
against the SIEM's copy with `mcp-gateway audit -verify -expect-head HASH`,
detects truncation or rewriting of the local trail, but only while a
shipper is actually forwarding the file, and not against an attacker who
also forges the shipped lines. Nothing compares the two automatically.

**It terminates no TLS** and refuses at startup any bind that is not
loopback, with no override. Everything network-facing depends on a
co-located reverse proxy and your network controls (`design/adr/0011`).

**It is a single point of failure, knowingly** (`design/adr/0001`): one
binary, one process, one SQLite file. A per-call ceiling bounds how long one
call may hold a backend (`design/adr/0025`), but nothing bounds how many
calls an authorised analyst may hold at once. Audit writes for failed
authentication are rate-limited (`design/adr/0027`) because, measured, an
unauthenticated flood could otherwise exhaust SQLite's busy timeout and get
an analyst's call refused -- a call that cannot be audited is refused.

**Prompt injection through a tool's result is not covered.** The response
check is a size ceiling plus validation against a declared output schema
(`design/adr/0014`).

**Credentials are resolved when a backend is spawned**, so rotating one in
the vault reaches an already-connected backend only after a restart; the
gateway warns while the old value is in use (`deploy/freebsd-jail.md`,
"Rotating credentials").

These gaps came out of four adversarial review rounds, the last of which
audited the whole system; each round found controls that were documented as
working and could not fire. The repository is written so that a fifth
finding can be proved rather than argued.

## Status

**Read [`CLOSEOUT.md`](CLOSEOUT.md) before trusting this in production.**

- All seven build phases in `WORKFLOW.md` are closed, and the v1 criterion
  (`design/adr/0026`) is met -- but all three of its conditions are about a
  development machine. "v1 declared" and "v1 running" are different claims,
  and only the first has been made.
- The end-to-end checkpoint passes on that machine: a client holding no
  backend credential reaches four spawned upstreams over HTTP, each
  receiving its injected secret, with that secret appearing nowhere the
  client can observe.
- The gateway ran once in a throwaway FreeBSD test jail, with the lab mocks
  as upstreams and an Authelia token (`deploy/gateway-serve.md`). The last
  successful provisioning there was 12 Sep 2026. Eight ADRs accepted since
  (`0020`-`0027`) have never run outside a test binary, and the owner has
  since abandoned that substrate; `CLOSEOUT.md` Track 1 records why its
  steps were not retargeted.
- Other open tracks: the SIEM anchor comparison has no owner, the older half
  of the design record has not been swept, and some proofs skip silently
  where `sops` and `age` are missing.
- This repository is a sanitized public copy of an internal SOC build.
  The upstream names in it are sanitized, and so, since 24 Sep 2026, are
  its network addresses and hostnames: RFC 5737 / RFC 2544 stand-ins and
  `*.example.internal`, held there by `internal/fitness/sanitize_test.go`.
  Older pushed history still carries the real ones (`CLOSEOUT.md` Track 6).
  Some ADRs referred to in `CLOSEOUT.md` live only in the private
  repository.

A running gateway keeps itself in step with the registry: `upstream
register`, `upstream deregister` and a signature that stops verifying take
effect within one `quarantine.refresh_interval` plus the time one
maintenance round takes (the timer is reset after the round, not before,
`design/adr/0013`'s 28 Sep 2026 correction); an unreadable registry
serves nothing until it can be read again (`design/adr/0020`). Role changes
and credential rotation need a restart.

## Repository map

| Path | What it is |
|---|---|
| `cmd/mcp-gateway/` | The binary: `serve` (composition root) and the operator console. |
| `internal/config/` | The TOML configuration contract and its validation. |
| `internal/access/` | OIDC token verification, roles and per-backend grants. |
| `internal/registry/` | Registered upstreams (the stdio transport). |
| `internal/signer/` | Ed25519 signing and verification of registry entries. |
| `internal/quarantine/` | Tool quarantine: pending, approved, changed. |
| `internal/vault/` | Credential vault; `sopsage/` is the sops+age adapter. |
| `internal/gateway/` | Routing, dispatch, the stdio dialer and the HTTP MCP endpoint. |
| `internal/audit/` | Hash-chained SQLite trail and the JSONL SIEM sink. |
| `internal/store/` | The single shared SQLite connection. |
| `internal/e2e/`, `internal/fitness/` | End-to-end checkpoint and architecture fitness tests. |
| `lab/` | Mock MCP servers, the credential-leak probe, and a traffic generator. |
| `deploy/`, `scripts/` | Provisioning scripts and runbooks for the FreeBSD test jail. |
| `design/` | Discovery, components, style, and one ADR per significant decision. |
| `examples/` | Blue team configuration examples. |
| `config.example.toml` | The full configuration reference, every key documented. |

## Documentation map

- **`examples/README.md`** -- how to put any tool behind the gateway.
- **`config.example.toml`** -- every configuration key and what goes wrong
  if you get it wrong. Its comments are in Portuguese.
- **`AGENTS.md`** -- the build brief: confirmed architecture, declared
  limits, what is still open.
- **`WORKFLOW.md`** -- the phased build order and gates. All seven phases
  are closed.
- **`CLOSEOUT.md`** -- what separates "v1 declared" from "v1 running".
- **`CONCEPTS.md`** -- a primer on MCP, gateways, credential brokering and
  API security, if any term above is unfamiliar.
- **`DEVELOPMENT-LOG.md`** / **`RESEARCH-recovered.md`** -- the
  investigation history and evidence behind each decision, including the
  six gateways evaluated.
- **`design/`** -- one ADR per decision; many of the later ones are in
  Portuguese.
- **`deploy/`** -- runbooks for the test jail, including credential
  rotation and alerting on a trail that went quiet.

## Development

Written in Go (`design/adr/0002-language-runtime.md`). `make check` runs
formatting, vet, lint, tests, race tests and the build.

This repository follows the `solo` profile of a repository-hardening
standard (`.hardening.toml`). The pre-commit hook in `.githooks/` is a local
guardrail, not a control. **Commits are not signed.** An earlier version of
this README said they were; measured on 12 Sep 2026, no commit in the
history ever was. The owner decided to keep signing off, and
`.hardening.toml` declares that as a `commit-signing` exception with its
reason, approver and a review date of 12 Mar 2027.

## License

Apache License 2.0. Copyright 2026 Gabriel Coelho. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
