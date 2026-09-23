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

There is **no per-analyst quota or concurrency limit**. See
[Security model](#security-model).

Gatte was built for one SOC team fronting four existing stdio MCP servers
(`casemgmt`, `logsearch`, `docsearch`, `threatintel`). It is not an adoption
of an existing gateway product: six candidates were lab-tested hands-on and
each failed the requirement this project exists for, brokering static API
keys rather than only OAuth (`DEVELOPMENT-LOG.md`). Nothing in the code is
specific to those four servers, and [`examples/`](examples/) shows the same
steps for other kinds of blue team tooling.

## Quick start

You need: Go (the version in `go.mod`), `sops` and `age` on the gateway
host (`deploy/freebsd-jail.md` pins sops at 3.13.2 or later), an OIDC
provider that puts group names in a token claim, and a TLS-terminating
reverse proxy. The gateway binds loopback only and terminates no TLS.

```sh
make build                                        # -> bin/mcp-gateway

# 1. A signing key. Prints the two [signer] lines to paste into the config.
bin/mcp-gateway sign -generate-key -out /usr/local/etc/mcp-gateway/signing.key

# 2. A configuration: the minimal base plus a role policy.
cat examples/base.toml examples/blue-team-roles.toml > /usr/local/etc/mcp-gateway/config.toml
#    edit: signer.trusted_keys, oidc.issuer, oidc.audience, paths
CFG=/usr/local/etc/mcp-gateway/config.toml

# 3. The vault: a flat JSON object of VAR_NAME -> value, encrypted.
age-keygen -o /usr/local/etc/mcp-gateway/age.key   # chmod 600
sops --encrypt --age <recipient> --input-type json --output-type json \
  secrets.json > /usr/local/etc/mcp-gateway/secrets.enc.json

# 4. Register and sign each tool, naming its credentials (names only).
bin/mcp-gateway upstream register -config "$CFG" -name edr -transport stdio \
  -command /usr/local/bin/your-edr-mcp -env EDR_CLIENT_ID -env EDR_CLIENT_SECRET
bin/mcp-gateway sign -config "$CFG" edr

# 5. Check the configuration offline, then run.
bin/mcp-gateway upstream list -config "$CFG"
bin/mcp-gateway serve -config "$CFG"

# 6. Approve the tools the gateway observed.
bin/mcp-gateway tool list    -config "$CFG" -server edr
bin/mcp-gateway tool approve -config "$CFG" edr get_host
```

Point the reverse proxy at `listen` (default `127.0.0.1:8080`) and point
MCP clients at the URL you set as `oidc.audience`. The gateway publishes
OAuth protected resource metadata (RFC 9728) at
`/.well-known/oauth-protected-resource`, and also at that prefix plus the
audience's path.

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

- **A local process speaking MCP over stdio.** That is the only transport
  with a dialer. `http` is recognised and refused at registration, and
  there is no container transport (`CLOSEOUT.md`, Track 1). A server
  reachable only over HTTP cannot be registered directly.
- **Configured by arguments and environment variables.** It receives its
  signed arguments, `PATH` and `HOME`, and the variables it declared.
- **Code you would trust with the gateway's service account**, because it
  runs as that account (below).

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
solved.

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
  The upstream names in it are sanitized, and some ADRs referred to in
  `CLOSEOUT.md` live only in the private repository.

A running gateway keeps itself in step with the registry: `upstream
register`, `upstream deregister` and a signature that stops verifying take
effect within one `quarantine.refresh_interval`; an unreadable registry
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
