# mcp-gateway

Self-hosted MCP gateway for the SOC team: one authenticated endpoint in
front of the four existing stdio MCP servers (`casemgmt`, `logsearch`,
`docsearch`, `threatintel`), so production API keys stop living in plaintext
`.env` files on every analyst's laptop.

Not an adoption of an existing gateway product — six candidates were
hands-on lab-tested and every one failed the one requirement this project
exists to satisfy (credential brokering for static API keys, not just
OAuth). Full investigation: `DEVELOPMENT-LOG.md`.

## Status

All seven phases are complete (see `WORKFLOW.md`, which is authoritative and
lists what remains as filed work rather than as a phase). The end-to-end
checkpoint passes: a client holding no backend credential reaches four
spawned upstreams over HTTP, each receiving its injected secret, with that
secret appearing nowhere the client can observe.

A running gateway keeps itself in step with the registry: `upstream
register` and `upstream deregister` take effect within one
`quarantine.refresh_interval`, as does an entry whose signature stops
verifying, and an unreadable registry serves nothing until it can be read
again (`design/adr/0020-reconciliacao-periodica-do-registro.md`). Rotating
a credential is the exception and still needs a restart, deliberately —
`deploy/freebsd-jail.md`, "Rotating credentials".

**It runs.** Phase 6 built the composition root and the Operator Console:

```
mcp-gateway upstream register -name casemgmt -transport stdio -command …
mcp-gateway sign casemgmt
mcp-gateway serve
```

Configuration is a documented TOML file — copy `config.example.toml`.
`mcp-gateway help` lists the rest (`tool list|approve|revoke`, `audit`,
`upstream list|deregister`).

Registry entries must be signed to be served (`require_signed` defaults
to true as of Phase 6); an unsigned entry is reported as such the moment
you register it, with the command to fix it.

## Security posture

Written for someone reading a public repository, and written the way this
project writes everything else: the limits are part of the claim.

**What it guarantees.** The production credential of four backends stops
living on N analyst laptops and lives in one sops+age file on one host,
resolved in memory at the moment each subprocess is spawned, never written
back, never logged, never returned to a client. The child's environment is
*built*, not inherited. Nothing downstream of authentication even holds the
analyst's token, so there is no variable to forward — a reflection test
fails the build if one is ever added.

**Against the analyst, who is the actor the design centres on**, it enforces
OIDC with a validated audience (RFC 8707, so a token minted for another
service of the same IdP is refused), role to tool-subset, and a per-tool
quarantine that makes every new or silently-rewritten tool invisible and
uncallable until a human approves it. Every call, refusal and failure lands
in a hash-chained audit trail, with a JSONL copy shipped to a SIEM the
gateway cannot rewrite.

**Against someone who gains write access to the SQLite database**, it
intends one more step: registry entries signed with Ed25519 and verified
against public keys that live in the configuration file, outside the blast
radius of the database. That step is only real while the private key is
outside the reach of whoever writes the database — the provisioning recipe
here got that wrong until 16 Sep 2026 and now keeps the key as root.

**It is not a control against someone executing code as the service user.**
That actor reads the decrypted vault, reads the signing key, and writes the
trail. The four stdio backends — the least trusted code in the system — run
as that same user, with no separate uid, nested jail or Capsicum between
them and the process holding every credential. That is declared in
`AGENTS.md` §2, not solved.

**It does not guarantee the trail's integrity against whoever controls the
host.** Records are not individually signed; an attacker who re-chains
leaves no trace in the chain itself, and the only real evidence of
truncation is comparing the chain head against the SIEM's copy — which is
worth exactly as much as a shipper actually forwarding the file, a condition
no check inside the process can establish. The heartbeat exists so that the
*absence* of lines is detectable; it too is unsigned.

**It terminates no TLS**, refuses at startup any bind that is not loopback,
has no escape hatch for that, and depends entirely on a co-located proxy and
a VPN for everything network-facing (`design/adr/0011`).

**It is a single point of failure, knowingly** (`design/adr/0001`): one
binary, one process, one SQLite file. A per-call ceiling bounds how long any
one call may hold a backend (`design/adr/0025`), but nothing bounds how many
calls an authorised analyst may hold at once. And a flood of unauthenticated
requests does more than compete for the one audit writer: measured, it can
exhaust SQLite's busy timeout, and since a call that cannot be audited is
refused, a stranger with no credential can get an analyst's call refused.
Both are declared in `AGENTS.md` §2; the second is filed as ADR-0027.

**Everything above was checked, not asserted.** The gaps named here came out
of four adversarial review rounds, the last of which audited the whole system
rather than a diff; each one found controls that were documented as working
and could not fire. If you find a fifth, that is the expected outcome, and
the repository is written so you can prove it rather than argue it.

## Start here

- **`AGENTS.md`** — what to build, confirmed architecture, what's still
  open. Read this first.
- **`WORKFLOW.md`** — the phased build order, gates, and Progress
  checklist.
- **`CONCEPTS.md`** — MCP/gateway/API-security primer, if any term in the
  two files above is unfamiliar.
- **`DEVELOPMENT-LOG.md`** / **`RESEARCH-recovered.md`** — full
  investigation history and evidence behind every decision.
- **`design/`** — discovery, components, style, and one ADR per
  significant decision.
- **`lab/`** — mock MCP servers + probe harness, reused as the test
  harness for this build (`AGENTS.md` §5.4).

## Language

Go (`design/adr/0002-language-runtime.md`).

## Repo hardening

This repo follows a repository-hardening standard's
`solo` profile — see `.hardening.toml`. The pre-commit hook in `.githooks/`
is a local guardrail, not a control — the server-side scan is what's
authoritative.

> **Commits are NOT signed, and this said they were.** The sentence here
> read "Commits are signed with SSH (`gpg.format=ssh`)". Measured 12 Sep
> 2026: `git log --format=%G?` returns `N` for every commit in the
> repository's history without exception, and `gpg.format`,
> `commit.gpgsign` and `user.signingkey` are unset both locally and
> globally. It was never true.
>
> (This first said "all 41 commits", which was accurate when measured and
> wrong in the artifact that stated it — the commit carrying the sentence
> made it 42, and the count would have drifted again with every commit
> after. A smaller instance of exactly what this note is about, caught in
> review.)
>
> That matters more here than a stale line usually would. This repository is
> public and holds a security tool; "commits are signed" is the claim
> someone would lean on to trust its history, and it is exactly the kind of
> unbacked assertion the code in this repo is repeatedly corrected for
> making.
>
> What is locally verifiable: `.hardening.toml` declares `perfil = "solo"`,
> and its own first line says every disabled control needs an exception
> declared in it — and the file contains none. Whether the `solo` profile
> requires signing is NOT checkable from this clone: that control list lives
> in the external hardening standard and `harden.py` is not here.
> `harden.py --explain solo` would settle it. The distinction is kept
> because this is a note about unbacked claims, and "the profile requires
> signing" would be inferred rather than measured.
>
> **Closed 12 Sep 2026 by declaring it, not by fixing it.** The owner's
> decision was to keep signing off — a single-operator repository with no
> signing key, and no intent to introduce one — so `.hardening.toml` now
> carries a `commit-signing` exception with the reason, approver and review
> date that file demands. Off and declared is a different posture from off
> and advertised as on, which is what this was until today. Review falls due
> 12 Mar 2027.
