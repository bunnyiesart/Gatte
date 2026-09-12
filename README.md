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

Phases 1–6 complete (see `WORKFLOW.md`); Phase 7, the hardening pass, is
what remains. The end-to-end checkpoint passes: a client holding no backend
credential reaches four spawned upstreams over HTTP, each receiving its
injected secret, with that secret appearing nowhere the client can observe.

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
> Two ways to close it, and both belong to the repository's owner rather
> than to whoever notices: configure SSH signing (it needs a key), or
> declare the exception in `.hardening.toml` with the reason, approver and
> review date that file demands. Writing that exception without an approver
> would be forging the approval, so it is left undone and said out loud
> instead.
