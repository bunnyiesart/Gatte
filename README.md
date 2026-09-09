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

Phases 1–5 complete (see `WORKFLOW.md`). The end-to-end checkpoint passes:
a client holding no backend credential reaches four spawned upstreams over
HTTP, each receiving its injected secret, with that secret appearing
nowhere the client can observe.

**It runs.** Phase 6 built the composition root and the Operator Console:

```
mcp-gateway upstream register -name casemgmt -transport stdio -command …
mcp-gateway sign casemgmt
mcp-gateway serve
```

Configuration is a documented TOML file — copy `config.example.toml`.
`mcp-gateway help` lists the rest (`tool list|approve`, `audit`,
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

This repo follows [`bunnyiesart/hardening-repositorios`](https://github.com/bunnyiesart/hardening-repositorios)'s
`solo` profile — see `.hardening.toml`. Commits are signed with SSH
(`gpg.format=ssh`); the pre-commit hook in `.githooks/` is a local
guardrail, not a control — the server-side scan is what's authoritative.
