# AGENTS.md — build brief for the custom MCP gateway

This file is the entry point for any AI agent picking up implementation
work on this project. Read this first. It tells you what to build and what
is still undecided; it does not re-explain *why* — that lives in
`DEVELOPMENT-LOG.md` and `design/adr/*.md`, linked inline below where the
reasoning actually matters for a decision you'd otherwise second-guess.

**Status as of 08 Sep 2026: Gate 0 satisfied, implementation authorized,
Phase 1 in progress.** Language is Go (§3). See `WORKFLOW.md`'s Progress
checklist for exactly which phase is current — keep it updated as work
lands, so the next agent doesn't have to reconstruct where things stand
from git history alone.

## 1. What this project is

A self-hosted MCP gateway for a ~7-person SOC team, replacing four separate
stdio MCP servers each analyst currently runs locally with their own copy
of production credentials. Full history: `DEVELOPMENT-LOG.md`.

- **Why not adopt an existing gateway:** six candidates were hands-on
  lab-tested (not just read about). All six failed on the one thing this
  project exists to fix — see `DEVELOPMENT-LOG.md` §5 (5 candidates,
  29 Aug) and §10.1a (`mcp-gateway-registry`, 31 Aug — the closest miss;
  real OAuth2 auth, but its credential-injection mechanism is strictly
  OAuth-on-behalf-of-user and cannot broker static API keys, which is
  exactly what this team's four backends need).
- **The actual four backends to support**, today's shape (stdio, Docker,
  `--env-file` pointing at plaintext files):

  | Server | Tools | Secrets |
  |---|---|---|
  | `casemgmt` | 10 | `~/.config/mcp-docsearch/.env.docker` |
  | `logsearch` | 10 | same file |
  | `docsearch` | 17 | same file |
  | `threatintel` | 28–29 | `~/threatintel/.env.docker` — 10 threat-intel API keys |

  All four are already-working MCP servers. This project does not rewrite
  them — it puts one gateway in front of them.

## 2. Confirmed architecture (do not re-litigate without a new ADR)

- **Style: monolithic, domain-partitioned ("modular monolith"), one
  quantum, synchronous by default.** Decided by quantum analysis, not
  preference — `design/adr/0001-monolithic-modular-style.md`. One binary,
  one process, no network hop between the gateway's own components.
- **Data store: one embedded SQLite** for `Upstream Registry`, `Tool
  Quarantine` state, and `Audit Trail`. **Never** for secrets — see below.
- **Failure mode when the registry store is briefly unreadable: fail
  closed, with short retry.** No tools served during the outage; retry
  quickly rather than caching indefinitely. Decided, not open —
  `design/adr/0004-registry-unavailability-failure-mode.md`.

### The eight components to build

Full responsibilities and the Actor/Ação derivation: `design/02-components.md`.

| Component | Responsibility | Confirmed mechanism |
|---|---|---|
| `Gateway Endpoint` | Single MCP surface; aggregates the 4 (later, more) backends; dispatches each call | — |
| `Access Control` | Authenticates caller; resolves role → allowed tool subset; validates token audience; **strips the client's own credential before any upstream call** (Kong `hide_credentials` pattern) | Credential-stripping step confirmed required — `design/adr/0003-security-controls.md` (31 Aug update) |
| `Credential Vault` | Resolves a secret reference to a real value, in memory, at upstream-process spawn time; never persisted, never logged | **sops + age**, `Provider` interface modeled on ToolHive's `pkg/secrets/types.go` (read-only reference, not copied — see license note below) |
| `Upstream Registry` | Config of registered backend servers | SQLite |
| `Tool Quarantine` | Per-**tool** (not per-server) SHA-256 over `name+description+schema`; new/changed tool → `pending`/`changed`, invisible and uncallable until Operator approves | Modeled on mcpproxy-go's quarantine — `DEVELOPMENT-LOG.md` §9.2 |
| `Definition Signer` | Ed25519 sign/verify of registry entries; hash **excludes secret values** (covers command/url + args + env-var *names* only) so credential rotation never breaks a signature | Modeled on Wirken's `mcp sign`/`mcp verify` — `DEVELOPMENT-LOG.md` §9.2 |
| `Audit Trail` | One record per call: analyst identity, tool, target upstream, timestamp | SQLite; granularity validated against Envoy/Ory Oathkeeper defaults, no gap found — `DEVELOPMENT-LOG.md` §10.2 |
| `Operator Console` | The single operator's surface: register/deregister upstream, approve quarantine, rotate secret, read audit trail | Not a separate service — subcommand/admin surface of the same binary |

**Do not copy source code from MCPJungle** (MPL-2.0, file-level copyleft) —
the Tool Groups *idea* is free to reimplement, the code is not. ToolHive
(Apache-2.0), mcpproxy-go (MIT), and Wirken (MIT) have no such restriction,
but all three mechanisms above should still be *reimplemented from the
described behavior*, not vendored, since none of their codebases are
Python (see §3) and the point is to match the mechanism, not the code.

### Security controls not yet designed (do not assume solved)

From `design/adr/0003-security-controls.md`'s explicit "not covered" list:

- **Telemetry/observability (OWASP MCP08)** — `Audit Trail` covers "who
  called what," not operational metrics. No design yet.
- **Response-schema validation** — mitigation for prompt-injection via a
  tool's *result* re-entering model context. Cited in research, not
  designed.
- **Token-passthrough prevention beyond credential stripping** — if the
  gateway ever calls a third-party OAuth-protected API on a client's
  behalf, it must mint its own upstream token (spec-level MUST, see
  `DEVELOPMENT-LOG.md` §9.1) — only relevant once/if an HTTP-facing,
  OAuth-authenticated endpoint is built; today's four backends are stdio
  and use env-injected static credentials, not OAuth.

## 3. Resolved 08 Sep 2026 — Gate 0 satisfied, implementation authorized

**Language/runtime: Go.** `design/adr/0002-language-runtime.md` is
`Accepted` — bunnyiesart chose Go directly, overriding the ADR's original
Python proposal (matches the two closest reference implementations,
ToolHive and mcpproxy-go, 1:1; costs a second language in the SOC team's
stack, accepted knowingly). Every phase in `WORKFLOW.md` that assumes a
Python-idiomatic mechanism (e.g. "sops has a Python binding") should be
read as "find the Go-idiomatic equivalent," not followed literally.

bunnyiesart also gave explicit authorization to move from planning to
implementation on the same date — both Gate 0 conditions in `WORKFLOW.md`
are satisfied. **Phase 1 is authorized to start.** The rest of this
section is kept for history; do not re-litigate it without a new ADR.

## 4. The build workflow

`WORKFLOW.md` is the phased, dependency-ordered implementation plan —
what to build in what sequence, the gates to check before each phase, and
a Progress checklist to keep updated as work happens. Read it once Gate 0
below is actually satisfied, not before.

## 5. Before writing any code

1. Get explicit confirmation to move from planning to implementation —
   this has been asked for and declined once already in this project's
   history; don't assume a later "sounds good" on an unrelated question
   counts as that confirmation.
2. Resolve §3 (language).
3. Read `docs/context/05-testabilidade-e-contratos.md` before
   the first class is written — ports & adapters (domain never touches
   Docker/SQLite/HTTP directly), dependency injection by constructor,
   pre/post-conditions per public method. This project has been designed
   against that methodology throughout; implementation should be too.
4. Reuse `lab/` (mock MCP servers, `probe.py`'s stdio/HTTP client + leak
   check) as the test harness for the new build itself, not just for
   evaluating third-party candidates — it was built generically enough
   for that from the start.
5. Write fitness functions early, not after the fact —
   `docs/context/07-fitness-functions.md`. The concrete one
   already named: nothing outside `Credential Vault`'s public interface
   may read a secret value directly (`design/adr/0001` Compliance section).

## 6. Where everything else lives

- `DEVELOPMENT-LOG.md` — full investigation narrative and evidence for
  every decision referenced above.
- `design/01-discovery.md` — the four driving characteristics (Security,
  Auditability, Simplicity & deployability, Extensibility), trade-offs,
  named conflicts.
- `design/02-components.md`, `design/03-style.md` — full derivation of §2.
- `design/adr/0001-0004` — one file per significant decision, with
  Contexto/Decisão/Consequências in the format
  `docs/context/04-adrs.md` specifies. **Any new significant
  decision made during implementation gets its own `000N-*.md` file here,
  not a comment buried in code or a chat message.**
- `lab/` — the reusable test harness (mock servers + probe + leak check).
- `WORKFLOW.md` — the phased implementation order and progress tracker;
  see §4.
- `docs/context/` — the software-architecture methodology this
  entire project has followed. Not project-specific; applies to any build
  decision here, present or future.
