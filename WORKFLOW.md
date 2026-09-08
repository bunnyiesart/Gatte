# WORKFLOW.md — implementation workflow for the MCP gateway build

Companion to `AGENTS.md` (what to build) — this file is the **order** to
build it in and the **gates** to check before and during each phase. Read
`AGENTS.md` first if you haven't. This file is meant to be re-read at the
start of every session that touches implementation — update the Progress
checklist below as phases complete so the next agent (or the next you)
doesn't have to reconstruct where things stand.

## Progress

- [x] **Gate 0** — implementation authorized, language decided (blocks everything below)
- [ ] Phase 1 — Audit Trail + Upstream Registry (foundation)
- [ ] Phase 2 — Credential Vault
- [ ] Phase 3 — Definition Signer + Tool Quarantine
- [ ] Phase 4 — Access Control
- [ ] Phase 5 — Gateway Endpoint (first end-to-end integration point)
- [ ] Phase 6 — Operator Console
- [ ] Phase 7 — Hardening pass (net-new controls from `AGENTS.md` §2)

*(Gate 0 satisfied 08 Sep 2026: bunnyiesart explicitly authorized moving to
implementation and confirmed the language. Phase 1 starts from here.)*

## Gate 0 — before any phase below starts

Do not proceed past this gate on your own judgment. Both conditions must be
true, confirmed by the human, not inferred from conversation tone:

1. **Explicit authorization to move from planning to implementation.**
   This has been asked for once already in this project and declined
   ("don't develop anything, only plan") — a later unrelated "sounds good"
   does not count as this authorization. Ask again, plainly, if unsure.
   **Satisfied 08 Sep 2026** — bunnyiesart asked directly to create the repo
   and start building.
2. **`design/adr/0002-language-runtime.md` status is `Accepted`.** It is
   currently `Proposed` (Python, unconfirmed). If it's still `Proposed`
   when you reach this gate, stop and ask — do not default to the
   proposal.
   **Satisfied 08 Sep 2026** — bunnyiesart chose **Go**, not the Python
   proposal. ADR-0002 updated to `Accepted` accordingly; every phase below
   that mentions a Python-idiomatic mechanism (`sops` binding, etc.) should
   be re-read as "find the Go equivalent," not followed literally.

Both conditions true as of 08 Sep 2026. Phase 1 is authorized to start.

## Why this order (dependency rationale)

Not arbitrary — later phases depend on earlier ones existing, per the
component graph in `design/02-components.md`:

- **Audit Trail first, before anything that could call it.** Every other
  component writes to it eventually; building it last would mean
  retrofitting logging calls into finished code instead of designing them
  in. Trivial in isolation (one table, one `record(...)` call) — that's why
  it's paired with Registry rather than given its own phase.
- **Upstream Registry before Definition Signer or Tool Quarantine** —
  both operate on registry entries; there's nothing to sign or quarantine
  before the registry can hold an entry.
- **Credential Vault has no dependencies on the above** but must exist
  before Gateway Endpoint, since Gateway Endpoint's whole reason to exist
  (spawning/calling an upstream with an injected credential) needs it.
  Built in parallel with Phase 1 in spirit, sequenced after only because
  one phase at a time keeps fitness functions and tests meaningful per
  step.
- **Access Control needs a decided identity model before it can be more
  than a stub** — this is a genuinely open question `AGENTS.md` did not
  previously surface: the original decision document's §10 Q4 ("named
  static tokens suffice for 7 people unless an IdP already exists") was
  never resolved. **Flag this to the human at the start of Phase 4, don't
  assume static tokens.**
- **Gateway Endpoint last among the "core" components** because it's the
  integration point — it has a real dependency on Registry, Vault,
  Quarantine, *and* Access Control all existing, even minimally. This is
  also the first point where `lab/`'s harness becomes useful against the
  real build instead of a design doc.
- **Operator Console after Gateway Endpoint**, not before — it administers
  state that the other components already define; building it earlier
  means building admin UI for interfaces still in flux.
- **Hardening pass last, not skipped.** The net-new controls named in
  `AGENTS.md` §2 (telemetry, response-schema validation, token-passthrough
  prevention beyond credential stripping) were deliberately deferred during
  design, not solved implicitly — don't let "phase 7" mean "someday."

## Phase 1 — Audit Trail + Upstream Registry

- SQLite schema for both (`design/02-components.md`: registry holds
  server config; audit holds one row per call — analyst identity, tool,
  target upstream, timestamp).
- Port/adapter split from the start (`docs/context/
  05-testabilidade-e-contratos.md`) — domain logic (what a valid registry
  entry looks like, what an audit record requires) behind an interface;
  SQLite access is the adapter, gets integration tests, not unit tests.
- Fitness function: a dependency-direction check that nothing outside
  these two components touches their tables directly once other
  components exist to consume them through an interface — write the
  *test* now, even though nothing violates it yet; it's cheaper to write
  before there's code to retrofit against.

## Phase 2 — Credential Vault

- `Provider` interface (modeled on ToolHive's `pkg/secrets/types.go` shape,
  reimplemented — see `AGENTS.md`'s license note, do not vendor code),
  backed by **sops + age** (`design/adr/0003-security-controls.md`).
- Resolve secret → value **in memory only**, at spawn time, for exactly one
  upstream process. Write the test that proves this *first*: grep every
  log line and every file the process touches during a resolve call for
  the plaintext value — this is the single most important test in the
  whole project, given every rejected candidate failed some version of it.
- Confirm against `lab/README.md`'s existing methodology
  (`<name>_credcheck` pattern) — reuse it rather than inventing a new
  verification method.

## Phase 3 — Definition Signer + Tool Quarantine

- Signer: Ed25519 over `command/url + args + sorted env-var names`,
  **excluding secret values** (Wirken pattern, `design/adr/0003`). Test:
  rotate a credential referenced by a signed entry, confirm the signature
  is still valid.
- Quarantine: per-**tool** SHA-256 over `name+description+schema`
  (mcpproxy-go pattern). Three states (`pending`/`approved`/`changed`),
  one field gating both index visibility and callability together — test
  that a `pending` or `changed` tool is unreachable through *every* path,
  not just the obvious one.
- These two are grouped because both operate on the same registry entries
  and both are pure verification logic with no I/O beyond reading the
  registry — good candidates to build and test together before Access
  Control introduces request-handling complexity.

## Phase 4 — Access Control

**Stop and confirm the identity model with the human before writing this
phase** — see "why this order" above. Once decided:

- Authentication (resolve caller identity).
- Role → allowed tool subset (fixes the N1-vs-DFIR gap named throughout
  `DEVELOPMENT-LOG.md`).
- Token audience validation.
- **Credential stripping** — remove the client-presented credential (if
  any) before the request reaches `Gateway Endpoint`. This is a named,
  required mechanism (`design/adr/0003`'s 31 Aug update, Kong
  `hide_credentials` pattern), not optional hardening.

## Phase 5 — Gateway Endpoint

- Single MCP surface, dispatch to the right upstream, aggregation of all
  registered servers.
- **Failure mode when Upstream Registry is briefly unreadable: fail
  closed with short retry** — decided, not a judgment call at
  implementation time (`design/adr/0004`, Accepted).
- **First point to run the `lab/` harness against the real build**: spin
  up the mock servers (`lab/servers/mock_mcp.py`), point the new gateway
  at them instead of at a candidate under evaluation, run `probe.py`'s
  clean-environment credential-injection + leak check exactly as done for
  every external candidate. If the custom build can't pass the same test
  the five external candidates failed, that's a stop-the-line finding, not
  a minor bug.

## Phase 6 — Operator Console

- Single admin surface (not a separate service — `design/03-style.md`):
  register/deregister upstream, approve quarantine, rotate secret, sign,
  read audit trail.

## Phase 7 — Hardening pass

Address what `AGENTS.md` §2 names as explicitly undesigned:

- Telemetry/observability (OWASP MCP08) — beyond what Audit Trail already
  gives.
- Response-schema validation on tool *results* before they re-enter model
  context (prompt-injection-via-result mitigation).
- Token-passthrough prevention beyond credential stripping — only if/when
  an HTTP-facing, OAuth-authenticated endpoint is added; not needed for
  the current all-stdio backend set.

## Continuous, not phased

Applies throughout every phase above, not as a separate step:

- **ADR discipline** — any new significant decision (per the criteria in
  `docs/context/04-adrs.md` §2) gets its own
  `design/adr/000N-*.md` file, numbered sequentially, same day it's made.
  Don't accumulate undocumented decisions "to write up later."
- **Fitness functions** — write the check when you write the rule it
  enforces, not after a violation is found. The concrete one already named
  (`design/adr/0001` Compliance): nothing outside `Credential Vault`'s
  public interface reads a secret value directly.
- **Testing pyramid** (`docs/context/06-testes-sistematicos.md`
  — not yet read in this project; read it before Phase 1's tests are
  written, not after).

## Definition of done for v1

All 7 phases checked above, plus: the `lab/` harness run against the
finished build end-to-end (Phase 5's checkpoint, repeated once Phases 6–7
are done, since Operator Console and hardening can change behavior the
earlier pass tested), and every ADR in `design/adr/` at `Accepted`, not
`Proposed`.
