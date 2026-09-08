# Phase 3 — Architectural style

Follows `docs/context/03-estilos-arquiteturais.md`. Decided by
quantum analysis, not preference, per the method's own rule.

## Question 1: monolith or distributed?

*"Does a single set of architectural characteristics suffice, or do
different parts need different ones?"*

Checked against all eight components from `02-components.md`: Security and
Auditability apply uniformly to every single call, regardless of which
component handles it — there's no part of the request path where audit
logging or credential handling is optional. Simplicity & deployability
argues *for* fewer moving parts, not more. Nothing in the eight components
needs independent scaling, independent failure isolation, or a different
operational profile from the others strong enough to justify a separate
deployable unit.

The one candidate for a split — **Operator Console** is used rarely
(register a server, approve a quarantine, rotate a secret) versus
**Gateway Endpoint** which is on the hot path for every analyst call — was
considered and rejected: splitting it into a second service doubles the
deployables a single operator maintains, for a component whose actual load
characteristics (a handful of calls a week) don't demand isolation. It's a
subcommand/admin surface of the same binary, not a second quantum.

**Decision: one quantum. Monolithic.**

## Question 2: where do the data live?

One embedded relational store (SQLite) for **Upstream Registry**, **Tool
Quarantine** state, and **Audit Trail** — matches "monolito geralmente um
relacional único" and needs no separate database process, which would be a
second thing to keep running on a host with no platform team.
**Credential Vault** does not use this store — secrets are resolved from
the sops+age-encrypted file straight into process memory and never written
to the SQLite database, deliberately, so a copy of the database file alone
never leaks a credential.

## Question 3: sync or async?

**Synchronous**, by default and without exception in v1. Per §03 §5.3: "use
sync by default, async only where justified." Nothing in this system has
the throughput or elasticity profile that would justify the added failure
modes (message ordering, at-least-once delivery, harder debugging) async
would bring. A single SOC's tool-call volume does not approach the scale
where synchronous request/response becomes the bottleneck.

## Style chosen: Monolito Modular (monolithic, domain-partitioned)

Not "Camadas" (layered/technical partitioning) — the eight components in
`02-components.md` are already domain-centered (`Tool Quarantine`,
`Credential Vault`, `Audit Trail`, …), not technical layers
(controller/service/persistence). Domain partitioning was chosen because
each component's *reason to change* is different (quarantine heuristics
change independently of dispatch logic, which changes independently of
signing algorithm choice) — exactly the signal `03` §2 uses to prefer
domain over technical partitioning.

**Superpowers this buys us**, matched against the four driving
characteristics:
- **Simplicity & deployability** — one binary, one process, one SQLite
  file, no network hop between our own components. Directly the style's
  named strength.
- **Testability** — module boundaries line up with domain concern
  boundaries, so `Tool Quarantine`'s hash/approval logic can be tested in
  isolation from `Gateway Endpoint`'s dispatch logic (feeds `05-testability`
  when that phase starts — ports & adapters *within* the modular monolith,
  not between separate services).

**Kryptonite accepted explicitly** (per the style's own weaknesses list):
- **Elasticity and tolerance to failure remain weak** — a crash takes down
  the whole gateway, all four backends, for every analyst at once. This is
  the real cost of "one quantum," named directly in the decision doc's
  §12 Risks ("a central endpoint means all analyst tooling stops when it
  stops"). Accepted for v1: the alternative (a distributed system) trades a
  known, bounded cost (one process restart) for the eight falácias below,
  which are worse for a team with no platform experience.
- **Modularity is fragile without governance** — nothing stops someone
  from importing `Credential Vault` directly from `Gateway Endpoint`'s
  request-handling code six months from now. This is exactly what
  `07-fitness-functions.md` exists to prevent; a dependency-direction check
  (no component reaching into `Credential Vault` except through its
  defined interface) is a concrete fitness function to write once
  implementation starts.

## The eight falácias — where they still apply

Not to our own components (they share one process — a function call, not a
network call). They **do** apply at the one real network/process boundary
that exists regardless of style: between **Gateway Endpoint** and each of
the four upstream MCP servers, which run as separate Docker containers
today and will continue to. Relevant ones to design against explicitly:

- **#1 network is reliable** — a backend container can be unhealthy while
  the gateway is up. Needs a timeout + a clear error back to the client,
  not a hang.
- **#2 latency is zero** — not measured yet for our four containers.
  **Action before implementation:** measure p50/p95 spawn-to-first-response
  for `casemgmt`, `logsearch`, `docsearch`, `threatintel` locally — the falácia's own
  lesson is that the average lies and the tail is what breaks things.
- **#4 the network is secure** — each container boundary still needs the
  same credential-injection discipline whether it's "distributed" in the
  architectural sense or not; Docker's default bridge network is not a
  trust boundary by itself.

## Consequence for ADRs

Two significant decisions from this phase go to `design/adr/`:
`0001-monolithic-modular-style.md` (this decision, formalized) and
`0002-language-runtime.md` (still open — see that file's status).
