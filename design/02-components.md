# Phase 2 — Logical components

Follows `docs/context/02-componentes-logicos.md`. Written as an
informed first draft per the method's own rule, and **kept as the record of
the derivation, not as a description of the built system.** Phases 1-6 have
since shipped; where this document and the code disagree, the code and the
ADRs win. The one correction folded back in so far is the Operator
Console's `rotate` (below) — the eight components and their boundaries have
otherwise held.

## Approach chosen: Actor/Ação

Selected because there are multiple, meaningfully different user types (the
criteria table in `02` names this as the trigger for Actor/Ação over
Workflow). The **System** actor is included deliberately — the method flags
it as the actor most often forgotten.

| Actor | Actions | Component(s) |
|---|---|---|
| **N1 triage analyst** | Connect to the gateway; call a tool from their allowed subset | `Gateway Endpoint`, `Access Control` |
| **DFIR lead** | Same, against a wider tool subset | `Gateway Endpoint`, `Access Control` |
| **Operator** (the one person who runs this) | Register a new upstream server; approve a quarantined tool; sign a registry entry; review the audit trail. (Rotate a credential too — but *not* through this system; see the Operator Console note below) | `Operator Console`, `Upstream Registry`, `Tool Quarantine`, `Definition Signer`, `Audit Trail` |
| **System** | Inject the real credential at process spawn; hash and compare tool definitions on every discovery; verify signatures at boot; write one audit record per call; validate token audience before dispatch | `Credential Vault`, `Tool Quarantine`, `Definition Signer`, `Audit Trail`, `Access Control` |

## Components

- **Gateway Endpoint** — the single MCP surface clients connect to.
  Aggregates the four (eventually more) upstream servers under one address,
  dispatches each call to the right backend. This is Job 1 (fan-in) from
  `DEVELOPMENT-LOG.md` §2 — the least novel part, but the one every client
  config depends on.
- **Access Control** — authenticates the caller, resolves their role to an
  allowed tool subset (N1 vs DFIR — fixes the "everyone sees all 65 tools"
  gap from §3), validates token audience, and is where token-passthrough
  prevention lives (§9.4: the gateway never forwards a client token
  upstream unmodified).
- **Credential Vault** — the `Provider` abstraction confirmed in ToolHive's
  source (§9.2), backed by sops+age instead of a TTY-gated encrypted vault.
  Resolves a secret reference to a real value in memory, at spawn time,
  for exactly one upstream process — never persisted, never logged.
- **Upstream Registry** — the list of configured backend servers (today:
  `casemgmt`, `logsearch`, `docsearch`, `threatintel`; tomorrow: whatever wraps the
  report scripts). Legitimate reference-data component — analogous to the
  dev-context's explicitly-allowed "Reference Data Manager" exception, not
  an entity-trap violation, because it holds configuration, not business
  workflow logic.
- **Tool Quarantine** — per-tool SHA-256 over name+description+schema
  (mcpproxy-go pattern, §9.2). New tool → `pending`, invisible and
  uncallable until Operator approval. Approved tool whose hash later drifts
  → `changed`, same block. This is what makes Extensibility safe rather
  than free (§01, "known conflicts").
- **Definition Signer** — Ed25519 sign/verify of registry entries (Wirken
  pattern, §9.2), hash excludes secret values so credential rotation never
  invalidates a signature. Runs at boot; anchored mode can refuse unsigned
  entries.
- **Audit Trail** — one record per tool call: analyst identity, tool,
  target upstream, timestamp. The component that directly closes the gap
  named in §3 ("no record of which analyst ran which lookup").
- **Operator Console** — the one interface the single operator uses for
  everything not automatic: register/deregister an upstream, approve a
  quarantined tool, sign a registry entry, read the audit trail.
  Deliberately not split further — one operator, one small surface, per
  "simplicity & deployability."

  **Correction, 09 Sep 2026 — no `rotate`.** This draft listed "rotate a
  secret" here, and Phase 6 deliberately did not build it. Rotation stays
  `sops secrets.json`: giving the gateway binary a write path into the
  encrypted store, when everything else it does with that store is *read*,
  buys convenience with the one asymmetry that makes the vault worth
  having. Same isolation reasoning that keeps the signing key out of the
  Credential Vault (`adr/0006`). The real operational hazard rotation does
  carry — credentials resolve at *dial* time, so an already-connected
  upstream keeps the old value until restart — is documented in
  `deploy/freebsd-jail.md` ("Rotating credentials") and tracked as ISSUE-20.

## Granularity check (desintegradores vs. integradores, §02 §7)

**Desintegrators that applied** (why these are separate components, not one
big `Gateway`):
- **Security isolation** — Credential Vault and Definition Signer hold
  cryptographic material; keeping them separate from Gateway Endpoint means
  a bug in request dispatch can't reach key material by accident.
- **Volatility** — Tool Quarantine's approval-state logic will change far
  more often (new heuristics, new statuses) than Gateway Endpoint's
  dispatch logic. Separating them keeps that churn from destabilizing the
  request path.

**Integrators that applied** (why these stayed together instead of
splitting further):
- **Shared code** — Access Control's authentication and its per-role tool
  filtering are two actions on the same actor-facing concept
  (`Access Control`), not two separate components — no meaningful driver to
  split them yet.
- **Workflow coupling** — Credential Vault and Upstream Registry are both
  read together on every spawn (secret ref lives in the registry entry).
  Kept as two components (different volatility: registry entries change
  rarely, credentials rotate often) but explicitly *not* four.

## What this is not

No entity-trap components (`ServerManager`, `ToolHandler`, `CredentialService`
were all considered and rejected as names — none of them say what the thing
*does*). No component mirrors a database table 1:1; `Upstream Registry` and
`Tool Quarantine` both hold state, but the state exists to serve a specific
behavior (dispatch routing; approval gating), not because a table happened
to exist.
