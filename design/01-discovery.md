# Phase 1 — Discovery: characteristics driving the custom gateway design

Follows `docs/context/01-descoberta-e-pensamento-arquitetural.md`.
Output of this phase feeds `02-components.md` and `03-style.md` directly —
it is not read-only background, it constrains what gets built next.

## Explicit characteristics (stated directly, in the original ask or the decision doc's scope)

- Single endpoint — all four MCP servers reachable through one address.
- Credentials off individual analyst laptops, into one controlled location.
- Self-hosted, zero cost — no managed/SaaS product.
- No Kubernetes — there is no platform team.

## Implicit characteristics (not written anywhere, forced by what the investigation found)

- **Auth cannot be an add-on config file.** Every one of the five tested
  candidates treated authentication as something bolted onto a working
  aggregator later — quick mode first, auth mode as an afterthought — and
  every one of them was disqualifying or defect-ridden as a result (see
  `DEVELOPMENT-LOG.md` §5). This is domain knowledge nobody wrote down; it
  came from watching five products fail the same way.
- **A SOC needs an audit trail even though nobody asked for one explicitly.**
  §3 already names "no record of which analyst ran which lookup against
  which IOC" as a gap. This is the textbook implicit characteristic from the
  dev-context material: disponibilidade/segurança that domain knowledge
  demands even when the request doesn't spell it out.
- **Whoever operates this owns it forever.** No platform team, ~7-person SOC
  → whatever gets built gets patched, restarted, and debugged by the same
  small group indefinitely. This is why "simplicity & deployability" was
  picked over, say, raw performance or elasticity — nobody here is fighting
  scale, they're fighting operational burden.

## Driving characteristics, prioritized by bunnyiesart (31 Aug 2026)

All four, no forced cut to 3 — the set is already ≤7 and each earns its
place independently:

1. **Security** — credential handling, authentication, tool-definition
   integrity. The entire reason the "adopt" path was rejected.
2. **Auditability** — per-analyst, per-call record. Currently zero.
3. **Simplicity & deployability** — headless, single-host, no ceremony to
   redeploy. Direct reaction to ToolHive's interactive-TTY defect.
4. **Extensibility** — adding new tools (the three loose report scripts,
   future MCP servers) without rearchitecting.

## Trade-off analysis (two columns, per §3 of the dev context)

| Characteristic | Pros of prioritizing it | Cons / cost |
|---|---|---|
| **Security** | Closes the exact gap that disqualified every tested candidate; matches the MUST-level protocol requirements found in research (token-passthrough prevention, audience validation) | More moving parts than a bare aggregator: an auth layer, a secrets provider, a quarantine/signing step — all before the first tool call works |
| **Auditability** | Gives the SOC something it has never had — per-analyst accountability; a prerequisite if any customer contract ever requires attribution (decision doc §10 Q1) | Storage and retention policy needed; every call now writes a log record, which is one more thing that can fail or fill a disk |
| **Simplicity & deployability** | Matches the team's actual operating capacity (no platform team); directly avoids the ToolHive/Vault-OSS headless-boot failure mode research just confirmed | Pulls against Security and Auditability, which both want more infrastructure, not less — the tension has to be resolved by picking lightweight mechanisms (sops+age, not Vault; SQLite/flat files, not a database cluster) rather than dropping the requirement |
| **Extensibility** | The three report scripts and any future MCP server should be addable without a rewrite | Every new upstream is also new attack surface — this is *why* quarantine exists, so extensibility is not free, it's extensibility-gated-by-security |

## Known conflicts, named explicitly

- **Security ↔ Simplicity.** Resolved in favor of *both*, at the cost of
  technology choice: sops+age over Vault OSS, an in-process quarantine
  state machine over a separate approval service. The dev-context's own
  guidance (favor the *least bad* trade-off, not the best-sounding one)
  applies directly — see §9.3 of `DEVELOPMENT-LOG.md`.
- **Extensibility ↔ Security.** A new upstream server is not usable until
  quarantine-approved (mcpproxy-go pattern, §9.2). This makes extensibility
  *slower by design* — a deliberate trade, not an oversight.
- **Auditability ↔ Simplicity.** Kept lightweight: audit is a structured
  log, not a SIEM integration, for v1. Revisit if a customer contract
  requires more (decision doc §10 Q1 is still open and is a business
  question, not ours to answer).

## Cut exercise ("if you had to eliminate one, which?")

Not forced — bunnyiesart kept all four — but worth recording the answer for
future re-litigation: **Extensibility** would be first to go. It's the only
one of the four not directly tied to a defect found in testing or an
explicit gap named in §3; it's a nice-to-have riding on the other three's
infrastructure, not a standalone driver. If scope pressure hits later,
Extensibility work (e.g. a generic REST→MCP wrapper for the report scripts)
is what slips first, not Security/Auditability/Simplicity.
