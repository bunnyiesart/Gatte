# WORKFLOW.md — implementation workflow for the MCP gateway build

Companion to `AGENTS.md` (what to build) — this file is the **order** to
build it in and the **gates** to check before and during each phase. Read
`AGENTS.md` first if you haven't. This file is meant to be re-read at the
start of every session that touches implementation — update the Progress
checklist below as phases complete so the next agent (or the next you)
doesn't have to reconstruct where things stand.

## Progress

- [x] **Gate 0** — implementation authorized, language decided (blocks everything below)
- [x] Phase 1 — Audit Trail + Upstream Registry (foundation)
- [x] Phase 2 — Credential Vault
- [x] Phase 3 — Definition Signer + Tool Quarantine
- [x] Phase 4 — Access Control
- [x] Phase 5 — Gateway Endpoint (first end-to-end integration point)
- [x] Phase 6 — Operator Console
- [x] Phase 7 — Hardening pass (net-new controls from `AGENTS.md` §2)

*(Gate 0 satisfied 08 Sep 2026: bunnyiesart explicitly authorized moving to
implementation and confirmed the language. Phase 1 starts from here.)*

**Every phase is closed. What remains is filed work, not a phase** — and
it is listed here rather than left in the prose below, because an item
that only exists inside a closed section is an item nobody re-reads:

- **The audit trail is not tamper-evident.** `audit_records` is an
  ordinary SQLite table: no append-only constraint, no hash chaining, so
  the write access ADR-0010 defends against also edits history. Named in
  Phase 7 and deliberately deferred — a hash-chained trail is its own
  design decision, and it changes the schema of a database that is live
  on `bun`.
- ✅ **GAB-20 — closed as detection-only, 10 Sep 2026.** Divergence
  detection is built (`gateway.CredentialDrift`, reported once per refresh
  tick): a credential rotated in the vault while an upstream is connected
  is now visible instead of silent, which was the actual defect — the
  operator believed they had rotated while the old value stayed in use.

  **The reconnect half was deliberately not built**, and the reason is in
  the deployment rather than in taste. It cannot be a console subcommand:
  there is no channel from the console to the serving process (no admin
  socket, no signal handler beyond SIGINT/SIGTERM), and a live connection
  is memory in another process, not a row the console can read. Building
  it means opening a control channel into the one process that holds every
  backend credential.

  SIGHUP looked like the cheap version and is a trap here. `deploy/gateway-jail/mcp_gateway`
  runs the gateway under `daemon -r`, and its pidfile holds the
  *supervisor's* pid — the script records, as a measured failure, that
  signalling the child under `-r` makes daemon(8) restart it while
  `service stop` reports success. So `kill -HUP` on the service pidfile
  would hit daemon(8), which forwards SIGTERM and not SIGHUP, and hitting
  the child instead is the documented footgun.

  Restart is the remedy and is the path that already works: SIGTERM
  reaches the child, the graceful shutdown reaps the stdio upstreams, and
  `-r` brings it back even if startup races the IdP. There is no session
  state to lose (ADR-0008 forbids a session ever standing in for
  authentication), which is exactly why a restart is cheap here and would
  not be in a stateful service.

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

## Phase 1 — Audit Trail + Upstream Registry ✅ done 08 Sep 2026

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

**Built:** `internal/registry` (domain) + `internal/registry/sqlite`
(adapter); `internal/audit` (domain) + `internal/audit/sqlite` (adapter);
`internal/store` (shared SQLite connection, used by both); `internal/fitness`
(the dependency-direction fitness function, `TestOnlyAdaptersTouchTheDatabase`
+ `TestDomainPackagesDoNotImportTheirOwnAdapter`); `cmd/mcp-gateway` (proves
the wiring, nothing more yet). `make check` runs fmt/vet/test/build.

**One real gotcha hit and documented, not just fixed silently:**
`internal/fitness`'s test shells out to `go list -json` at runtime, which
`go test`'s result cache cannot see — a deliberately-introduced violation
in `internal/registry` reproducibly returned a stale cached PASS under a
bare `go test ./...`, confirmed by hand, even after blank-importing the
inspected packages as a partial mitigation. `go list -json` itself was
always instantly correct; only `go test`'s caching was wrong. **Always run
`make test` (`-count=1`) for this project, never a bare `go test ./...`
when `internal/fitness` matters** — see the comment in
`internal/fitness/fitness_test.go` for the full account.

**Next: Phase 2 — Credential Vault.**

## Phase 2 — Credential Vault ✅ done 08 Sep 2026

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

**Built:** `internal/vault` (domain: `Provider` interface, `Secret` type)
+ `internal/vault/sopsage` (adapter). The decisive test
(`internal/vault/sopsage/leak_test.go`,
`TestResolveThenSpawnDoesNotLeak`) resolves a real secret through a
real sops+age-encrypted fixture, spawns a real subprocess running
`lab/mockutil`'s `<name>_credcheck` tool over stdio (reused exactly as
instructed, not reinvented), injects the resolved value into that
subprocess's environment the same way a future Gateway Endpoint will,
and scans the full JSON-RPC transcript, the tool result, and the
subprocess's stderr for the raw secret — all three come back clean.
Fitness function added: `internal/fitness`'s
`TestOnlyCompositionRootImportsAdapters` generalizes ADR-0001's
Compliance-section requirement ("nenhum componente acessa Credential
Vault fora da interface pública dele") to every port/adapter pair in the
project, not just the vault.

**One real decision made and documented, not just implemented silently:**
`design/adr/0005-shell-out-to-sops-cli.md` — the Credential Vault shells
out to the standalone `sops` binary via `os/exec` rather than importing
`github.com/getsops/sops/v3` as a Go library. Verified by hand: `go
install`-ing that package's `cmd/sops` produces a 72MB binary (against
`filippo.io/age`'s ~6MB) because sops's core unconditionally pulls in
AWS/GCP/Azure/Vault KMS SDKs this project never uses — embedding it would
have quietly undone the "single small binary, no external KMS" reasoning
that won sops+age the comparison against Vault OSS in the first place
(`DEVELOPMENT-LOG.md` §9.3).

**One real gotcha, documented, not hidden:** `sops`, `age`, and
`age-keygen` are runtime prerequisites of `internal/vault/sopsage`'s
tests, not Go module dependencies (that's the whole point of the ADR
above) — so those tests **skip**, rather than fail, when the binaries
aren't on `PATH`. That includes the decisive leak test. Run `make
devtools` once per dev machine/CI image (installs all three via `go
install`, no system package manager needed) and make sure `make check`
in CI actually has them on `PATH` — otherwise the single most important
test in the project quietly stops running instead of failing loudly.

**Next: Phase 3 — Definition Signer + Tool Quarantine.**

## Phase 3 — Definition Signer + Tool Quarantine ✅ done 08 Sep 2026

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

**Built:** `internal/signer` (domain: `Canonical`, `Signature`, `Signer`,
`Verify`, key load/generate) + `internal/signer/sqlite` (adapter, its own
`entry_signatures` table); `internal/quarantine` (domain: `ToolIdentity`,
`Hash`, three-state `Tool` with a pure transition function, and `Usable()`
as the single caller-facing gate) + `internal/quarantine/sqlite` (adapter,
transaction-wrapped read-modify-write so a concurrent discovery cycle
can't overwrite a `changed` verdict).

**Two new ADRs, because three implementation-time decisions were
security-significant and would otherwise look like arbitrary choices to
whoever reads the code next:** `0006` (signing key in its own file, never
in SQLite or the Vault; signatures in their own table; canonical hash
includes `Name` and is length-prefixed and version-tagged) and `0007`
(`changed` is permanent until a human approves; schema hashed as raw bytes
with no JSON canonicalization; one predicate gates visibility and
execution together).

**Next: Phase 4 — Access Control, which is blocked on the identity model
decision (see the gate above).**

## Phase 4 — Access Control ✅ done 08 Sep 2026

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

**Identity model decided:** self-hosted OIDC (`design/adr/0008`). bunnyiesart's
constraint that everything be self-hostable removed Google/Entra from the
table, and he chose a self-hosted provider over named static tokens,
against the earlier recommendation and knowing the operational cost.

**Built:** `internal/access` (domain: `Identity`, `Role`, `Policy` with
`Authorize`/`AllowedTools`/`RolesFor`, the `TokenVerifier` port, and the
401-vs-403 sentinels) + `internal/access/oidc` (adapter, provider-agnostic,
go-oidc based).

**Which IdP to run is deliberately not a code decision.** The verifier
takes an issuer, an audience and a configurable groups-claim name; Keycloak,
Authelia and Zitadel are indistinguishable from the gateway's side.
ADR-0008 recommends Authelia (single binary + SQLite) without binding to it.

**A real bug was found in review and fixed, worth recording because the
class of it recurs:** `Policy` documented itself immutable -- and its
no-locking design depends on that -- but stored the caller's `Role` structs
directly. `Role.Tools` is a slice, so the policy shared a backing array
with its constructor's caller, *and* `RolesFor` handed that same array to
the request path, meaning `p.RolesFor(id)[0].Tools[0] = "..."` silently
rewrote what the gateway authorized. Both directions are now cloned, and
`TestPolicyIsActuallyImmutable` was confirmed to fail against the pre-fix
code before being trusted.

**Credential stripping is only structurally complete here.** `Identity`
carries no raw token and a reflection test fails the build if a field named
like a credential is ever added. The *enforcement point* -- ensuring a
caller's token never reaches a spawned upstream -- lives in Phase 5, where
upstream calls actually happen, and the `lab/` probe already exists to
prove it.

**Next: Phase 5 — Gateway Endpoint.**

## Phase 5 — Gateway Endpoint ✅ done 08 Sep 2026

- Single MCP surface, dispatch to the right upstream, aggregation of all
  registered servers.
- **Failure mode when Upstream Registry is briefly unreadable: fail
  closed with short retry** — decided, not a judgment call at
  implementation time (`design/adr/0004`, Accepted).
- **First point to run the `lab/` harness against the real build**: spin
  up the mock servers (`lab/servers/{casemgmt,logsearch,docsearch,threatintel}`),
  point the new gateway at them instead of at a candidate under
  evaluation, run `lab/probe`'s clean-environment credential-injection +
  leak check exactly as done for every external candidate — `make
  lab-probe` does both. If the custom build can't pass the same test the
  five external candidates failed, that's a stop-the-line finding, not a
  minor bug. (This bullet named `mock_mcp.py` and `probe.py` until 09 Sep
  2026; those were the Python/Docker harness from the candidate
  evaluation and were never committed — `lab/README.md` says so and gives
  the Go paths above.)

**Built:** `internal/gateway` (routing table, namespacing, the
authorize -> quarantine -> audit -> dispatch sequence), `internal/gateway/stdio`
(spawns an upstream with an injected credential; child environment built
explicitly, nothing inherited), `internal/gateway/httpapi` (streamable
HTTP, stateless, bearer-only, per-identity tool exposure, every internal
error reduced to a class and a constant string before it crosses the
wire).

**The checkpoint this phase exists for is green.** `internal/e2e` wires
the real store, registry, quarantine, audit, policy, stdio dialer and HTTP
surface together, spawns all four lab mocks as real subprocesses, and puts
a real MCP client in front over real HTTP. A client holding no backend
credential of its own reaches four backends that each received the
injected secret, and that secret appears nowhere in the client-facing
traffic or in the gateway's own logs. This is the same question five of
six external candidates failed.

The Credential Vault is the one component the checkpoint fakes (in-memory
Provider). Deliberate: the vault's own no-leak property is proven against
real sops encryption in `internal/vault/sopsage/leak_test.go`, and making
the headline checkpoint depend on the sops binary would mean it silently
skips wherever sops is absent.

**Session handling resolved.** The open question about the 2026-07-28 spec
revision was answered from the SDK rather than the secondary source:
`StreamableHTTPOptions.Stateless` aligns with the spec's sessionless
direction (SEP-2567) and neither reads nor sets `Mcp-Session-Id`. Used.
"Session IDs must never double as authentication" is therefore true by
construction, not by discipline.

**Two defects found and fixed:** an upstream advertising a malformed input
schema could *panic the gateway process* (`mcp.Server.AddTool` panics on a
schema that is nil or not a JSON object of type "object", and the schema
is upstream-controlled) -- now refused at discovery, before the tool is
even observed into quarantine; and `ListTools` handed out schema bytes
aliasing the routing table, the same defect class already caught in
`access.Policy`.

**One gap found and left visible on purpose — since closed.** An
out-of-role tool probe was refused but not audited, because `httpapi`'s
per-identity registration means the call never reaches `Dispatch`, the only
writer of denials. It was pinned in the checkpoint as current behaviour so
that fixing it would fail loudly. **GAB-16 closed it:** `httpapi` now
records the attempt itself, attributed to the caller and carrying a reason,
without changing what the caller is told. The checkpoint asserts the
denial row rather than its absence
(`TestCheckpoint_RoleLimitsWhatIsReachable`, `internal/e2e/checkpoint_test.go`).

**Also outstanding:** the registry couples a vault key to the destination
environment variable name (`env[name] = Resolve(name)`), so two upstreams
cannot receive different values under the same variable name.
`DEVELOPMENT-LOG.md` §7 said to reuse ToolHive's
`--secret NAME,target=TARGET` shape, which separates the two; that
separation was not carried into `registry.UpstreamServer`.

**Next: Phase 6 — Operator Console.**

## Phase 6 — Operator Console ✅ done 09 Sep 2026

- Single admin surface (not a separate service — `design/03-style.md`):
  register/deregister upstream, approve quarantine, rotate secret, sign,
  read audit trail.

**Built:** `cmd/mcp-gateway` is no longer a stub. `serve` is the composition
root -- config, store, four migrations, sops+age vault, OIDC verifier,
policy, gateway (signer included), HTTP surface, graceful shutdown that
reaps upstream subprocesses. Alongside it: `upstream list|register|
deregister`, `tool list|approve`, `sign`, `audit`. Configuration is TOML
(`config.example.toml`, ADR-0009).

**GAB-17 and GAB-18 both closed by this phase.** The gateway can be run,
and the Definition Signer -- built in Phase 3 and invoked from nowhere
until now -- verifies every entry before anything is spawned. A tampered
entry is never dialed, which is the only ordering that means anything.

**ADR-0006's declared debt came due and was paid.** That ADR tolerated
unsigned entries *only* until the Operator Console could sign at volume.
The console shipped, so `require_signed` now defaults to **true**. The
field became a `*bool` in the process: a plain bool cannot distinguish
"unset" from "explicitly false", and reading unset as off is precisely how
a security default rots -- which is the failure this project disqualified
five of six candidates for.

**Verified by running the real binary**, not only by test: register an
upstream, see it reported NOT SIGNED with the consequence spelled out,
sign it, watch `serve` refuse to start against an unreachable IdP, and
confirm the injected credential appears in no log. A group-readable
signing key is refused with the exact chmod to run — by **`sign`**, which
is the only command that reads that key; `serve` never opens it, and
`config.Signer.KeyFile` is optional for exactly that reason.

**Operational property found by running it:** the gateway cannot start
without a reachable IdP. Correct (starting unable to authenticate anyone
is not service), but it means an IdP outage plus a gateway restart
recovers in order -- IdP first. Recorded in ADR-0008.

**One scoped item deliberately not built: `rotate`.** Rotation stays
`sops secrets.json`, so the binary keeps a read-only relationship with the
encrypted store -- same isolation reasoning that keeps the signing key out
of the Credential Vault (ADR-0006). But that exposed a real gap: credentials
resolve at *dial* time, so rotating one does nothing for an
already-connected upstream until restart, and nothing said so anywhere.
Now documented in `deploy/freebsd-jail.md` ("Rotating credentials") and in
the `internal/vault` package doc; a reconnect command and divergence
detection are GAB-20.

**Next: Phase 7 — the deferred hardening controls.**

## Phase 7 — Hardening pass

Address what `AGENTS.md` §2 names as explicitly undesigned:

- ✅ **Telemetry/observability (OWASP MCP08) — mostly delivered before this
  phase reached it, 09 Sep 2026.** Written as an open item, it turned out
  GAB-24 / `design/adr/0012-audit-completeness.md` had already closed the
  substance: a failed call now records `OutcomeFailed`, authentication
  failures are recorded at all (they produced *zero* records before), and
  every record carries a source address taken from the rightmost
  `X-Forwarded-For` entry — the one the proxy wrote, not the one a client
  can forge. All three are running in the deployment on `bun`.

  **What is genuinely left, and the original list never named it: the trail
  is not tamper-evident.** `audit_records` is an ordinary SQLite table with
  no append-only constraint and no hash chaining, so the same database
  write access that ADR-0010 exists to defend against also permits editing
  or deleting history. Filed rather than done here, because a hash-chained
  trail is a design decision of its own and not a hardening tweak.
- ✅ **Response validation on tool *results* — done 10 Sep 2026**, and the
  statement of this item changed on the way in. It used to read
  "prompt-injection-via-result mitigation", and that is not what schema
  validation is: a schema proves *shape*, and a result can satisfy its
  schema perfectly while carrying an instruction addressed to the model in
  a string field the schema declares as a string.
  `design/adr/0014-response-validation-scope.md` records the correction and
  what was built instead:
  - **A result size ceiling, always enforced** (`response.max_bytes`,
    default 1 MiB). This is the half with an effect today. Exceeding it is
    a refusal recorded with `OutcomeFailed`, never a truncation.
  - **`StructuredContent` validated against `Tool.OutputSchema`** when a
    backend declares one. None of the four does today — checked, not
    assumed, and pinned by a test — so this runs against no traffic yet and
    is not claimed as an active control.
  - **No injection detection.** No heuristics, no phrase lists, no test,
    because no promise. Injection via result stays open; the defence is the
    result reaching the model marked as untrusted data, which is the MCP
    client's property and not this gateway's.
- ✅ **Token-passthrough prevention — satisfied structurally, verified
  10 Sep 2026.** The HTTP-facing OAuth endpoint this item was waiting on
  now exists, so the condition was checked rather than left pending.

  Nothing forwards the analyst's token because **nothing downstream holds
  it**. `access.TokenVerifier` consumes the raw token at the edge and
  returns an `Identity`; `gateway.Caller` carries that `Identity` and a
  source address and no credential; `Dispatch` is never given one; and the
  child environment is built from nothing rather than appended to
  `os.Environ` (`internal/gateway/stdio`, and see `access_test.go`'s
  `TestIdentity_CarriesNoCredentialField`).

  That distinction is the point: this is not "the code remembers not to
  forward it", which decays. There is no variable to forward. The MCP
  spec's MUST is met by the shape of the types, and the fitness functions
  keep the shape.

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
