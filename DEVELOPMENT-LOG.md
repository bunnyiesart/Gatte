# MCP Gateway — Development Log

Consolidated record of everything observed across three rounds of work, kept as
one file so the next phase (building our own) starts from a single source of
truth instead of three documents that each know only part of the story.

- Round 1 (26 Aug 2026): landscape research → `RESEARCH-recovered.md`
- Round 2 (29 Aug 2026, morning): formal decision document → `doc/mcp-gateway-decision.html`
- Round 3 (29 Aug 2026, evening): hands-on lab against 5 candidates → `doc/test-report.html`, `lab/`
- Round 4 (31 Aug 2026): decision — **build our own**. This file, plus resuming
  research with `docs/context/` (the software-architecture dev
  context) as the method for how to do it.

---

## 1. The original ask

> "we will start a research into mcp gateways for us to use inside my company,
> use the dev-context to see what will be useful and what won't... I need a
> lot of different gateways for consolidating api keys and mcp servers that
> one call will call others, i don't understand a lot of this concept."

`dev-context` did not exist in this project directory at the time (Round 1)
and was researched without it. It has since been located at
`docs/context/` — see §6.

## 2. What a "gateway" actually bundles — four unrelated jobs

The word does four unrelated jobs; conflating them is the source of most
market confusion:

1. **Fan-in (aggregation)** — N servers behind 1 endpoint. Config ergonomics
   only. Least valuable of the four, and the one most products lead with.
2. **Credential broker** — keys live in the gateway, not on every laptop.
   This was the actual ask.
3. **Composition** — one tool call fans out to many downstream calls
   ("enrich this IP" → VirusTotal + Shodan + AbuseIPDB + logs, merged).
   Only ToolHive vMCP and (partially) ContextForge do this natively.
4. **Governance** — per-user RBAC, audit log, rate limits, allowlists,
   traffic scanning.

**Fan-in does not reduce token cost.** 65 tools behind one endpoint still
ship 65 tool definitions into context. What does: tool filtering, tool
search, or code mode — different levers entirely.

## 3. Our actual stack (the part that changed the whole picture)

From `~/workspace/.mcp.json`, four stdio MCP servers, ~65 tools:

| Server | Tools | Secrets |
|---|---|---|
| `casemgmt` | 10 | `~/.config/mcp-docsearch/.env.docker` |
| `logsearch` | 10 | same env file |
| `docsearch` | 17 | same env file |
| `threatintel` | 28–29 | `~/threatintel/.env.docker` — 10 threat-intel keys |

**Already solved before any gateway was evaluated:**
- `threatintel` is already an API-key gateway (10 TI keys behind one MCP server).
- `threatintel` already does composition (`enrich`, `recon` fan out internally).
- REST→MCP translation is done by hand for all four servers.
- Container isolation is already the deployment model (one container/server).

**Genuinely open:** keys still sit in plaintext env files on every analyst's
laptop; stdio means local-only, one process per client; no per-analyst audit
of who ran what against which IOC; no per-role tool views (N1 triage vs.
DFIR lead see the same 65 tools).

**Ruled out categorically:** every managed/SaaS gateway (Composio, Arcade,
MintMCP, Cloudflare Portals, Nango, Bedrock AgentCore, …) — traffic is
customer CASEMGMT case data, Logsearch telemetry, IOCs. Routing that through a
third-party control plane is an LGPD/data-egress decision for a Brazilian
security provider, not a tooling choice. Eliminates roughly half the market
before evaluation starts.

## 4. Landscape surveyed (Round 1)

Self-hostable candidates verified against primary sources: IBM ContextForge,
ToolHive + vMCP, agentgateway, MetaMCP, MCPJungle, Docker MCP Gateway, Unla,
Lasso, Obot, Bifrost, MCP Mesh, mcp-proxy (tbxark), Supergateway, Kong/
Portkey/TrueFoundry, Microsoft MCP Gateway, Wirken, Open Edison. Full
comparison table in `RESEARCH-recovered.md` §Part 3.

**Standing conclusion from the survey itself:** no tool combines a
three-level hierarchy, federation, per-client tool visibility, and
lightweight self-hosting. A compromise on some axis was always expected —
what the lab testing (§5) found is that the compromises are worse than the
docs let on.

## 5. Hands-on lab results (Round 3, 29 Aug 2026) — the decisive round

Harness: `lab/` — dependency-free mock stdio MCP servers shaped like our real
four, credential-injection proven via `<name>_credcheck` (reports whether the
expected secret arrived + a fingerprint, never the secret itself), leak check
scans every client-side message. Full detail in `doc/test-report.html` and
`lab/README.md`.

### Defects found, ranked

> **A note on this section, added when this repository was made public.**
> What follows is an evaluation run in a lab in **late August 2026**,
> against each project's **documented quickstart configuration** at that
> date. Several of these are default-mode weaknesses that the projects may
> since have changed, and a quickstart is by nature not a hardened
> deployment — reading these as current, exploitable claims about those
> projects today would be wrong.
>
> Specific endpoints, payloads and reproduction steps have been removed:
> the point that mattered for *this* decision is that the credential
> brokering these tools advertise did not hold up under a clean-environment
> test, and that point survives without a how-to. If you maintain one of
> these projects and want the detail, it is better sent to you directly
> than published here.

| Severity | Product | Defect |
|---|---|---|
| **CRITICAL** | MCPJungle | In the documented quickstart mode, an unauthenticated API path exposed injected credentials, and the local database was written without encryption and with permissive file modes |
| **HIGH** | ToolHive | The quickstart ("quick") mode ships with no authentication at all — an unauthenticated request reached full tool and credential access |
| **HIGH** | tbxark/mcp-proxy | Does not aggregate — one route per server rather than a single endpoint. Fails the single-endpoint requirement outright |
| **MEDIUM** | mcpproxy-go | The auto-generated API key protected the web UI only; the MCP endpoint itself answered without it |
| **MEDIUM** | ToolHive | Encrypted secrets provider (AES-256-GCM) needs an interactive keyring password at boot — fails outright on a non-TTY, undocumented for headless/service deployment |
| **LOW** | ToolHive | 4 servers become 12 containers (egress proxy + dnsmasq per server) — defensible, but triples footprint and isn't signalled in advance |

### What each candidate got right (worth stealing regardless of the verdict)

- **ToolHive** — `--secret NAME,target=TARGET` and `-v host:container[:ro]`
  confirmed working; accepts arbitrary local Docker images, no registry
  required (this resolves the volume-mount question for `threatintel`'s
  `config.json` that Round 2 left open); `--optimizer` collapses 66 tools to
  2 (`find_tool`, `call_tool`) — server-side progressive disclosure;
  `--enable-audit` middleware.
- **mcpproxy-go** — quarantines new upstreams by default, pending human
  approval, before exposing their tools. A genuine tool-poisoning defence
  nothing else tested has. Exposes 12 BM25-searched meta-tools instead of
  raw backend tools.
- **Wirken** — turned out to not be an MCP gateway at all (it's a WebChat /
  agent platform that *consumes* MCP as a client, disqualified from the
  shortlist entirely) — but `wirken mcp sign` / `wirken mcp verify`
  cryptographically sign each `mcp.json` server entry and report
  valid/invalid/unsigned. Exactly the tool-definition-pinning control the
  decision doc's §11 recommends, already shipping somewhere. Also publishes
  the strongest supply-chain artefacts seen (checksums + signature + SLSA
  provenance).
- **tbxark/mcp-proxy** — best authentication of everything tested: 401
  without a token, 401 with a wrong one, 200 with the right one.
- **MCPJungle** — Tool Groups and the `${VAR}` secret-reference model are
  simple and easy to reason about, independent of the fact that the default
  mode leaks everything.

### What was never tested (still open if we ever revisit "adopt" instead of "build")

Open Edison (no release binary), any candidate's *authenticated* config
(everything above was quickstart/default mode), multi-user/concurrent
identity, performance/latency/restart behaviour, telemetry/phone-home
behaviour (unverified for all candidates, material for a security provider),
and all of the above against the real MCP servers rather than mocks.

## 6. Decision: build our own

**None of the five tested candidates meets the bar**, and not narrowly:

- The two that aggregate correctly (ToolHive, MCPJungle) each have a
  disqualifying default-mode security defect — one HIGH, one CRITICAL.
- The one with real authentication (tbxark/mcp-proxy) doesn't aggregate.
- Every candidate's documented quickstart is unauthenticated by default.
  Getting any of them to the bar means building the authenticated
  configuration ourselves anyway — at which point the appeal of "adopt,
  don't build" mostly evaporates, and the CRITICAL/HIGH findings above mean
  the remaining gap on the strongest candidate (ToolHive) is trust, not
  convenience.
- Container overhead (12 containers for 4 servers) and the interactive-
  password/headless-deploy gap add ongoing operational cost on top of that.

**Decided 31 Aug 2026:** design and build a purpose-built gateway instead of
adopting one of the five. Scope stays what §01 of the decision document
already fixed — single endpoint, credentials off analyst laptops, self-hosted,
zero-cost, no managed SaaS, no Kubernetes requirement (no platform team) — the
change is *who builds it*, not *what it needs to do*.

## 7. What carries forward into the build

From this investigation, direct inputs to the next phase (`01-descoberta` in
the dev context, §8):

- **Reuse, don't reinvent:** ToolHive's `--secret NAME,target=TARGET` /
  `-v host:container:ro` flag shape is a proven, simple contract for
  credential injection + volume mounting — worth using as a reference
  design even if the implementation is ours.
- **Steal the quarantine idea** (mcpproxy-go) — new upstream servers should
  not have their tools exposed until approved.
- **Steal the signing idea** (Wirken) — sign/verify each `mcp.json` entry,
  catching tool-definition tampering (OWASP MCP03, tool poisoning).
- **Authentication is not optional from day one.** Every tested candidate's
  weakest point was treating auth as a config file you add later. The
  custom build's Phase-1 `-ilities` discovery (§01 of the dev context) must
  put security/authentication in the top-3 driving characteristics, not as
  an afterthought bolted onto a working aggregator — that is exactly the
  mistake all five candidates made.
- **Container-count discipline** — whatever isolation model we choose,
  measure it against ToolHive's 4→12 container multiplication before
  accepting it as a default.
- **Threat model is already scoped:** LGPD/data-egress (§3) rules out any
  cloud-touching component; the four real backends and their credential
  shapes are already known (§3 table) and the lab's mock servers
  (`lab/servers/mock_mcp.py`) can be reused directly for testing the new
  build without touching production credentials.

## 8. The dev context (found)

`docs/context/` — software-architecture reference distilled from
four books (*Fundamentals of Software Architecture*, *Head First Software
Architecture*, *The Hard Parts*, *Effective Software Testing*). Not project-
specific; it's the method to use for *any* build decision in this repo.
Chain: `01` discovery (extract driving `-ilities` from what's in §3, §7
above) → `02` logical components (Workflow / Actor-Action) → `03`
architectural style (decided by quantum analysis, not preference) → `04`
ADRs (record every significant decision, both technical and business
justification) → `05` testability (ports & adapters — domain never touches
Docker/HTTP directly) → `06` systematic testing → `07` fitness functions
(automate the guardrails, e.g. "no server's tools become visible before
quarantine approval" as a CI check, not a review step).

Two rules from `01` apply immediately to this project: **cut the `-ilities`
list to ≤7** and **get the top 3 from the actual stakeholder** (i.e., ask
bunnyiesart, don't assume) before locking component design. That's the natural
next step once "more research" below is done.

## 9. Deeper research (31 Aug 2026) — protocol, source patterns, secrets

Three research passes done before touching component design, so the build
starts from verified mechanism, not from candidates' marketing copy.

### 9.1 Protocol & threat ground truth

- **Token passthrough is forbidden by spec (MUST NOT).** If our gateway ever
  calls a third-party API on a client's behalf, it mints its *own* upstream
  credential — it never forwards a client-presented token unmodified. This is
  exactly what credential injection already does for our four servers; it
  just needed the spec citation.
- **stdio backends (all four of ours today) should get credentials via
  environment injection, not OAuth** — the spec itself says implementations
  SHOULD NOT use the OAuth flow over stdio and should pull credentials from
  the environment instead. This directly validates the ToolHive-style
  `--secret NAME,target=TARGET` approach as the right shape, not just a
  convenient one.
- **If we ever expose an HTTP-facing endpoint** (needed the moment an
  analyst connects from anywhere other than the box running the gateway):
  MUST implement OAuth 2.0 Protected Resource Metadata (RFC 9728), MUST
  validate token audience via Resource Indicators (RFC 8707), MUST use
  `Authorization: Bearer` only (never a URL param), MUST use PKCE + exact
  redirect-URI match, SHOULD use short-lived tokens. Dynamic Client
  Registration is only a SHOULD.
- **Session IDs must not double as authentication** — every request must be
  independently verified; session IDs must be non-deterministic (UUID-grade)
  and SHOULD be bound to user identity. **Open item to verify before
  implementation:** a secondary source claims a 2026-07-28 spec revision
  removes the session model entirely — check `modelcontextprotocol.io/
  specification/2026-07-28` directly before designing session handling.
- **OWASP MCP Top 10 mapped against our two borrowed controls:** quarantine
  (mcpproxy-go pattern) covers MCP09 (unapproved deployments) and part of
  MCP03 (blocks a newly-added poisoned server pre-review). Signing (Wirken
  pattern) covers the rug-pull sub-case of MCP03 and tool-definition
  tampering. **Neither touches MCP01 (credential handling), MCP02
  (permission creep), MCP07 (weak access control), MCP08 (insufficient
  telemetry), or MCP10 (cross-tenant leakage)** — those need independent
  controls in the design, not an assumption that quarantine+signing already
  covers them.

### 9.2 Confirmed mechanisms in the four tested candidates' actual source

- **ToolHive** (Apache-2.0) — `--secret NAME,target=TARGET` parses to a
  `SecretParameter{Name, Target}`, resolved through a pluggable `Provider`
  interface (`pkg/secrets/types.go`) — environment / encrypted / 1Password /
  keyring are all just implementations of it — into an **in-memory map**
  passed straight to the container-runtime env-set call at spawn. It never
  touches disk or a log. `--optimizer` is a real SQLite-backed semantic tool
  store collapsing the tool list to 2 meta-tools (`find_tool`, `call_tool`).
  **Quick mode's lack of auth is a deliberate, explicitly-logged scope
  split**, not an oversight — `IncomingAuth.Type` is hard-set to `anonymous`
  with a loud "development only" warning, and `oidc` is a first-class,
  equally-weighted option one config field away. The defect we found isn't
  that auth is hard to reach — it's that the quickstart docs don't surface
  the warning loudly enough.
- **mcpproxy-go** (MIT) — quarantine is **per-tool, not per-server**, and
  hash-based: SHA-256 over `name + description + input schema` per tool. A
  trusted server auto-baselines its first-seen tools; a quarantined server
  leaves every tool `pending` until a human approves the *server*. After
  baseline, hash drift on a previously-approved tool flips it to `changed`
  (blocked from index *and* execution together — one status field gates
  both, so nothing is ever indexed-but-uncallable).
- **Wirken** (MIT, Rust) — Ed25519 signature over a **canonical hash that
  deliberately excludes secret values**: for stdio servers it hashes
  `command + args + sorted env-var names` (not values, which are
  `vault:NAME` references resolved separately) — so rotating a credential
  never invalidates the signature. An "anchored" build variant can hard-
  refuse unsigned entries via a compile-time-embedded root pubkey. It does
  **not** attest that `command` resolves to any particular binary on disk —
  only that the config entry is what the signer intended.
- **MCPJungle** (MPL-2.0 — file-level copyleft, so copy the idea, not the
  code) — Tool Groups are a simple named include/exclude list over tools and
  servers. `${VAR}` resolution is a generic reflection-based walker over
  `os.Getenv`. The credential exposure is **the dev-mode default itself**,
  not one overlooked route: in that mode the auth middleware no-ops
  entirely, so the API is unauthenticated in the configuration the
  documented quickstart puts you in. (Code-level detail elided — see the
  note in §5.)

### 9.3 Secrets management: sops + age

Compared against Vault OSS, OS keychains, plain env-file-via-supervisor, and
`pass`/gpg. **sops + age wins**: single ~15MB binary, decrypts headlessly at
process start with no TTY and no external KMS (directly avoids ToolHive's
interactive-password defect), encrypted file is git-safe and reviewable,
language-agnostic (Go and Python bindings both exist). Vault OSS's one real
advantage — dynamic/leased credentials — doesn't apply to our ~10 static
third-party API keys, and its auto-unseal story is *worse* than sops+age's
without an external KMS. OS keychains (macOS Keychain, Linux Secret Service)
have no programmatic unlock without an interactive login session — not
viable for a headless service at all. Plain env-file-via-systemd (today's
pattern, just centralized to one host) gains nothing cryptographically over
`.env.docker` — the gain is purely organizational (one controlled file
instead of N laptop copies).

### 9.4 What this confirms or changes from §7

- **Credential injection:** mirror ToolHive's `Provider` abstraction +
  spawn-time in-memory env injection — but back the `Provider` with sops+age
  instead of ToolHive's TTY-gated encrypted vault.
- **Quarantine:** mirror mcpproxy-go's granularity — per-tool hash and a
  three-state (`approved`/`changed`/`pending`) status gating index and
  execution together — not just a per-server approve/deny toggle.
- **Signing:** mirror Wirken's canonical-hash design exactly, including
  excluding secret values from the hash, so rotation doesn't break
  signatures.
- **Tool Groups:** the MCPJungle idea (named include/exclude list) is free
  to reimplement; the code itself is MPL-2.0 and not to be copied verbatim.
- **Net-new, not covered by anything borrowed:** token-passthrough
  prevention (mint our own upstream credentials), audit/telemetry (MCP08),
  and — pending the spec-version check above — session-ID handling. These
  need to be designed as first-class controls, not assumed to fall out of
  quarantine + signing.

## 10. Round 5 — second web/GitHub scan (31 Aug 2026)

Requested explicitly: look again for existing MCP gateways and general API
gateways on GitHub, in case the custom-build decision (§6) needs revisiting
or the in-progress design has a gap. Two parallel passes.

### 10.1 A candidate that might reopen "adopt vs. build"

**`agentic-community/mcp-gateway-registry`** (Apache-2.0, not in the
original 17-item survey) claims the exact combination that disqualified all
five tested candidates: **OAuth2/OIDC authentication on by default**
(Keycloak/Entra ID/Okta/Auth0/Cognito/PingFederate), aggregation of
multiple backend MCP servers behind one endpoint with per-tool access
control, and per-user credential brokering so tokens never sit on an
analyst's laptop. Active project (2,318 commits, 890 stars).

**Not yet trusted.** No third-party defect reports exist for it the way we
generated our own for the other five — "claims auth by default" is exactly
what MCPJungle's and ToolHive's *docs* also implied before hands-on testing
found the CRITICAL/HIGH defects in §5. Deployment docs are AWS-flavored
(EKS/ECS-first, though Docker Compose alone should work), which cuts
against "no platform team." **If this is worth reopening the adopt
question, it needs the same lab treatment as the other five** — mock
servers, clean-env probe, leak check — before being trusted on its word.
This is a real decision point, not a settled one; see the question posed to
bunnyiesart below.

**Open Edison — status corrected.** Flagged 29 Aug as "no release binary."
That's now wrong — it ships via `uvx open-edison`, `pipx`, and Docker. But
its `api_key` is configured, not mandatory by default — the identical
"auth is optional" failure mode as ToolHive's quick mode and MCPJungle's
dev mode. Not worth lab-testing ahead of `mcp-gateway-registry`.

**No fixes found** on any of the five already-tested candidates since 29
Aug 2026 — ToolHive is still at v0.46.0, MCPJungle's OAuth addition (v0.4.2)
is for authenticating *to* upstream servers, not a fix for its
unauthenticated dev-mode default. The CRITICAL/HIGH findings from §5 stand.

### 10.1a Lab-tested: `mcp-gateway-registry` (31 Aug 2026)

**Verdict: ingress auth is real and live-verified, but the platform does
not solve the credential-consolidation problem for a static-API-key backend
— this is the one reason the whole investigation started (§2, Job 2), and
it's not there.** Full run log in `lab/README.md` (Round 2, including the
"Round 2 completed" section with the finished credential-injection test).

Ran the actual documented Quick Start (`docker-compose.prebuilt.yml`) —
not the AWS path — locally: 9 containers for the platform itself (nginx/
registry, auth-server, mcpgw-server, Keycloak, Keycloak's Postgres, MongoDB,
OpenBao, Prometheus, Grafana), before registering a single backend server.
Two blockers hit and worked around, both host-environment issues rather
than product defects: the setup script wants `sudo` to create
`/var/log/containers/ai-registry` (worked around by bind-mounting logs to a
user-writable path instead); the "Quick Start" README path skips the
embeddings-model pre-download the full install guide calls for, so search
indexing logged a non-fatal error.

**The decisive test, live, not from docs:** unauthenticated `tools/list`
and `tools/call` against the one pre-registered MCP server, and
an unauthenticated API request — **both returned HTTP 401**, including
a wrong/garbage bearer token, with no dev-mode or quick-mode bypass found
anywhere in nginx's generated nginx config (unlike MCPJungle/ToolHive,
whose failures were exactly this). Then completed the real Keycloak M2M
OAuth2 client-credentials flow end-to-end (`init-keycloak.sh` →
`get-all-client-credentials.sh` → token request) and confirmed a **valid
token gets HTTP 200 with a real tool list** — the auth path is not just
present, it actually works.

**Completed in a follow-up pass, 31 Aug 2026:** built a purpose-built
streamable-HTTP mock server (this platform's backend model is
"already-running HTTP server, credential injected per-request as a header,"
not "spawn a process with env vars" like the five stdio gateways in round
1), registered it through the real REST flow (session-cookie auth + CSRF
token, `auth_scheme=api_key`/`auth_credential`/`auth_header_name`), and
called it live with a valid OAuth token from a clean environment.

**The credential was never injected.** The header dump on arrival showed
only gateway-internal identity/audit headers (`x-user`, `x-scopes`,
`x-tool-name`, …) — no trace of the configured credential or header. Traced
in source: `auth_credential`/`auth_header_name` are read only by the
registry's own discovery/health-check client (`registry/core/mcp_client.py`,
`registry/health/service.py`) and by an unrelated feature that fetches
"skill" content from GitHub/GitLab (`registry/services/skill_service.py`).
**Zero references to either field in `auth_server/server.py`'s `mcp_proxy`
function — the actual code path that handled the live request.** The only
mechanism that injects a credential into a live proxied call is
`egress_auth` (OpenBao-backed, off by default) — and it is strictly
OAuth-on-behalf-of-the-user (GitHub/Google/Atlassian/Microsoft/Slack/
custom-OIDC), which has no shape that fits a static third-party API key
like VirusTotal's, Shodan's, or our own `casemgmt`/`logsearch`/`docsearch`
service credentials — none of those are OAuth providers with an
authorize/token endpoint to broker against.

**This reverses the tentative read from the first pass.** "Architecturally
coherent, not yet proven live" undersold how narrow `egress_auth` actually
is. The mechanism that looked, from the docs, like ToolHive's
`--secret NAME,target=TARGET` turned out to serve a completely different
purpose (the registry's own out-of-band calls), not the live client path.

**One real defect found:** the platform's own bundled default tool server
was security-scanned at startup, flagged `HIGH` severity / `UNSAFE`, and
was **enabled anyway** — contradicting the README's claim that "unsafe
items are held for review." Possibly a deliberate first-party exception,
but undocumented as such; whether a genuinely *third-party* registration is
actually held for review was not tested (needs the registration flow this
pass didn't complete).

**Credential injection is the real disqualifier — operational weight is the
second one.** 9 fixed platform containers (Keycloak + its Postgres, MongoDB,
OpenBao, Prometheus, Grafana, plus the three app containers) is a materially
larger footprint
than any of the five already-rejected candidates, and every one of those
9 is a stateful service with its own upgrade/backup/patch lifecycle — for
a 7-person SOC team with no platform role. No release-asset checksums/
signatures found on GitHub releases (ships as container images instead;
signature verification not checked this pass) — a step down from ToolHive
(sigstore+SBOM) and Wirken (checksums+sig+SLSA) on supply-chain evidence.

**Where this leaves the adopt-vs-build decision:** the one thing that
disqualified all five other candidates — auth-by-default — is genuinely
solved here, live-verified. But "no platform team, self-hosted, zero
ceremony" was also a hard constraint from the start, and this platform's
baseline footprint is harder to justify for four backend servers and ~7
users than a purpose-built gateway sized to that exact scope. Leaning
toward continuing the custom build, informed by this platform's *design*
(the OAuth-enforced-at-every-hop pattern, the OpenBao-backed egress
brokering, the fail-closed-by-default posture in the auth-server source)
rather than adopting the platform itself — but this is a call for bunnyiesart,
not a conclusion to assert unilaterally.

### 10.2 Gaps surfaced by comparing our design against established API gateways

Survey of Kong, Apache APISIX, Envoy/Envoy Gateway, Ory Oathkeeper against
the 8-component design in `design/02-components.md`:

- **Credential stripping is a named, missing mechanism, not just an
  aspiration.** Kong's `hide_credentials` flag explicitly strips the
  client-presented credential before proxying upstream — a distinct step
  from *injecting* the gateway's own credential. `design/adr/0003` already
  flagged "token passthrough prevention" as uncovered; this gives it a
  concrete mechanism to copy. **Action taken:** added to `0003` as a
  required step in `Access Control`, not left as an open question.
- **Fail-open vs. fail-closed on Upstream Registry unavailability is
  genuinely undefined.** An Envoy operator postmortem: a dependency outage
  caused an *empty* routing table to be pushed, and Envoy correctly-but-
  unhelpfully 503'd every route instead of serving last-known-good config.
  Our design never specified what `Gateway Endpoint` does if the SQLite-
  backed `Upstream Registry` is briefly unreadable — fail closed (safest,
  breaks every analyst at once) or serve a last-known-good in-memory copy
  (available, but risks serving stale or quarantine-bypassed state). **This
  is a real open decision**, tracked as `design/adr/0004` — see below.
- **Audit Trail design validated**, no gap — Envoy's and Ory Oathkeeper's
  default log granularity (caller identity, target, timestamp, routing
  decision) matches what we already designed.
- **Plugin/extension trust is not yet a concern** — APISIX's documented
  RCE exposure (trust-on-install, no sandboxing for Lua plugins) is a
  cautionary tale for *if* the gateway ever grows a loadable-extension
  mechanism. Today it doesn't (each upstream MCP server is an isolated
  Docker container), so no action needed now — flagged for whenever that
  changes.
- **Independent confirmation, not new information:** multiple API-gateway
  operators separately describe a single gateway instance as "the most
  critical failure point in the system" — this is the same SPOF risk
  `design/adr/0001` already named and accepted; outside sources just
  confirm it's a commonly underestimated cost, not a theoretical one.

---

## Sources

Everything in §2–§5 is reproducible: `lab/README.md` for exact commands,
`doc/test-report.html` §08 "Reproduction" for the harness, `RESEARCH-
recovered.md` for the Round 1 primary-source list. Nothing above was
invented for this summary — it restates what those three documents already
established.
